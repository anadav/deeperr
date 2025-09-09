# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Any, Dict, Tuple, List, Optional, Set, Iterable, Callable, Union, cast
from collections import defaultdict
import os
import sys
import bisect
import io
import logging

import angr
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
import capstone
from cle.backends.symbol import Symbol
from arch import arch
from kallsyms import Kallsyms
from kcore import Kcore
from ftrace import Ftrace
from prmsg import pr_msg, Pbar
from simprocedures import CopyProcedure, RetpolineProcedure, ReturnProcedure, ProcedureWrapper, RepHook

userspace_copy_funcs: Set[str] = {
    '_copy_to_user',
}

direct_sym_libc_hooks = {
    'memcpy', 'memcmp', 'strcpy', 'strstr', 'strlen', #'strcmp',
                            'strncmp', 'strchr', 'memset', 'strsep'
}


ignore_funcs_pure: Set[str] = set()

ignore_funcs_nopure: Set[str] = set()

no_kprobe_funcs: Set[str] = set()

# Returns the number of uncopied bytes unlike memcpy

class DisassemblyError(Exception):
    def __init__(self, msg: str) -> None:
        self.msg = msg

class Angr:
    type_map: Dict[str, Any] = dict()
    step_func_proc_trace = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']()  # type: ignore[attr-defined]

    def __init__(self,
                 kallsyms: 'Kallsyms',
                 kcore: Optional['Kcore'],
                 saved_segs: Optional[List[Dict[str, Any]]]) -> None:
        global arch

        self.proj: angr.Project
        self.indirect_thunk_addrs: Dict[int, str] = dict()
        self.indirect_thunk_start: Optional[int] = None
        self.indirect_thunk_end: Optional[int] = None
        self.removed_unsupported_insn_syms: Set[Symbol]
        self.analyzes: defaultdict[str, Dict]
        self.replaced_insns: Dict[int, capstone.CsInsn] = dict()
        self.md: capstone.Cs = arch.init_capstone()
        self.disasm_sym_cache: Dict[Symbol, List[capstone.CsInsn]] = dict()
        self.disasm_one_cache: Dict[int, List[capstone.CsInsn]] = dict()
        self.disasm_failure: Set[Symbol] = set()
        self.sym_hint: Optional[Symbol] = None
        self.code_hooks_done : Set[Symbol] = set()

        Angr.type_map = {x: 'TYPE_OTHER'  # type: ignore[misc]
                    for x in ['a', 'A', 'd', 'D', 'b', 'B', 'r', 'R', 'v', 'V']}
        Angr.type_map.update({x: 'TYPE_FUNCTION'  # type: ignore[misc]
                    for x in ['t', 'T', 'w', 'W']})

        self.analyzes = defaultdict(dict)
        self.removed_unsupported_insn_syms = set()

       
        self.read_ignored_funcs()

        self.load(kallsyms, kcore, saved_segs)

        self.skipped_hooked_procedure:Set[Symbol] = set()
        self.fastpath_to_ret_hooked_procedures:Set[Symbol] = set()
        self.fastpath_to_out_hooked_procedures:Set[Symbol] = set()

        self.init_general_hooks()
        self.init_retpoline()
        self.init_untrain_ret()
        self.init_copy_hooks()

        self.hooked_rep_string_addr:Set[int] = set()
        self.md.detail = True
        self.parse_interrupt_table()
        arch.init_symbols(self.proj)

        self.no_probe_sym_names = (ignore_funcs_pure|ignore_funcs_nopure|
                                    userspace_copy_funcs|direct_sym_libc_hooks|
                                    no_kprobe_funcs)

        # During simulation, we ignore pure functions, non-pure functions, and
        # functions that can't be kprobed (for safety/stability)
        self.ignore_sym_names = ignore_funcs_pure|ignore_funcs_nopure|no_kprobe_funcs

    def read_ignored_funcs(self) -> None:
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        
        # Read ignore_funcs_pure.txt
        try:
            file_path = os.path.join(script_dir, 'ignore_funcs_pure.txt')
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0:
                        continue
                    ignore_funcs_pure.add(line)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"error reading ignore_funcs_pure.txt: {e}")
        
        # Read ignore_funcs_nopure.txt
        try:
            file_path = os.path.join(script_dir, 'ignore_funcs_nopure.txt')
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0:
                        continue
                    ignore_funcs_nopure.add(line)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"error reading ignore_funcs_nopure.txt: {e}")
        
        # Read no_kprobe_funcs.txt
        try:
            file_path = os.path.join(script_dir, 'no_kprobe_funcs.txt')
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0:
                        continue
                    no_kprobe_funcs.add(line)
        except FileNotFoundError as e:
            raise FileNotFoundError(f"error reading no_kprobe_funcs.txt: {e}")
 
    def save(self) -> List[Dict[str, Any]]:
        code = list()
        for o in self.proj.loader.all_objects:
            if isinstance(o, angr.cle.Blob):
                for backer in o.memory.backers():
                    code.append({
                        'addr': backer[0] + o.mapped_base,
                        'name': o.binary_basename,
                        'offset': backer[0],
                        'code': bytes(backer[1])
                    })
        return code

    def load(self, kallsyms: Kallsyms, kcore: Optional[Kcore], saved_segs: Optional[List[Dict[str, Union[int, bytes]]]]) -> None:
        first = True
        f:io.IOBase
            
        if saved_segs is not None:
            memfd = os.memfd_create("vmlinux")
            memfd_offsets = dict()
            
            f = open(memfd, "w+b")
            offset = 0
            for seg in saved_segs:
                code = seg['code']
                assert isinstance(code, bytes)
                memfd_offsets[seg['addr']] = offset
                f.write(code)
                offset += len(code)
        else:
            assert kcore is not None
            f = open(kcore.path, "rb")

        for exe_name, exe in kallsyms.exes.items():
            segments:List[Tuple[int,int,int]] = list()

            assert isinstance(exe['segments'], List)

            if saved_segs is not None:
                segments = [(memfd_offsets[s[0]], s[0], s[1] - s[0]) for s in exe['segments']]
            else:
                assert kcore is not None
                assert kcore.path is not None
                assert isinstance(exe['mapped_addr'], int)
                assert isinstance(exe['size'], int)
                assert isinstance(exe['segments'], List)

                segments = [(kcore.get_offset(s[0]), s[0], s[1] - s[0]) for s in exe['segments']]

            # filter out segments with negative size (3rd)
            segments = [s for s in segments if s[2] > 0]

            # Skip if no valid segments remain
            if not segments:
                logging.warning(f"No valid segments found for {exe_name}, skipping")
                continue

            cle = angr.cle.Blob(exe['path'] or exe_name, f, segments=segments, arch=arch.arch_name,
                                base_addr = exe['base_addr'],
                                custom_base_addr = exe['mapped_addr'],
                                force_rebase = True)

            # XXX: Angr's Blob._load() calls self.memory.add_backer() while
            # calculating the relative address as (mem_addr - self.linked_base).
            # That assumes that the base is the same as the remapped base, which is
            # not true for the kernel. So we need to override it.
            backers = [b for b in cle.memory.backers()]
            for b in backers:
                cle.memory.remove_backer(b[0])

            for b in backers:
                cle.memory.add_backer(b[0] + exe['base_addr'] - exe['mapped_addr'], b[1])
                
            angr_syms = kallsyms.get_symbols(cle, exe_name)

            cle.symbols.update([s for s in angr_syms if s.size is not None and s.size > 0])

            # Hack; should have overriden get_symbol()
            cle._symbol_cache = {sym.name:sym for sym in angr_syms}

            if first:
                self.proj = angr.Project(cle, arch='amd64',
                        default_analysis_mode='symbolic',
                    load_options = {
                    'auto_load_libs': False,
                    'perform_relocations': False,
                    'use_system_libs': False,
                    })
                first = False
            else:
                self.proj.loader.dynamic_load(cle)

        f.close()

    def remove_unsupported_pyvex_insn_one_sym(self, sym: Symbol) -> bool:
        if sym in self.removed_unsupported_insn_syms:
            return False
        if sym.size is None:
            return False
        cle = self.proj.loader.find_object_containing(sym.rebased_addr)
        if not self.disasm_sym(sym):
            return False
        if self.disasm_sym_cache and self.disasm_sym_cache[sym]:
            for insn in self.disasm_sym_cache[sym]:
                # Some instructions are not handled correctly by pyvex. For
                # instance, mov-sreg and WRFSBASE.  Overwrite with nops and hook.
                hook, need_nops = arch.pyvex_workaround(insn)
                if hook is None:
                    continue

                if need_nops:
                    cle.memory.store(insn.address - cle.mapped_base,
                                    arch.nop_insn(insn.size))
                    self.replaced_insns[insn.address] = insn

                self.proj.hook(insn.address, hook, length=insn.size, replace=True)

        self.removed_unsupported_insn_syms.add(sym)
        return True
    
    def remove_unsupported_pyvex_insn(self, syms: Iterable[Symbol]) -> None:
        for s in syms:
            self.remove_unsupported_pyvex_insn_one_sym(s)

    def __is_hooked_sym_in_set(self, thing: Any, syms: Set[Symbol]) -> bool:
        ip = self.thing_to_address(thing)
        if ip is None or not self.proj.is_hooked(ip):
            return False
        sym = self.get_sym(ip)
        return sym in syms

    def is_skipped_sym(self, thing: Any) -> bool:
        return self.__is_hooked_sym_in_set(thing, self.skipped_hooked_procedure)
    
    def is_fastpath_to_out(self, thing: Any) -> bool:
        return self.__is_hooked_sym_in_set(thing, self.fastpath_to_out_hooked_procedures)

    def is_fastpath_to_ret(self, thing: Any) -> bool:
        return self.__is_hooked_sym_in_set(thing, self.fastpath_to_ret_hooked_procedures)

    def is_predicated_mov(self, s: SimState) -> bool:
        insn = self.state_insn(s)
        return insn is not None and arch.is_predicated_mov(insn)

    def is_noprobe_sym(self, sym: Symbol) -> bool:
        sym_base_name = sym.name.split('.')[0]
        if sym_base_name in self.no_probe_sym_names:
            return True
        if not self.disasm_sym(sym):
            return True
        return False

    def is_ignored_sym(self, sym: Symbol) -> bool:
        sym_base_name = sym.name.split('.')[0]
        if sym_base_name in self.ignore_sym_names:
            return True
        if not self.disasm_sym(sym):
            return True
        return False

    def for_each_insn_in_sym(self, sym: Symbol, fn: Callable[..., None], **kwargs) -> None:
        if sym.size is None or sym.size == 0:
            return
        if not self.disasm_sym(sym):
            self.disasm_sym(sym)
            raise DisassemblyError(f"Failed to disasm {sym.name}")
        insns = self.disasm_sym_cache[sym]

        # Skip on decode problem
        if insns is None:
            return

        for insn in insns:
            fn(sym, insn, **kwargs)

    def analyze_untracked_ftrace_callees(self, sym: Symbol) -> Set[Symbol]:
        def collect(sym: Symbol, insn:capstone.CsInsn, untrackable:Set[Symbol]):
            if not arch.is_direct_call_insn(insn):
                return
            tgt_addr = arch.get_direct_branch_target(insn)
            tgt_sym = self.get_sym(tgt_addr, hint = sym)
            if tgt_sym is not None:
                untrackable.add(tgt_sym)

        untrackable: Set[Symbol] = set()
        self.for_each_insn_in_sym(sym, collect, untrackable=untrackable)
        return untrackable

    # The instructions that need to be probed per symbol without those
    # of related symbols (e.g., cold)
    def analyze_jmp_traget_syms(self, sym: Symbol) -> Set[Symbol]:
        def collect(sym: Symbol, insn:capstone.CsInsn, br_tgts:Set[Symbol]):
            if arch.is_direct_jmp_insn(insn):
                tgt_addr = arch.get_direct_branch_target(insn)
                if tgt_addr is not None:
                    tgt_sym = self.get_sym(tgt_addr, hint = sym)
                    if tgt_sym and sym != tgt_sym:
                        br_tgts.add(tgt_sym)

        sym_key = str(sym.name) if sym else 'unknown'
        if 'branch targets' not in self.analyzes[sym_key]:
            br_tgts: Set[Symbol] = set()
            self.for_each_insn_in_sym(sym, collect, br_tgts=br_tgts)
            self.analyzes[sym_key]['branch targets'] = br_tgts

        return self.analyzes[sym_key]['branch targets']

    # Returns ([probe insns], [reachable symbols], [complete])
    def process_reachable_syms(self, syms: Iterable[Symbol]) -> Set[Symbol]:
        processed_syms:Set[Symbol] = set()
        to_process_syms = set(syms)

        # Find all symbols that are reachable from the given symbol by branches.
        # Cleanup the symbols by removing unsupported instructions and collect
        # the probe points.
        #
        # Note that we do not use angr CFGEmulated and other analysis methods since
        # they prove to be either too slow or too inaccurate.
        with Pbar("reachable syms", items=to_process_syms, unit="syms") as pbar:
            while len(to_process_syms) != 0:
                sym = to_process_syms.pop()
                self.remove_unsupported_pyvex_insn_one_sym(sym)
                jmp_target_syms = self.analyze_jmp_traget_syms(sym)
                to_process_syms |= jmp_target_syms - {sym} - processed_syms
                processed_syms.add(sym)
                pbar.update(1)

        return processed_syms

    @staticmethod
    def state_ip(s: SimState) -> Optional[int]:
        v = s.registers.load(arch.ip_reg_name)
        try:
            return s.solver.eval_one(v)
        except angr.SimValueError:
            return None
    
    def state_insn(self, s: SimState) -> Optional[capstone.CsInsn]:
        try:
            ip = s.solver.eval_one(s.regs.rip)
            return self.get_insn(ip)
        except (angr.SimValueError, ValueError):
            return None

    def init_general_hooks(self) -> None:
        # Hook all functions that should be ignored during simulation
        # This includes pure functions and functions that can't be kprobed
        for sym_name in (ignore_funcs_pure | no_kprobe_funcs):
            try:
                sym = self.get_sym(sym_name)
            except ValueError:
                continue

            self.hook_sym(sym, None, skip_to_ret = True, replace = False)

        self.code_hooks_done = set()

    def init_copy_hooks(self) -> None:
        dict_sym_libc_hook = [(f, f) for f in direct_sym_libc_hooks]

        dict_sym_libc_hook.extend(
            [('memcpy_erms', 'memcpy'),
             ('memset_erms', 'memset')]
        )

        for s, f in dict_sym_libc_hook:
            try:
                limits = None
                if f in {'memcpy', 'memcmp'}:
                    limits = [(None, None), (None, None), (0, 4096)]

                self.hook_sym(s,
                              ProcedureWrapper(angr.SIM_PROCEDURES['libc'][f], limits),  # type: ignore[attr-defined, arg-type]
                              skip_to_ret=True)
            except (ValueError, KeyError) as e:
                pass

        for s in userspace_copy_funcs:
            try:
                self.hook_sym(s,
                              CopyProcedure(),
                              skip_to_ret=True)
            except ValueError:
                continue

    def init_retpoline(self) -> None:
        for reg in arch.retpoline_thunk_regs:  # type: ignore[attr-defined]
            try:
                self.hook_sym('__x86_indirect_thunk_'+reg,
                              proc = RetpolineProcedure(reg),
                              skip_to_ret = False)
            except ValueError:
                pass

    def init_untrain_ret(self) -> None:
        for sym_name in ['zen_untrain_ret', '__x86_return_thunk']:
            try:
                self.hook_sym(sym_name,
                              proc = ReturnProcedure(),
                              skip_to_ret = False)
            except ValueError:
                pass

    def after_last_branch_addr(self, s: SimState) -> int:
        js = s.history.jump_source
        insns = s.history.parent.state.block().disassembly.insns  # type: ignore[attr-defined]
        src_insn = [insn for insn in insns if insn.address == js][0]
        return src_insn.address + src_insn.size

    def remapped_address_to_rebased(self, remapped_addr: int) -> Optional[int]:
        obj = None
        for loaded_obj in self.proj.loader.all_objects:
            if loaded_obj.contains_addr(remapped_addr):
                obj = loaded_obj
                break

        if obj is None:
            return None
        # TODO: return None instead of asserting

        #obj = self.proj.loader.addr_belongs_to_object(remapped_addr)
        original_address = obj.mapped_base - remapped_addr + obj.linked_base 
        return original_address

    def get_sym(self,
                thing: Union[str, int, capstone.CsInsn, Symbol],
                exact: bool = False, hint: Optional[Symbol] = None,
                no_zero_size: bool = True) -> Optional[Symbol]:
        sym = None
        if hint is None:
            hint = self.sym_hint
        if isinstance(thing, Symbol):
            self.sym_hint = thing
            return thing
        elif isinstance(thing, str):
            sym = self.proj.loader.find_symbol(thing)
            if sym is None:
                raise ValueError(f"Symbol not found: {thing}")
            self.sym_hint = sym
            return sym

        addr = self.thing_to_address(thing)

        # TODO: get rid of remapped_addr 
        remapped_addr = addr
        if remapped_addr is None:
            return None  # type: ignore[unreachable]
            
        def sym_matches(sym: Symbol, addr: int, exact:bool) -> bool:
            if no_zero_size and sym.size is None:
                return False
            return (sym.rebased_addr == addr or
                (not exact and sym.rebased_addr <= addr and sym.size is not None and
                 addr < sym.rebased_addr + sym.size))
            
        # Fast path if we are given a hint
        if hint is not None and sym_matches(hint, remapped_addr, exact):
            self.sym_hint = hint
            return hint

        sym = self.proj.loader.find_symbol(remapped_addr, fuzzy = not exact)
        if sym is not None and sym_matches(sym, remapped_addr, exact):
            self.sym_hint = sym
            return sym

        sym = self.proj.loader.find_symbol(remapped_addr + 1, fuzzy = True)
        if sym is not None and sym_matches(sym, remapped_addr, exact):
            self.sym_hint = sym
            return sym

        # Go backwards if we did not have size and we do not care about exact
        # address (going backwards does not make sense otherwise.)
        if not exact:
            addr = remapped_addr - 1
            while True:
                sym = self.proj.loader.find_symbol(addr, fuzzy = True)
                if sym is None:
                    break
                if sym.size is None:
                    addr = addr - 1
                    continue
                if sym_matches(sym, addr, exact):
                    assert(sym is not None)
                    self.sym_hint = sym
                    return sym
                break

        raise ValueError(f"Symbol not found for address {hex(remapped_addr)}")

    def base_addr(self, addr: int) -> Tuple[str, int]:
        cle = self.proj.loader.find_object_containing(addr)
        base_addr = addr - cle.mapped_base + cle.linked_base
        return cle.binary, base_addr

    def get_sym_addr(self, thing: Any, exact: bool = False) -> Optional[int]:
        sym = self.get_sym(thing, exact)
        return None if sym is None else int(sym.rebased_addr)

    def get_sym_name(self, thing: Any, exact: bool = False) -> str:
        sym = self.get_sym(thing, exact)
        return "[unknown]" if not sym else sym.name

    def next_insn(self, insn: capstone.CsInsn) -> Optional[capstone.CsInsn]:
        next_insn_addr = self.next_insn_addr(insn)
        return self.get_insn(next_insn_addr)

    def next_insn_addr(self, thing: Any) -> Optional[int]:
        insn = self.get_insn(thing)
        return insn and insn.address + insn.size
    
    def thing_to_address(self,
                         thing: Union[int, capstone.CsInsn, Symbol, SimState]) -> Optional[int]:
        if isinstance(thing, int):
            return thing
        if isinstance(thing, capstone.CsInsn):
            return thing.address
        if isinstance(thing, Symbol):
            return thing.rebased_addr
        if isinstance(thing, SimState):
            return thing.addr  # type: ignore[attr-defined]
        return None
    
    def thing_to_insn(self,
                      thing: Union[int, capstone.CsInsn, Symbol, SimState]) -> Optional[capstone.CsInsn]:
        assert not isinstance(thing, int)

        if isinstance(thing, capstone.CsInsn):
            return thing
        
        addr = self.thing_to_address(thing)
        return self.get_insn(addr)
         
    def get_prev_insn(self, thing: int, sym: Optional[Symbol] = None) -> Optional[capstone.CsInsn]:
        # Use capstone, since pyvex does not know too many instructions
        addr = self.thing_to_address(thing)
        if addr is None:
            return None
        return self.get_insn(addr-1, sym, exact=False)

    def prev_insn_addr(self, addr: int) -> Optional[int]:
        insn = self.get_prev_insn(addr)
        return insn and insn.address
    
    def disasm_one(self, addr: int) -> Optional[capstone.CsInsn]:
        assert(isinstance(self.proj.loader.memory, angr.cle.memory.Clemory))
        code = self.proj.loader.memory.load(addr, 16)
        if len(code) < 16:
            return None
        cs = self.md.disasm(code, addr)
        try:
            insn = next(cs)
        except StopIteration:
            return None
        self.disasm_one_cache[addr] = insn  # type: ignore[assignment]
        return insn

    def disasm_sym(self, sym: Symbol) -> Optional[List[capstone.CsInsn]]:
        if sym in self.disasm_sym_cache:
            return self.disasm_sym_cache[sym]
        if sym in self.disasm_failure:
            return None
        addr = sym.rebased_addr
        assert(isinstance(self.proj.loader.memory, angr.cle.memory.Clemory))

        # For retries
        while True:
            code = self.proj.loader.memory.load(addr, sym.size)
            cs = self.md.disasm(code, addr)
            decoded = [insn for insn in cs]

            n_decoded_bytes = (0 if len(decoded) == 0 else
                (decoded[-1].address + decoded[-1].size - decoded[0].address))

            if (n_decoded_bytes != len(code)):
                if (code[n_decoded_bytes:n_decoded_bytes+3] == b'\x0f\x01\xee' or
                    code[n_decoded_bytes:n_decoded_bytes+3] == b'\x0f\x01\xef'):
                    code = self.proj.loader.memory.store(addr + n_decoded_bytes, arch.nop_insn(3))
                    continue

                self.disasm_failure.add(sym)
                self.hook_sym(sym, None, False)
                return None

            self.disasm_sym_cache[sym] = decoded
            return decoded

    def get_insn(self, thing: Any, sym_hint: Optional[Symbol] = None, exact: bool = True) -> Optional[capstone.CsInsn]:
        """
        Get the instruction from the provided thing (address, capstone.CsInsn, or angr.block.CapstoneInsn).
        
        Args:
            thing: A capstone.CsInsn, angr.block.CapstoneInsn, or an address.
            sym_hint: An optional hint for the symbol.
            exact: Whether to return an exact match or the closest instruction if not found.
        
        Returns:
            The capstone.CsInsn instruction if found, None otherwise.
        """
        if isinstance(thing, capstone.CsInsn):
            return thing
        if hasattr(thing, 'address') and hasattr(thing, 'mnemonic'):  # Check for CapstoneInsn-like
            return thing  # type: ignore[return-value]

        ip = self.thing_to_address(thing)
        if ip is None:
            return None
        try:
            sym = self.get_sym(ip, exact=False, hint=sym_hint)
        except ValueError:
            sym = None

        disasm_sym_cache = self.disasm_sym(sym) if sym else None
        if disasm_sym_cache is None:
            if ip is None:
                return None
            insn = self.disasm_one(ip)
            if not insn:
                if ip is not None:
                    raise ValueError(f"Unknown instruction at {hex(ip)}")
                return None
            return insn

        # Find the index of the instruction with an address equal or greater than ip
        if (sys.version_info >= (3, 10)):
            idx = bisect.bisect_left(disasm_sym_cache, ip, key=lambda x:x.address)
        else:
            idx = next((i for i, insn in enumerate(disasm_sym_cache)
                        if insn.address >= ip), len(disasm_sym_cache))

        # Return the instruction if its address matches ip or the closest instruction if allowed
        if idx < len(disasm_sym_cache) and disasm_sym_cache[idx].address == ip:
            return disasm_sym_cache[idx]

        if exact or idx - 1 < 0:
            raise ValueError(f"Wrong boundary for instruction at {hex(ip)}")

        return disasm_sym_cache[idx - 1]

    def get_branch_target_insn(self, insn: capstone.CsInsn) -> Optional[capstone.CsInsn]:
        target_addr = arch.get_direct_branch_target(insn)
        if target_addr is None:
            raise ValueError(f"Instruction {insn.mnemonic} {insn.op_str} does not have a branch target")

        return self.get_insn(target_addr)

    # TODO: Move to arch
    def is_module_address(self, addr: int) -> bool:
        return addr >= 0xffffffffa0000000 and addr <= 0xfffffffffeffffff

    def is_ebpf_or_ftrace(self, addr: int) -> bool:
        # Need to read modules memory; for now, assume any address in the modules space
        # is of ebpf or ftrace
        return self.is_module_address(addr)

    def prepare_code_hooks(self, thing: Any) -> None:
        try:
            sym = self.get_sym(thing)
        except ValueError:
            return
        if sym is None:
            return

        # We have already set hooks for individual retpoline
        if sym.name == '__x86_indirect_thunk_array':
            return
        
        if sym not in self.code_hooks_done:
            def hook(sym: Symbol, insn:capstone.CsInsn, **kwargs):
                a = kwargs['angr']
                if arch.is_fixed_rep_insn(insn):
                    a.proj.hook(insn.address, RepHook(insn.mnemonic).run, length=insn.size)
                    a.hooked_rep_string_addr.add(insn.address)

            try:
                self.for_each_insn_in_sym(sym, hook, angr=self)
            except DisassemblyError:
                pr_msg(f"Failed to disassemble {sym.name}", level='DEBUG')
                pass
            self.code_hooks_done.add(sym)

        self.remove_unsupported_pyvex_insn_one_sym(sym)

    def hook_sym(self,
                 thing: Any,
                 proc: Optional[SimProcedure],
                 skip_to_ret: bool,
                 replace: bool = False) -> None:
        sym = self.get_sym(thing)

        if proc is None:
            proc = ProcedureWrapper(self.step_func_proc_trace.__class__)

        hook_addr = self.get_sym_addr(sym)
        if hook_addr is not None:
            if sym is not None:
                if proc == self.step_func_proc_trace:
                    self.skipped_hooked_procedure.add(sym)
                elif skip_to_ret:
                    self.fastpath_to_ret_hooked_procedures.add(sym)
                else:
                    self.fastpath_to_out_hooked_procedures.add(sym)
                self.proj.hook(hook_addr, proc, sym.size, replace=replace)

    def parse_interrupt_table(self) -> None:
        interrupt_table = arch.parse_interrupt_table(self.proj)

        self.addr_to_vectors = defaultdict(set)
        for vector, addr in interrupt_table.items():
            self.addr_to_vectors[addr].add(vector)

    def is_interrupt_handler_addr(self, thing: Any) -> bool:
        ip = self.thing_to_address(thing)

        return ip is not None and ip in self.addr_to_vectors
    
    def is_exception_addr(self, thing: Any) -> bool:
        ip = self.thing_to_address(thing)
        if ip is None or ip not in self.addr_to_vectors:
            return False

        vectors = self.addr_to_vectors[ip]
        return any([arch.is_exception_vector(vector) for vector in vectors])
    
    @staticmethod
    def state_concrete_addr(state: SimState) -> Optional[int]:
        try:
            return state.solver.eval_one(state.addr)
        except angr.errors.SimValueError:
            return None

    @staticmethod        
    def concrete_reg(s: SimState, reg: str) -> Optional[int]:
        try:
            return s.reg_concrete(reg)
        except angr.SimValueError:
            return None

    def state_ret_addr(self, s: SimState) -> Optional[int]:
        # TODO: use callstack_depth
        if len(s.callstack) - 1 == 0:
            return None
        ret_addr = s.callstack.ret_addr
        if ret_addr < 0:
            ret_addr += 1 << 64
        elif ret_addr == 0:
            call_insn = self.get_insn(s.callstack.call_site_addr)
            assert call_insn is not None
            ret_addr = self.next_insn_addr(call_insn)
        return ret_addr

    def return_reg_name(self) -> str:
        cc = self.proj.factory.cc()
        return cc.RETURN_VAL.reg_name  # type: ignore[attr-defined]
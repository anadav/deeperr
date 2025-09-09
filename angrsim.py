# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Any, Dict, Tuple, List, Optional, Set, Iterable, Callable, Union, cast
import logging
import time
import angr
from angr.sim_state import SimState
from angr.sim_manager import SimulationManager
import capstone
from dwarf import ELFDWARFAnalyzer
from cle.backends.symbol import Symbol
from arch import arch
from angrmgr import Angr
from prmsg import pr_msg, Pbar, warn_once
from controlstateplugin import ControlStatePlugin

class AngrSim:
    STEP_TIMEOUT: int = 10
    BACKTRACK_TIMEOUT: int = 60
    MAX_BACKTRACK_STEPS: int = 100

    def init_state(self, entry_addr: int) -> SimState:
        add_options = { angr.options.SYMBOLIC_WRITE_ADDRESSES,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
                        angr.options.SYMBOLIC_INITIAL_VALUES,
                        angr.options.CONSERVATIVE_WRITE_STRATEGY,
                        angr.options.CONSERVATIVE_READ_STRATEGY,
                        angr.options.STRINGS_ANALYSIS,
                        angr.options.AVOID_MULTIVALUED_WRITES,
                        angr.options.AVOID_MULTIVALUED_READS,
                        angr.options.DOWNSIZE_Z3,
                        angr.options.NO_SYMBOLIC_JUMP_RESOLUTION,
                        angr.options.REVERSE_MEMORY_NAME_MAP,
                        angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
                        } | angr.options.resilience | angr.options.simplification

        remove_options = {  angr.options.SYMBOLIC,
                            angr.options.ABSTRACT_SOLVER }

        s = self.angr_mgr.proj.factory.blank_state(addr=entry_addr,
                                            stack_end = arch.stack_end,
                                            stack_size = 0x5000,
                                            add_options = add_options,
                                            remove_options = remove_options)

        s.registers.store(arch.per_cpu_reg, arch.per_cpu_offset)
        s.registers.store(arch.stack_reg, arch.stack_end)
        return s

    def __init__(
            self,
            angr_mgr: Angr,
            branches: List[Dict[str, Union[int, None, List[int], Dict[str, int]]]],
            errcode: int,
            has_calls: bool,
            sim_syms: Optional[Set[Symbol]],
            detailed_trace: bool
        ):
        assert len(branches) > 0
        assert isinstance(branches[-1]['to_ip'], int)
        assert isinstance(branches[0]['from_ip'], int)

        self.simgr: Optional[SimulationManager] = None
        self.angr: angr.Project
        self.has_calls = has_calls
        self.sim_syms: Optional[Set[Symbol]] = sim_syms
        self.caller_ret_addr:int = branches[-1]['to_ip']
        self.errcode = errcode
        self.detailed_trace = detailed_trace
        self.angr_mgr = angr_mgr
        self.return_type_cache: Dict[Symbol, str] = dict()

        self.reset_state(entry_addr = branches[0]['from_ip'],
                         branches = branches,
                         detailed_trace = detailed_trace)

    def reset_state(self,
                    entry_addr: int,
                    branches: List[Dict[str, Any]],
                    detailed_trace: bool,
                    done_branches: int = 0) -> None:
        s = self.init_state(entry_addr = entry_addr)
        s.register_plugin('control', ControlStatePlugin(detailed_trace = detailed_trace,
                                                        branches = branches,
                                                        done_branches = done_branches,
                                                        angr_mgr = self.angr_mgr))
        s.register_plugin('history', angr.state_plugins.SimStateHistory())
        s.register_plugin('callstack', angr.state_plugins.CallStack())

        self.simgr = self.angr_mgr.proj.factory.simulation_manager(s,
                                    save_unsat = True,
                                    hierarchy = False,
                                    save_unconstrained = True)

    @property
    def active_states(self) -> List[SimState]:
        """Get the active states from the simulation manager."""
        if self.simgr is None:
            return []
        # Access the active stash which is a list of states
        return self.simgr.active  # type: ignore[attr-defined]

    @staticmethod
    def callstack_depth(s: SimState) -> int:
        return len(s.callstack) - 1

    def following_insn_addr(self, addr: int) -> int:
        insns = self.angr.factory.block(addr).disassembly.insns
        src_insn = next(insn for insn in insns if insn.address == addr)
        return src_insn.address + src_insn.size

    def copy_reset_state(self, s: SimState) -> SimState:
        # If simulation becomes too slow, ignore the entire memory and registers, and just
        # keep the callstack
        cs = s.callstack.copy()  # type: ignore[attr-defined]
        n = self.init_state(s.addr)  # type: ignore[arg-type]

        # Copy registers which are concrete
        for reg_name in arch.stack_related_reg_names + [arch.ip_reg_name]:
            try:
                v = s.reg_concrete(reg_name)
            except angr.SimValueError:
                pass
            else:
                n.registers.store(reg_name, v)

        # Copy concrete stack memory
        try:
            sp = s.reg_concrete(arch.stack_reg)
        except angr.SimValueError:
            pass
        else:
            for p in range(sp, arch.stack_end):
                try:
                    v = s.mem_concrete(p, 1)
                except angr.SimValueError:
                    pass
                else:
                    n.memory.store(p, v, 1)

        n.register_plugin('callstack', cs, inhibit_init=True)
        hist = s.history.copy()
        n.register_plugin('history', hist, inhibit_init=True)
        n.register_plugin('control', s.control, inhibit_init=True)  # type: ignore[attr-defined]

        return n

    def is_skipped_code(self, s: SimState) -> bool:
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]

        if self.callstack_depth(s) > s.control.max_depth:  # type: ignore[attr-defined]
            return True
        if s.history.jumpkind == 'Ijk_Ret' or self.callstack_depth(s) == 0:
            return False
        
        rip = Angr.state_ip(s)
        if rip is None:
            return True

        try:
            sym = self.angr_mgr.get_sym(rip)
        except ValueError:
            return True

        # TODO: Move this to arch
        if sym.name == '__x86_indirect_thunk_array':
            return False

        # XXX: hack
#        if sym.name in {'_copy_to_user'}:
#            return False

        if self.angr_mgr.is_skipped_sym(s):
            return True

        if s.control.only_symbols is not None and sym not in s.control.only_symbols:  # type: ignore[attr-defined]
            return True
        
        return False
    
    @staticmethod
    def is_failure(s: SimState, errcode: int, potential: bool = False) -> bool:
        '''Check if the state is a failure state.
            potential: If true, check if the state is a potential failure state,
                        not necessarily the only one.
        '''
        # For some reason is_true() sometime returns false, although this is the
        # only possible value, so we need to further check.
        s = s.copy()
        try:
            # TODO: Move the register read to arch code

            # There are some compiler optimizations that might not allow us to have
            # a single concrete return value, for instance due to the use of sbb
            # instruction in x86. Tracking the data flow is too complicated, and might
            # also introduce various problems. Instead just check multiple values to
            # account for most cases.
            if potential:
                vals = s.solver.eval_upto(s.regs.eax, 3)
            else:
                vals = [s.solver.eval_one(s.regs.eax)]
        except (angr.errors.SimValueError, angr.errors.SimUnsatError):
            return False

        return any([val == (1 << 32) - errcode for val in vals])

    def is_simulation_successful(self, states: List[SimState]) -> bool:
        return any(AngrSim.is_failure(s, self.errcode) for s in states)

    @staticmethod
    def is_unconstrained_call_target_no_follow(s: SimState) -> bool:
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]
        return s.history.jumpkind == 'Ijk_Call' and s.control.backtracking  # type: ignore[attr-defined]
    
    @staticmethod
    def is_unconstrained_ret(s: SimState) -> bool:
        return s.history.jumpkind == 'Ijk_Ret'

    @staticmethod
    def update_state_max_depth(s: SimState) -> None:
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]

        if s.control.no_callees:  # type: ignore[attr-defined]
            s.control.max_depth = min(s.control.max_depth, AngrSim.callstack_depth(s))  # type: ignore[attr-defined]

    def warn_potential_simulation_problem(self, s: SimState) -> None:
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]

        if not s.control.detailed_trace and not s.control.backtracking:  # type: ignore[attr-defined]
            ip = Angr.state_ip(s)
            if ip is None:
                return

            try:
                next_insn = self.angr_mgr.get_insn(ip)
            except (ValueError, TypeError):
                return

            if arch.is_rep_insn(next_insn) and not arch.is_fixed_rep_insn(next_insn):
                warn_once("REP-prefix with Intel PT cannot be simulated correctly")
            if arch.is_predicated_mov(next_insn):
                warn_once("CMOVxx/SETxx with Intel PT cannot be simulated correctly")

    @staticmethod
    def split_ret_state(s: SimState) -> SimState:
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]
        branch = s.control.current_branch  # type: ignore[attr-defined]
        assert isinstance(branch, Dict)

        ret_val = branch['ret']
        taken = s
        not_taken = s.copy()
        taken.add_constraints(taken.registers.load(arch.ret_reg_name) == ret_val)
        not_taken.add_constraints(not_taken.registers.load(arch.ret_reg_name) != ret_val)
        not_taken.control.diverged = True  # type: ignore[attr-defined]
        not_taken.control.expected_ip = None  # type: ignore[attr-defined]
        return not_taken

    def backtrack_step_func(self, simgr: SimulationManager) -> SimulationManager:
        simgr = simgr.step(selector_func = self.is_skipped_code,
                            target_stash = 'tmp',
                            procedure = Angr.step_func_proc_trace)
                            
        simgr = simgr.step(stash = 'unconstrained',
                            target_stash = 'tmp',
                            selector_func = self.is_unconstrained_call_target_no_follow,
                            procedure = Angr.step_func_proc_trace)
        
        if 'tmp' in simgr.stashes:
            simgr = simgr.move(from_stash = 'tmp', to_stash = 'active')
        
        simgr = simgr.apply(state_func=self.update_state_max_depth)
        return simgr

    def step_func(self, simgr: SimulationManager) -> SimulationManager:
        self.follow_trace(simgr)

        self.move_to_diverged()

        simgr = simgr.apply(state_func=self.update_state_max_depth, stash='active')
        simgr = simgr.apply(state_func=self.warn_potential_simulation_problem, stash='active')
        return simgr


    def prepare_hooks(self) -> None:
        for s in self.active_states:
            ip = Angr.state_ip(s)
            self.angr_mgr.prepare_code_hooks(ip)

    def prepare_simulation_step(self) -> None:
        for s in self.active_states:
            control = cast(ControlStatePlugin, s.control)  # type: ignore[attr-defined]
            control.diverged = False
            control.expected_ip = None

    def handle_rep_insn(self) -> None:
        pass

    def handle_exception(self) -> None:
        def is_exception(s: SimState) -> bool:
            control = cast(ControlStatePlugin, s.control)  # type: ignore[attr-defined]
            br = control.current_branch
            return br is not None and br.get('exception', False) and br['from_ip'] == Angr.state_ip(s)

        if not any(is_exception(s) for s in self.active_states):
            return
        
        def get_exception_successors(s: SimState) -> angr.engines.successors.SimSuccessors:
            exception_state = s.copy()
            no_exception_state = s.copy()
            
            assert isinstance(exception_state.control, ControlStatePlugin)
            c = exception_state.control
            c.next_branch()
            assert isinstance(c.current_branch, Dict)

            addr = Angr.state_ip(s)
            successors = angr.engines.successors.SimSuccessors(addr, s)
            
            no_exception_state.control.diverged = True
            successors.add_successor(state = no_exception_state,
                                    target = addr,
                                    guard = exception_state.solver.true,
                                    jumpkind = "Ijk_NoException")
            
            after_exception_ip = c.current_branch['to_ip']

            successors.add_successor(state = exception_state,
                                    target = after_exception_ip,
                                    guard = exception_state.solver.true,
                                    jumpkind = "Ijk_Exception")
            c.next_branch()
            return successors
        
        self.simgr.step(selector_func = is_exception,
#                        num_inst = 1,
                        successor_func = get_exception_successors)
                  #      procedure = self.exception_procedure)
        self.move_to_diverged()
   
    def move_to_diverged(self) -> None:
        self.simgr.drop(stash='active',
                        filter_func=lambda s:s.control.diverged and self.is_ignored_function_on_stack(s))
        self.simgr.move('active', 'diverged', lambda x:x.control.diverged)

    def handle_predicated_mov(self) -> None:
        cmov_states = [s for s in self.active_states
                        if s.control.detailed_trace and self.angr_mgr.is_predicated_mov(s)]  # type: ignore[attr-defined]

        for s in cmov_states:
            ip = Angr.state_ip(s)
            insn = self.angr_mgr.get_insn(ip)
            matched_entry = (s.control.current_branch['from_ip'] == ip and
                             s.control.current_branch['to_ip'] == self.angr_mgr.next_insn_addr(insn))
            taken_predicated_mov = not matched_entry
            if matched_entry:
                s.control.next_branch()
            successors = arch.predicated_mov_constraint(s, taken_predicated_mov, insn)
            self.simgr.active.remove(s)
            self.simgr.active.extend(successors)

    def handle_simulation_timeout(self, step_time: float) -> bool:
        # Occassionally we can get unreasonably long simulation time. If we
        # are simulating instructions that are much earlier than the
        # failure, we would just copy the concrete values and continue.
        
        simgr = self.simgr
        handle_timeout = False
        # TODO: Consider adding: len(self.branches) - trace.b_idx > self.MAX_BACKTRACK_STEPS and
        
        if not handle_timeout or step_time <= AngrSim.STEP_TIMEOUT:
            return False

        next_states = [s.copy() for s in simgr.active]
        reset_states = [self.copy_reset_state(s) for s in next_states]
        simgr.drop(stash = 'active')
        simgr.populate('active', reset_states)
        return True

    def constrain_calls(self) -> None:
        for s in self.active_states:
            insn = self.angr_mgr.get_insn(s)
            if insn is None:
                continue

            if not arch.is_call_insn(insn):
                continue

            # TODO: Move this to arch
            if len(insn.operands) != 1:
                continue

            op = insn.operands[0]

            # We do not support anything other than simple cases
            if op.type != capstone.x86.X86_OP_REG or op.size != 8:
                continue

            control = cast(ControlStatePlugin, s.control)  # type: ignore[attr-defined]
            if control.current_branch is None or control.current_branch['from_ip'] != Angr.state_ip(s):
                continue

            reg = s.registers.load(insn.op_str)
            to_ip = control.current_branch['to_ip']
            s.add_constraints(reg == to_ip)
            s.registers.store(insn.op_str, to_ip)

    def run_one_step(self, stats: Dict[str, Any]) -> bool:
        simgr = self.simgr
        start_step_time = time.time()

        for s in simgr.active:  # type: ignore[union-attr]
            control = cast(ControlStatePlugin, s.control)  # type: ignore[attr-defined]
            control.update(s)

        #self.constrain_calls()
        simgr.move('active', 'skipped', lambda x: self.is_skipped_code(x))
        
        simgr = simgr.step(num_inst = 1)

        simgr = simgr.step(stash = 'skipped',
                           target_stash = 'active',
                           procedure = Angr.step_func_proc_trace,
                           num_inst = 1)

        # TODO: just get rid of step_func 
        self.step_func(self.simgr)
        
        end_step_time = time.time()

         # Reenable later - disabled for debug
        timed_out = self.handle_simulation_timeout(end_step_time - start_step_time)

        if len(simgr.stashes.get('diverged', [])) > self.MAX_BACKTRACK_STEPS:
            stats['divergence points'] += len(simgr.stashes['diverged']) - self.MAX_BACKTRACK_STEPS 
            simgr.stashes['diverged'] = simgr.stashes['diverged'][-self.MAX_BACKTRACK_STEPS:]

        return timed_out

    def _update_control(self, state: SimState, new_states: List[SimState]) -> None:
        c = cast(ControlStatePlugin, state.control)  # type: ignore[attr-defined]
        jump_source = state.history.jump_source
        insn = jump_source and self.angr_mgr.get_insn(jump_source)

        jump_target = Angr.state_concrete_addr(state)
        from_ip, to_ip = c.current_branch['from_ip'], c.current_branch['to_ip']  # type: ignore[index]
        next_ip = insn and self.angr_mgr.next_insn_addr(insn)

        if state.history.jumpkind == 'Ijk_Call':
            if self.is_skipped_code(state):
                # Skip all branches within the skipped and hooked code. Assume no nesting.
                ret_addr = self.angr_mgr.state_ret_addr(state)
                if ret_addr:
                    while c.current_branch is not None and c.current_branch['to_ip'] != ret_addr:
                        c.next_branch()
            elif self.angr_mgr.is_fastpath_to_out(state):
                raise NotImplementedError()
            elif ((not from_ip or from_ip == jump_source) and
                  (not to_ip or to_ip == jump_target)):
                # This is a hack to ensure Intel PT behaves at least half as sane.
                # We cannot recover from such a case.
                if arch.is_direct_branch_insn(insn) and not from_ip and not to_ip:
                    c.diverged = True
                    c.expected_ip = None 
                else:
                    c.next_branch()
            elif arch.is_indirect_call_insn(insn) and jump_source is not None:
                # Need to be tolerant to Intel PT shenanigans
                c.diverged = True
                c.expected_ip = to_ip
        elif state.history.jumpkind == 'Ijk_Ret':
            if (to_ip == jump_target and
                (not from_ip or not jump_source or from_ip == jump_source)):
                if c.current_branch and 'ret' in c.current_branch and from_ip is None:
                    new_states.append(self.split_ret_state(state))
                c.next_branch()
            elif jump_source is not None:
                c.diverged = True

        elif state.history.jumpkind == 'Ijk_Boring' and insn is not None:
            if arch.is_fixed_rep_insn(insn) and c.detailed_trace:
                while to_ip == insn.address:
                    c.next_branch()
                    to_ip = c.current_branch['from_ip']
            elif arch.is_branch_insn(insn):
                if from_ip == jump_source and to_ip == jump_target:
                    c.next_branch()
                elif from_ip != jump_source and jump_target == next_ip:
                    pass
                elif arch.is_cond_branch_insn(insn) or arch.is_indirect_jmp_insn(insn):
                    c.diverged = True
                    if from_ip == jump_source:
                        # We got an entry that needs to be skipped
                        c.expected_ip = to_ip
                        c.next_branch()
                    elif arch.is_cond_branch_insn(insn):
                        # Not taken in practice while expected to be taken
                        c.expected_ip = next_ip
            elif jump_target != next_ip:
                # Not even a branch: no recovery possible
                c.diverged = True

    def follow_trace(self, simgr: SimulationManager) -> None:
        """
        Follow the execution trace in the given Simulation Manager, updating
        the states based on their control flow and removing diverged states.

        Args:
            simgr: The Simulation Manager to process.
        """
        new_states: List[SimState] = list()

        # Re-constrain the unconstrained states for indirect calls and returns
        for state in simgr.unconstrained:
            c = state.control
            if c.diverged:
                continue

            jump_source = state.history.jump_source
            branch = c.current_branch
            assert branch is not None
            insn = jump_source and self.angr_mgr.get_insn(jump_source)
            trace_from_ip = branch['from_ip']
            trace_to_ip = branch['to_ip']

            if insn is None:
                continue

            angr_mgr = self.angr_mgr

            # Again, we have Intel PT shenanigans to care for. The from_ip might be zero/None
            # because of retpoline and friends for some reason.
            if ((c.diverged or Angr.state_ip(state) is None) and
                (arch.is_indirect_branch_insn(insn) or arch.is_ret_insn(insn)) and
                 (trace_from_ip == jump_source or not trace_from_ip)):

                # Ensure the diverged states would succeed backtracking later.
                #
                # For now only support registers, but anyhow memory is not used today
                # due to retpolines
                if trace_to_ip and len(insn.operands) > 0 and insn.operands[0].type == capstone.CS_OP_REG:
                    reg_id = insn.operands[0].value.reg
                    reg_name = insn.reg_name(reg_id)
                    rip_reg = state.registers.load(reg_name)
                    for diverged_state in [state] + simgr.stashes['diverged']:
                        diverged_state.add_constraints(rip_reg == trace_to_ip)

                if arch.is_indirect_call_insn(insn) and not trace_to_ip:
                    # Assuming you have a state `state`
                    # Force the execution of a 'ret' instruction
                    ret_proc = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']()

                    # Drop the diverged states, they are likely to diverge
                    simgr.drop(stash='diverged')

                    state.registers.store(arch.ip_reg_name, trace_from_ip)
                    c.next_branch()
                    c.diverged = False

                    # Execute the 'ret' instruction
                    successors = angr_mgr.proj.factory.procedure_engine.process(state, procedure=ret_proc)
                    simgr.populate('active', successors.successors)
                    continue


                state.registers.store(arch.ip_reg_name, trace_to_ip)
                c.diverged = False

                # If we are returning, we need to constrain the return value
                if arch.is_ret_insn(c.last_insn) and state.history.parent is not None:
                    ret_reg_name = arch.ret_reg_name
                    ret_reg = state.registers.load(ret_reg_name)
                    parent_ret_reg = state.history.parent.state.registers.load(ret_reg_name)
                    state.add_constraints(ret_reg == parent_ret_reg)
                    state.registers.store(ret_reg_name, parent_ret_reg)

        simgr.move('unconstrained', 'active', lambda x: not x.control.diverged)

        for state in simgr.active:
            self._update_control(state, new_states)

        simgr.populate('active', new_states)
        simgr.drop(stash='unconstrained')

    def is_ret_failure(self, s: SimState) -> bool:
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]

        # Check if the last branch was a return
        if s.history.jumpkind != 'Ijk_Ret':
            return False
        
        # Check if the return value is symbolic
        ret_val = s.registers.load(arch.ret_reg_name)
        if s.solver.symbolic(ret_val):
            return False

        return AngrSim.is_failure(s = s, errcode = self.errcode)
    
    def handle_divergence(self, res: Dict[str, Any]) -> None:
        if len(self.simgr.stashes.get('diverged', [])) == 0:
            raise SystemError("simulation failed")

        s = self.simgr.stashes['diverged'][-1]
        assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]

        if s.control.expected_ip is None:
            raise SystemError("simulation failed")

        s.control.diverged = False
        s.registers.store(arch.ip_reg_name, s.control.expected_ip)

        # Move s into active
        self.simgr.move('diverged', 'active', lambda x: x is s)

        assert isinstance(res['simulation diverged'], int)
        res['simulation diverged'] += 1

    def is_void_functions(self, s: SimState) -> bool:
        sym = self.angr_mgr.get_sym(s)

        if sym in self.return_type_cache:
            return self.return_type_cache[sym] == "void"

        addr = sym.linked_addr
        if not sym.owner or not sym.owner.binary:
            return False

        with ELFDWARFAnalyzer(sym.owner.binary) as d:
            cu = d.find_cu_by_address(addr)
            if cu is None:
                return False

            t = d.find_function_return_type(cu, addr)

        self.return_type_cache[sym] = t
        return t == "void"

    def simulate(self) -> Dict[str, Union[List, int]]:
        errno = self.errcode
        ret_addr = self.caller_ret_addr
        res: Dict[str, Union[List, int]] = {
            'simulation diverged': 0,
            'divergence points': 0
        }
        
        self.simgr.populate('diverged', list())

        active = self.active_states
        if not active:
            raise RuntimeError("No active states in simulation manager")
        c = active[0].control
        trace_length = len(c.branches) - 1
        c.no_callees = False
        c.only_symbols = self.sim_syms
        del c

        msg = "simulating"
        pbar = Pbar(msg, total=trace_length, unit="branch")

        while len(self.simgr.deadended) == 0 and len(self.active_states) != 0:
            # All states should have the same instruction pointer
            pbar.update_to(self.active_states[0].control.done_branches)

            self.prepare_simulation_step()
            self.handle_exception()
            self.prepare_hooks()
            self.handle_predicated_mov()

            timed_out = self.run_one_step(res)
            if timed_out:
                pbar.set_description_str(f'{msg} (trimmed)')

            self.simgr.prune() 

            # Handle early divergance (predicated-mov)
            self.move_to_diverged()

            for s in self.active_states:
                insn = s.control.last_insn
                if insn is None:
                    continue

                sym_name = self.angr_mgr.get_sym_name(s.addr)
                logging.debug("simulating {0} -> {1} ({2: <20}) {3} {4}".format(hex(insn.address),
                    hex(s.addr), sym_name, insn.mnemonic, insn.op_str))

            self.simgr.move('active', 'deadended',
                            lambda x:len(x.control.branches) == 0 or self.is_ret_failure(x))

            if len(self.simgr.deadended) == 0 and len(self.active_states) == 0:
                pbar.set_description_str(f'{msg} (diverged)')
                self.handle_divergence(res)

        pbar.close()

        pr_msg("checking simulation...", level='DEBUG')


        simulation_successful = self.is_simulation_successful(self.simgr.deadended)
        if (not simulation_successful or
            not 'diverged' in self.simgr.stashes or
            len(self.simgr.stashes['diverged']) == 0):
            if simulation_successful:
                pr_msg("simulation successful, but no divergence found", level='DEBUG')
            raise SystemError("simulation failed")
        
        errorcode_callstack_depth = len(self.simgr.deadended[0].callstack)
        res['errorcode return depth'] = errorcode_callstack_depth

        def filter_func(s: SimState) -> str:
            assert isinstance(s.control, ControlStatePlugin)  # type: ignore[attr-defined]
            if s.addr != ret_addr and len(s.callstack) != s.control.stop_depth:
                return 'active'
            return 'stashed' if AngrSim.is_failure(s, errno) else 'deadended' 
       
        pr_msg("simulation was successful, looking for failure point...", level='DEBUG')

        diverged_list = self.simgr.stashes['diverged'].copy()
        diverged_list.reverse()
        bar_title = "backtrack"
        assert isinstance(res['divergence points'], int)
        res['divergence points'] += len(diverged_list)
        backtrack_attempts = 0

        dv: SimState

        for dv in Pbar(bar_title, diverged_list, unit="state"):
            if self.is_void_functions(dv):
                continue
            start_state = dv.copy()
            backtrack_attempts += 1
            
            dv.simplify()
            if not dv.satisfiable():
                continue

            # Skip the callees since we already tested them
            assert isinstance(dv.control, ControlStatePlugin)
            dv.control.no_callees = True
            dv.control.max_depth = self.callstack_depth(dv)
            dv.control.backtracking = True
            dv.control.stop_depth = errorcode_callstack_depth

            for stash in ['deadended', 'active', 'unconstrained', 'unsat', 'active', 'errored']:
                self.simgr.drop(stash = stash)

            # Some debug printouts
            js = start_state.history and start_state.history.jump_source 
            jt = start_state.addr
            js_str = (hex(js) if js else '')
            jt_str = hex(jt)
            js_sym_name = js and self.angr_mgr.get_sym_name(js)
            jt_sym_name = jt and self.angr_mgr.get_sym_name(jt)
            pr_msg(f'trying ({js_str} [{js_sym_name}])->({jt_str} [{jt_sym_name}])', level='DEBUG')

            self.simgr.populate('active', [dv])
            self.start_backtracking_time = time.time()
            self.simgr.run(filter_func = filter_func,
                           step_func = self.backtrack_step_func,
                           until = self.backtrack_until_func)

            if len(self.simgr.deadended) > 0:
                failure_stack = self.get_failure_stack(start_state)
                if failure_stack is not None:
                    res['failure_stack'] = failure_stack
                break

        res['backtrack'] = backtrack_attempts
        return res

    def is_ignored_function_on_stack(self, failing_state: SimState) -> bool:
        def is_ignored_function(addr: Optional[int]) -> bool:
            try:
                sym = self.angr_mgr.get_sym(addr)
            except ValueError:
                return False
            return sym and self.angr_mgr.is_ignored_sym(sym)

        for callstack_entry in failing_state.callstack:
            addr = callstack_entry.func_addr
            # Ignore zero and None
            if not addr:
                continue
            if is_ignored_function(addr):
                return True
        
        return False

    def backtrack_until_func(self, simgr: SimulationManager) -> bool:
        if time.time() - self.start_backtracking_time > self.BACKTRACK_TIMEOUT:
            return True
        return len(simgr.deadended) > 0

    def get_failure_stack(self, failing_state: Optional[SimState]) -> Optional[List[int]]:
        failure_stack: List[int] = [] 
        if failing_state is None:
            return None
        
        # Usually the source of the divergence is the root cause, but for
        # unemulated functions, we go back another entry back.
        if failing_state.history.jump_source is not None:
            failure_stack.append(failing_state.history.jump_source)
        elif failing_state.history.parent and failing_state.history.parent.jump_source:
            failure_stack.append(failing_state.history.parent.jump_source)

        for cs in failing_state.callstack:
            failure_stack.append(cs.call_site_addr)

        # Last entry is invalid
        failure_stack.pop()
        return failure_stack

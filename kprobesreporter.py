# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Dict, Iterable, List, Optional, Set, Any

from cle.backends.symbol import Symbol
from prmsg import Pbar, warn_once, pr_msg
from arch import arch
from reporter import Reporter

class KprobesReporter(Reporter):
    def report(self) -> None:
        for failure in self.failures:
            trace = self.traces[failure['trace_id']]
            sim_syms_list = [self.angr_mgr.get_sym(s) for s in failure['sim_syms']]
            sim_syms = {s for s in sim_syms_list if s is not None}
            branches = self.ftrace_to_branch(trace = trace,
                                             filter_pid = failure['pid'],
                                             sim_syms = sim_syms)
            super().report_one(branches = branches,
                               errcode = failure['errcode'],
                               sim_syms = sim_syms)

    # Converting ftrace to branches format that is common to processor trace
    # and ftrace.
    def ftrace_to_branch(self, trace: List[Dict[str, Any]], filter_pid: int, sim_syms: Set[Symbol]) -> List[Dict[str, Any]]:
        branches = []
        first = True
        insn = None
        pending_rep_insn, pending_rep_iterations = None, None
        unemulated_call_entry = None

        pbar = Pbar("processing ftrace", items=trace, unit="lines")
        for l in pbar:
            if filter_pid != l['pid']:
                # It should not happen, as we already configured ftrace to
                # filter the pid of the failure during the recording.
                warn_once(f"skipping pid {l['pid']}")
                continue

            if 'type' not in l:
                warn_once("ftrace snapshot includes unknown entries")
                continue
            
            next_ip, state = None, None

            ty = l['type']

            # If we reached the syscall tracing at the end, stop
            if ty == 'sysexit':
                pr_msg(f"processing sysexit: {l}", level="DEBUG")
                break
            elif ty == 'sysenter':
                pr_msg(f"processing sysenter: {l}", level="DEBUG")
                continue
            elif ty == 'probe':
                pr_msg(f"processing probe: {l}", level="DEBUG")
                state = arch.ftrace_state_dict(l)
                next_ip = l['addr']
            elif ty == 'ret':
                pr_msg(f"processing return - from 0x{l['from_ip']:x}@{l['from_func']} to 0x{l['to_ip']:x}@{l['to_func']}", level="DEBUG")
                next_ip = None
            elif ty == 'func':
                pr_msg(f"processing function entry - from 0x{l['from_ip']:x}@{l['from_func']} to 0x{l['to_ip']:x}@{l['to_func']}", level="DEBUG")
                try:
                    prev_insn = self.angr_mgr.get_prev_insn(l['from_ip'])
                    next_ip = prev_insn.address if prev_insn else None
                except ValueError:
                    next_ip = None
            else:
                raise ValueError(f"unknown ftrace type entry: {ty}")
                
            if first:
                insn = self.angr_mgr.get_prev_insn(l['from_ip'])
            
            first = False

            # Adding fake branches for rep instructions to reflect the number
            # of iterations that were executed.
            if pending_rep_insn is not None:
                for _ in range(0, pending_rep_iterations -
                                  arch.rep_iterations(pending_rep_insn, state)):
                    branches.append(
                        {'from_ip': pending_rep_insn.address,
                         'to_ip': pending_rep_insn.address}
                    )
                pending_rep_insn = None
                
            while insn and insn.address != next_ip:
                unemulated_call_entry = None

                pr_msg(str(insn), level="DEBUG")
                if not arch.is_branch_insn(insn):
                    insn = self.angr_mgr.next_insn(insn)
                    continue

                try:
                    target_insn = self.angr_mgr.get_branch_target_insn(insn)
                    target_sym = target_insn and self.angr_mgr.get_sym(target_insn)
                except:
                    target_insn = None
                    target_sym = None

                if arch.is_direct_jmp_insn(insn):
                    assert(target_insn is not None)
                    branches.append({'from_ip': insn.address, 'to_ip': target_insn.address})
                    insn = target_insn
                elif ((arch.is_direct_call_insn(insn) and target_sym not in sim_syms) or
                      (arch.is_indirect_call_insn(insn) and self.angr_mgr.next_insn_addr(insn) == next_ip)):
                    branches.append({'from_ip': insn.address, 'to_ip': None})
                    insn = self.angr_mgr.next_insn(insn)
                    unemulated_call_entry = {'from_ip': None, 'to_ip': insn.address}
                    branches.append(unemulated_call_entry)
                else:
                    break

            match_ip = insn and insn.address == next_ip

            if ty == 'func' and not match_ip:
                raise RuntimeError(f"Function entry trace mismatch: expected IP {hex(next_ip) if next_ip else 'None'}, but instruction is at {hex(insn.address) if insn else 'None'}")

            target_insn = None
            go_to_next_insn = False
            
            if ty == 'probe' and match_ip and unemulated_call_entry is not None:
                unemulated_call_entry['ret'] = l['ax']
                unemulated_call_entry = None

            # If insn is None at this point, we can't process branch instructions
            if insn is None:
                continue

            if arch.is_indirect_jmp_insn(insn):
                raise NotImplementedError("indirect jump")
            elif arch.is_call_insn(insn):
                if ty != 'func':
                    pass  # Skip non-function traces for call instructions
                elif not match_ip or ty != 'func':
                    raise RuntimeError(f"Call instruction trace mismatch at {hex(insn.address)}: expected function entry but got trace type '{ty}' with match_ip={match_ip}")
                else:
                    # ty == 'func'
                    to_ip = self.angr_mgr.get_sym_addr(l['to_ip'])
                    target_insn = self.angr_mgr.get_insn(to_ip)
            elif arch.is_ret_insn(insn):
                assert ty == 'ret'
                from_sym = self.angr_mgr.get_sym(insn)
                assert (from_sym is not None and from_sym.name == l['from_func'])

                target_insn = self.angr_mgr.get_insn(l['to_ip'])
            elif arch.is_cond_jmp_insn(insn):
                assert ty == 'probe'
                assert match_ip
                assert state is not None
                if arch.is_cond_jmp_taken(insn, state):
                    target_insn = self.angr_mgr.get_branch_target_insn(insn)
                    assert(target_insn is not None)
                    pr_msg(f"taken branch: {insn} -> {target_insn}", level="DEBUG")
                else:
                    go_to_next_insn = True
                    pr_msg(f"not taken branch: {insn}", level="DEBUG")
            elif arch.is_loop_insn(insn):
                assert state is not None

                if arch.is_loop_taken(insn, state):
                    target_insn = self.angr_mgr.get_branch_target_insn(insn)
                else:
                    go_to_next_insn = True
            elif arch.is_rep_insn(insn):
                assert ty == 'probe'
                assert state is not None
                pending_rep_iterations = arch.rep_iterations(insn, state)
                if pending_rep_iterations > 0:
                    pending_rep_insn = insn
                go_to_next_insn = True
            elif arch.is_predicated_mov(insn):
                # Create psuedo entry to know that the cmov was taken
                assert state is not None

                if not arch.is_cond_jmp_taken(insn, state):
                    target_insn = self.angr_mgr.next_insn(insn)

            if go_to_next_insn:
                pr_msg(str(insn), level="DEBUG")
                insn = self.angr_mgr.next_insn(insn)
            elif target_insn is not None:
                pr_msg(str(insn), level="DEBUG")
                assert insn is not None
                branch = {'from_ip':insn.address, 'to_ip':target_insn.address}
                if 'callstack' in l:
                    branch['callstack'] = l['callstack']
                if ty == 'ret':
                    branch['ret'] = l['ret']
                branches.append(branch)
                insn = target_insn

        return branches
    
    @property
    def detailed_trace(self) -> bool:
        return True

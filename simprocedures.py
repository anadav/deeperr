# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
import inspect
from typing import Optional, Set, Type, Tuple, cast
from angr.sim_state import SimState
from angr.sim_procedure import SimProcedure
from angr.errors import SimValueError
from angr.exploration_techniques.tracer import RepHook as BaseRepHook
from controlstateplugin import ControlStatePlugin
from arch import arch

def state_ip(s: SimState) -> Optional[int]:
    v = s.registers.load(arch.ip_reg_name)
    try:
        return s.solver.eval_one(v)
    except SimValueError:
        return None

def track_to_ret(proc: SimProcedure) -> None:
    state = proc.state
    control = cast(ControlStatePlugin, state.control)  # type: ignore[attr-defined]

    if control.backtracking:
        return

    ip = state_ip(state)
    assert(ip is not None)
    # TODO: Check if we need better way
    ret_ip = state.callstack.ret_addr  # type: ignore[attr-defined]
    assert(ret_ip is not None and ret_ip != 0)
    # TODO: let the arch give the address width
    if ret_ip < 0:
        ret_ip += 1 << arch.address_width

    br = control.current_branch
    while br is not None and br['to_ip'] != ret_ip:
        control.next_branch()
        br = control.current_branch

    if br is None:
        # We would not be able to return to the correct address
        control.diverged = True
        control.expected_ip = None
    else:
        br.update({
            'from_ip': None,
            'from_sym': None,
            'from_offset': None
        })

def track_out_of_syms(proc: SimProcedure, sym_names: Set[str]) -> None:
    state = proc.state
    control = cast(ControlStatePlugin, state.control)  # type: ignore[attr-defined]

    if control.backtracking:
        return

    ip = state_ip(state)
    assert(ip is not None)

    br = control.current_branch
    while br is not None and br['from_ip'] in sym_names:
        control.next_branch()
        br = control.current_branch

    if br is None:
        control.diverged = True
        control.expected_ip = None

class CopyProcedure(SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst_addr, src_addr, limit):  # type: ignore[override]
        track_to_ret(self)
        copied = self.state.solver.BVS('copied', 64)
        self.state.add_constraints(copied >= 0)  # type: ignore[operator]

        # Dead code - False condition
        # if False and 'unconstrained' in str(limit):
        #     old_limit = limit
        #     limit = self.state.solver.BVS('limit', arch.address_width)
        #     self.state.add_constraints(old_limit == limit)

        self.state.add_constraints(limit <= self.state.libc.max_memcpy_size)  # type: ignore[attr-defined]
        #self.state.add_constraints(copied <= self.state.libc.max_memcpy_size)
        self.state.add_constraints(copied <= limit)

        if not self.state.solver.is_true(copied == 0):
            src_mem = self.state.memory.load(src_addr, copied)  # type: ignore[arg-type]
            self.state.memory.store(dst_addr, src_mem, size=copied, endness='Iend_LE')

        return self.ret(limit - copied)

    def __repr__(self) -> str:
        return 'CopyProcedure'

class ReturnProcedure(SimProcedure):
    def __init__(self) -> None:
        super(ReturnProcedure, self).__init__()

    def run(self):  # type: ignore[override]
        control = cast(ControlStatePlugin, self.state.control)  # type: ignore[attr-defined]

        if control.backtracking:
            self.ret()
        
        track_out_of_syms(self, {'zen_untrain_ret', '__x86_return_thunk'})
        if control.diverged:
            return None
        
        # Force the correct return address
        if control.current_branch is not None:
            self.ret_to = control.current_branch['to_ip']  # type: ignore[attr-defined]
        r = self.ret()
        self.ret_to = None  # type: ignore[attr-defined]
        control.next_branch()
        return r

class ProcedureWrapper(SimProcedure):
    def __init__(self, proc_class: Type[SimProcedure], limits: Optional[Tuple[Optional[int], Optional[int]]] = None) -> None:
        super(ProcedureWrapper, self).__init__()
        self.proc_class = proc_class
        sig = inspect.signature(proc_class.run)
        self.n_parameters = len(sig.parameters) - 1
        self.limits = limits and enumerate(limits)

    def run(self):  # type: ignore[override]
        # Collect arguments from the state registers according to the calling convention
        track_to_ret(self)

        cc = self.state.project.factory.cc()  # type: ignore[attr-defined]
        args = cc.ARG_REGS

        # Fetch arguments from the registers
        arg_values = [self.state.registers.load(reg) for reg in args][:self.n_parameters]

        if self.limits:
            for i, (min_val, max_val) in self.limits:  # type: ignore[misc]
                if min_val is None and max_val is None:
                    continue

                val = arg_values[i]
                if max_val is not None:
                    self.state.add_constraints(val <= max_val)
                if min_val is not None:
                    self.state.add_constraints(val >= min_val)

        # call the procedure with the fetched arguments
        result = self.inline_call(self.proc_class, *arg_values).ret_expr
        if result.length == arch.address_width:
            return result
        
        return result.sign_extend(arch.address_width - result.length)

class RepHook(BaseRepHook):
    def __init__(self, mnemonic: str) -> None:
        super().__init__(mnemonic.split(" ")[1])

    def trace_to_next(self, state: SimState) -> None:
        c = cast(ControlStatePlugin, state.control)  # type: ignore[attr-defined]
        if not c.backtracking:
            addr = state.addr  # type: ignore[attr-defined]
            br = c.current_branch
            while br is not None and br['from_ip'] == addr and br['to_ip'] == addr:
                c.next_branch()
                br = c.current_branch

    def run(self, state: SimState, procedure=None, *arguments, **kwargs) -> None:  # type: ignore[override]
        self.trace_to_next(state)

        if procedure is not None:
            result = self._inline_call(state, procedure, *arguments, **kwargs)
            print(f'Result of inline call: {result}')

        
        # Invoke the run() method from the parent class
        super().run(state)

# TODO: Move to AngrSim
class RetpolineProcedure(SimProcedure):
    def __init__(self, reg: str) -> None:
        super(RetpolineProcedure, self).__init__()
        self.reg = reg

    def run(self):  # type: ignore[override]
        state = self.state
        reg = getattr(state.regs, self.reg)
        control = cast(ControlStatePlugin, state.control)  # type: ignore[attr-defined]

        if control.backtracking:
            return self.jump(reg)

        if control.current_branch is None:
            control.diverged = True
            return self.jump(reg)
        trace_from_ip = control.current_branch['from_ip']
        trace_to_ip = control.current_branch['to_ip']
        control.expected_ip = trace_to_ip
        angr_mgr = control.angr_mgr

        current_state_ip = state_ip(state)
        prev_state_ip = state.history and state.history.parent and state.history.parent.addr  # type: ignore[attr-defined]

        def in_retpoline(ip: int) -> bool:
            sym_name = angr_mgr.get_sym_name(ip)
            return (sym_name.startswith('__x86_indirect_thunk') or 
                    sym_name in {'__x86_return_thunk', 'zen_untrain_ret'})

        # When using kprobes we skip the retpolines, but when using hardware tracer
        # we keep them.
        if (current_state_ip == trace_from_ip or
            (not in_retpoline(trace_from_ip) and prev_state_ip == trace_from_ip)):
            # TODO: Handle the case in which the trace ends with a retpoline
            while in_retpoline(trace_to_ip):
                control.next_branch()
                trace_to_ip = control.current_branch['to_ip']
                trace_from_ip = control.current_branch['from_ip']
                if not in_retpoline(trace_from_ip):
                    control.diverged = True
                    break
            control.expected_ip = trace_to_ip
        else:
            control.diverged = True

        if not control.diverged:
            state.add_constraints(reg == trace_to_ip)
            control.next_branch()
            return self.jump(trace_to_ip)

        return self.jump(reg)
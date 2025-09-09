# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Tuple, Union, Callable, Set, List, Dict, Any, Optional, Iterable, TYPE_CHECKING
from abc import ABC, abstractmethod

import angr
import capstone

if TYPE_CHECKING:
    from angr.sim_state import SimState

class ControlStatePluginArch(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def copy(self) -> 'ControlStatePluginArch':
        pass

class Arch(ABC):
    def __init__(self):
        pass
    
    @abstractmethod
    def init_capstone(self) -> capstone.Cs:
        pass

    @property
    @abstractmethod
    def default_text_base(self) -> int:
        pass

    @abstractmethod
    def is_call_insn(self, insn: capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_ret_insn(self, insn: capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_branch_insn(self, insn: capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_indirect_branch_insn(self, insn: capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_direct_call_insn(self, insn: capstone.CsInsn) -> bool:
        pass

    def is_indirect_call_insn(self, insn:capstone.CsInsn) -> bool:
        return self.is_call_insn(insn) and not self.is_direct_call_insn(insn)

    @abstractmethod
    def is_rep_insn(self, insn) -> bool:
        pass

    @property
    @abstractmethod
    def arch_name(self) -> str:
        pass

    @abstractmethod
    def pyvex_workaround(self, insn:capstone.CsInsn) -> Tuple[Union[Callable, None],  bool]:
        pass

    @abstractmethod
    def nop_insn(self, size:int) -> bytes:
        pass

    @abstractmethod
    def is_predicated_mov(self, insn) -> bool:
        pass

    @abstractmethod
    def predicated_mov_constraint(self, state: 'SimState', cond_true: bool, insn: capstone.CsInsn) -> List['SimState']:
        """
        Handle predicated move instructions (CMOVxx, SETxx) by creating constrained states.
        
        Returns two states following a conditional move constraint:
        - The first is the state where the condition was met (move happened)
        - The second is the state where the condition was not met (move didn't happen)
        
        Args:
            state: The current simulation state
            cond_true: Whether the condition was actually true in the trace
            insn: The conditional move instruction
            
        Returns:
            List of two states: [taken_state, not_taken_state]
        """
        pass

    @property
    @abstractmethod
    def syscall_entry_points(self) -> Set[str]:
        pass
    
    @abstractmethod
    def is_syscall_entry_sym(self, sym_name: Optional[str]) -> bool:
        """Check if a symbol name indicates a syscall entry point.
        
        Args:
            sym_name: The symbol name to check (can be None)
            
        Returns:
            True if this is a syscall entry point symbol
        """
        pass

    @abstractmethod
    def get_direct_branch_target(self, insn:capstone.CsInsn) -> int:
        pass

    @abstractmethod
    def is_jmp_insn(self, insn) -> bool:
        pass
 
    @abstractmethod
    def is_indirect_jmp_insn(self, insn) -> bool:
        pass
 
    def is_direct_jmp_insn(self, insn) -> bool:
        return self.is_jmp_insn(insn) and not self.is_indirect_jmp_insn(insn)

    @abstractmethod 
    def is_iret_insn(self, insn:capstone.CsInsn) -> bool:
        pass
    
    @abstractmethod
    def is_sysexit_sysret_insn(self, insn:capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_fixed_rep_insn(self, insn:capstone.CsInsn) -> bool:
        pass

    @property
    @abstractmethod
    def ftrace_state_str(self) -> str:
        pass
    
    @abstractmethod
    def ftrace_state_dict(self, d:Dict[str, Any]) -> Dict[str, Any]:
        pass

    @property
    @abstractmethod
    def stack_end(self) -> int:
        pass
    
    @property
    @abstractmethod
    def per_cpu_reg(self) -> str:
        pass

    @property
    @abstractmethod
    def per_cpu_offset(self) -> int:
        pass

    @property
    @abstractmethod
    def stack_reg(self) -> str:
        pass

    @property
    @abstractmethod
    def ret_reg_name(self) -> str:
        pass

    @property
    @abstractmethod
    def stack_related_reg_names(self) -> List[str]:
        pass

    @property
    @abstractmethod
    def ip_reg_name(self) -> str:
        pass

    @abstractmethod
    def is_cond_branch_insn(self, insn:capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_direct_branch_insn(self, insn:capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_indirect_branch_target(self, insn:capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_cond_jmp_insn(self, insn:capstone.CsInsn) -> bool:
        pass

    @abstractmethod
    def is_cond_jmp_taken(self, insn:capstone.CsInsn, state:Dict[str, Any]) -> bool:
        pass
    
    @abstractmethod
    def is_loop_insn(self, insn:capstone.CsInsn) -> bool:
        pass
    
    @abstractmethod
    def is_loop_taken(self, insn:capstone.CsInsn, state:Dict[str, Any]) -> bool:
        pass

    @abstractmethod
    def rep_iterations(self, insn:capstone.CsInsn, state:Dict) -> int:
        pass

    @property
    @abstractmethod
    def syscall_insn_len(self) -> int:
        pass
  
    @abstractmethod
    def controlStatePluginArch(self) -> ControlStatePluginArch:
        pass

    @property
    @abstractmethod
    def page_size(self) -> int:
        pass

    @abstractmethod
    def parse_interrupt_table(self, proj:angr.Project) -> Dict[int, int]:
        pass

    @abstractmethod
    def init_symbols(self, proj:angr.Project) -> None:
        pass

    @abstractmethod
    def is_exception_vector(self, vector:int) -> bool:
        pass

    @property
    @abstractmethod
    def irq_exit_sym_names(self) -> Set[str]:
        pass

    @property
    @abstractmethod
    def address_width(self) -> int:
        pass

    @property
    @abstractmethod
    def stack_size(self) -> int:
        """Size of a stack element in bytes (word size for stack operations)"""
        pass

    @property
    @abstractmethod
    def pointer_size(self) -> int:
        """Size of a pointer in bytes"""
        pass
import os
import logging
from typing import Optional, Tuple, Any
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarfinfo import DWARFInfo
from elftools.dwarf.die import DIE
from elftools.dwarf.descriptions import describe_form_class
from elftools.common.exceptions import DWARFError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ELFDWARFAnalyzer:
    def __init__(self, filename: str):
        self.filename = filename
        self.elffile = None
        self.dwarfinfo = None

    def __enter__(self):
        self.elffile = ELFFile(open(self.filename, 'rb'))
        self.dwarfinfo = self.elffile.get_dwarf_info()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.elffile:
            self.elffile.stream.close()

    def find_cu_by_address(self, address: int) -> Optional[Any]:
        """Find the Compilation Unit (CU) containing the given address."""
        aranges = self.dwarfinfo.get_aranges()
        cu_offset = aranges.cu_offset_at_addr(address)
        if cu_offset is not None:
            for CU in self.dwarfinfo.iter_CUs():
                if CU.cu_offset == cu_offset:
                    return CU
        return None

    def get_referenced_die(self, cu: Any, attr: Any) -> Optional[DIE]:
        """Get the DIE referenced by an attribute."""
        form_class = describe_form_class(attr.form)
        if form_class == 'reference':
            if attr.form.startswith('DW_FORM_ref'):
                return self.dwarfinfo.get_DIE_from_refaddr(cu.cu_offset + attr.value, cu)
            elif attr.form in ['DW_FORM_ref_addr', 'DW_FORM_data4', 'DW_FORM_data8']:
                return self.dwarfinfo.get_DIE_from_refaddr(attr.value)
        raise DWARFError(f"Unsupported reference form: {attr.form}")

    def resolve_type(self, die: DIE, prefix: str = "", is_type = False, depth: int = 0) -> str:
        """Resolve the type name of a DIE."""
        if depth > 10:
            return "<max depth reached>"

        if die.tag == 'DW_TAG_pointer_type':
            prefix = prefix + "*"

        if 'DW_AT_abstract_origin' in die.attributes:
            origin_attr = die.attributes['DW_AT_abstract_origin']
            origin_die = self.get_referenced_die(die.cu, origin_attr)
            return self.resolve_type(origin_die, prefix, is_type, depth + 1)

        if 'DW_AT_type' in die.attributes:
            type_attr = die.attributes['DW_AT_type']
            type_die = self.get_referenced_die(die.cu, type_attr)
            return self.resolve_type(type_die, prefix, True, depth + 1)

        if is_type and 'DW_AT_name' in die.attributes:
            return prefix + die.attributes['DW_AT_name'].value.decode('utf-8')

        return "void"

    def find_function_return_type(self, cu: Any, func_address: int) -> Optional[str]:
        """Find the return type of a function at a given address."""
        for die in cu.get_top_DIE().iter_children():
            if die.tag != 'DW_TAG_subprogram':
                continue

            if 'DW_AT_low_pc' not in die.attributes or 'DW_AT_high_pc' not in die.attributes:
                continue

            low_pc = die.attributes['DW_AT_low_pc'].value
            high_pc_attr = die.attributes['DW_AT_high_pc']
            high_pc = (low_pc + high_pc_attr.value 
                       if high_pc_attr.form != 'DW_FORM_addr' 
                       else high_pc_attr.value)

            if low_pc <= func_address < high_pc:
                logger.info(f"Found function DIE at offset: 0x{die.offset:x}")
                logger.info(f"Function address range: 0x{low_pc:x} - 0x{high_pc:x}")
                return self.resolve_type(die)

        logger.warning(f"No return type found for function at address {hex(func_address)}")
        return None

    def find_source_location(self, func_address: int) -> Tuple[Optional[str], Optional[int], Optional[int]]:
        """Find the source file, line number, and column for a given function address."""
        cu = self.find_cu_by_address(func_address)
        if cu is None:
            logger.warning(f"No CU found for address {hex(func_address)}")
            return None, None, None

        return_type = self.find_function_return_type(cu, func_address)
        logger.info(f"Function at address {hex(func_address)} returns type: {return_type}")

        lineprog = self.dwarfinfo.line_program_for_CU(cu)
        prev_state = None

        for entry in lineprog.get_entries():
            if not entry.state:
                continue

            if entry.state.address <= func_address:
                prev_state = entry.state
            else:
                break

        if prev_state:
            file_entry = lineprog['file_entry'][prev_state.file - 1]
            file_name = file_entry.name.decode('utf-8')
            directory = (lineprog['include_directory'][file_entry.dir_index - 1].decode('utf-8')
                         if file_entry.dir_index > 0 else '.')
            full_path = os.path.join(directory, file_name)

            logger.info(f"Address {hex(func_address)} found in {full_path}:{prev_state.line}, column {prev_state.column}")
            return full_path, prev_state.line, prev_state.column

        logger.warning(f"No source location found for address {hex(func_address)}")
        return None, None, None

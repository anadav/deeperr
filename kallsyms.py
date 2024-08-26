# Copyright 2023 VMware, Inc.
# SPDX-License-Identifier: BSD-2-Clause
from typing import Any, Dict, Tuple, List, Optional, Set, Iterable, Callable
import logging
import pathlib
import io
import struct
import os
import zstandard as zstd
import lief
from intervaltree import IntervalTree
from prmsg import pr_msg
from collections import defaultdict
from typing import BinaryIO

from elftools.elf.elffile import ELFFile

import cle.backends
import angr
from arch import arch

def get_vmlinux(user_option:Optional[List[BinaryIO]]) -> List[BinaryIO]:
    if user_option is None:
        user_option = []

    # Check if any of the filenames includes 'vmlinux'
    if any('vmlinux' in pathlib.Path(f.name).stem for f in user_option):
        return user_option
    
    vmlinux_search = [
        f'/usr/lib/debug/boot/vmlinux-{os.uname().release}',
        'vmlinux'
    ]
    for vmlinux in vmlinux_search:
        try:
            f = open(vmlinux, 'rb')
            pr_msg(f'Using vmlinux file {vmlinux}', level='INFO')
            user_option.append(f)
            return user_option
        except FileNotFoundError:
            pass
        except PermissionError:
            pr_msg(f'Could not open vmlinux file {vmlinux}', level='ERROR')

    pr_msg('Could not find vmlinux file, trying to continue without one', level='ERROR')
    pr_msg('''Consider installing symbols using:
                sudo apt install linux-image-$(uname -r)-dbgsym [deb/ubuntu]
                sudo dnf debuginfo-install kernel [fedora]
                sudo pacman -S linux-headers [arch]
                sudo emerge -av sys-kernel/linux-headers [gentoo]
            ''', level='WARN')
    return user_option

def find_module_dbg(module_name:str):
    pathes = [f'/usr/lib/debug/lib/modules/{os.uname().release}']
    for path in pathes:
        if not os.path.exists(path) or not os.path.isdir(path):
            continue
        for root, dirs, files in os.walk(path):
            for file in files:
                if file == f'{module_name}.ko' or file == f'{module_name}.ko.debug':
                    return os.path.join(root, file)
    return None

lief_to_angr_type_map:Dict[Any, angr.cle.backends.SymbolType] = {
    lief.ELF.Symbol.TYPE.OBJECT: angr.cle.backends.SymbolType.TYPE_OBJECT,
    lief.ELF.Symbol.TYPE.FUNC: angr.cle.backends.SymbolType.TYPE_FUNCTION,
    lief.ELF.Symbol.TYPE.FILE: angr.cle.backends.SymbolType.TYPE_OTHER,
    lief.ELF.Symbol.TYPE.SECTION: angr.cle.backends.SymbolType.TYPE_SECTION,
    lief.ELF.Symbol.TYPE.COMMON: angr.cle.backends.SymbolType.TYPE_OTHER,
    lief.ELF.Symbol.TYPE.TLS: angr.cle.backends.SymbolType.TYPE_TLS_OBJECT,
    lief.ELF.Symbol.TYPE.GNU_IFUNC: angr.cle.backends.SymbolType.TYPE_OTHER,
    lief.ELF.Symbol.TYPE.NOTYPE: angr.cle.backends.SymbolType.TYPE_NONE,
}

class Kallsyms:
    def __init__(self, objs:List[io.BufferedReader]):
        self.parsed_modules = self.parse_proc_modules()
        self.__find_modules()

        self.keep_sym_types: Set[str] = {'t', 'T', 'w', 'W', 'r', 'R'}
        self.type_map:Dict[str, angr.cle.backends.SymbolType] = {
                    'a':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'A':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'd':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'D':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'b':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'B':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'r':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'R':angr.cle.backends.SymbolType.TYPE_OBJECT,
                    'v':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'V':angr.cle.backends.SymbolType.TYPE_OTHER,
                    't':angr.cle.backends.SymbolType.TYPE_FUNCTION,
                    'T':angr.cle.backends.SymbolType.TYPE_FUNCTION,
                    'w':angr.cle.backends.SymbolType.TYPE_OTHER,
                    'W':angr.cle.backends.SymbolType.TYPE_OTHER,
        }

        #self.remapped_module_sections = self.read_module_sections()
        self.intervals = IntervalTree()

        obj_basenames = {self.__get_basename(pathlib.Path(f.name).stem):f for f in objs}

        self.remapped_syms = self.__read_symbols()

        for module, syms in self.remapped_syms.items():
            if module.startswith('__builtin') or module.startswith('bpf:'):
                min_addr = self.__get_min_addr(syms)
                max_addr = self.__get_max_addr(syms)
                sz = max_addr - min_addr
                self.intervals[min_addr:max_addr] = module

        self.exes = dict()

        self.__read_module_syms(obj_basenames)

        self.__read_vmlinux_syms(obj_basenames)

        # create sorted list of (module-address, module-name)
        sorted_modules_list = sorted(self.parsed_modules.items(), key=lambda x: x[1]['address'])

        next_module_start = dict()
        # match each module with the next start
        for i, (module, module_info) in enumerate(sorted_modules_list):
            next_module_start[module] = (None if i == len(sorted_modules_list) - 1 else 
                                        sorted_modules_list[i + 1][1]['address'])

        for non_module in self.remapped_syms.keys() - self.parsed_modules.keys() - {'vmlinux'}:
            syms = self.remapped_syms[non_module]
            min_addr = self.__get_min_addr(syms)
            max_addr = self.__get_max_addr(syms)
            sz = max_addr - min_addr
            self.exes[non_module] = {
                'mapped_addr': min_addr,
                'base_addr': 0,
                'size': sz,
                'symbols': self.__relative_symbol_tuples(syms, min_addr, sz),
                'path': None,
                'segments': [(min_addr, max_addr)],
            }

        # Save memory and help pickle
        del self.intervals

    @staticmethod
    def get_build_id(binary:lief.ELF.Binary) -> Optional[str]:
        for note in binary.notes:
            if note.type == lief.ELF.Note.TYPE.GNU_BUILD_ID and note.name == "GNU":
                return note.description.hex()
        return None

    @staticmethod
    def get_ro_sections(binary:lief.ELF.Binary) -> Dict[str, Dict[str, any]]:
        sections = dict()
        for section in binary.sections:
            if section.name.startswith('.note'):
                continue
            if ((section.has(lief.ELF.Section.FLAGS.ALLOC) and not section.has(lief.ELF.Section.FLAGS.WRITE))
                or section.name.startswith('.rodata')):
                sections[section.name] = {
                    'address': section.virtual_address,
                    'size': section.size,
                    'symbols': []
                }

        return sections

    def __read_module_syms(self, obj_basenames:Dict[str, io.BufferedReader]) -> Dict[str, List[Tuple[str, int, str, Optional[int]]]]:
        obj_names = self.remapped_syms.keys()
        parsed_module_names = self.parsed_modules.keys()

        for obj_name in obj_names & parsed_module_names:
            path = (obj_basenames[obj_name].name if obj_name in obj_basenames
                    else self.parsed_modules[obj_name].get('path'))

            if path is None:
                continue

            binary = lief.parse(path)

            # Check build-id
            build_id = Kallsyms.get_build_id(binary)
            live_build_id = Kallsyms.get_module_build_id(obj_name)
            if live_build_id != build_id:
                raise Exception(f"Build ID mismatch for {obj_name}")

            sections = Kallsyms.get_ro_sections(binary)

            # Populate the dictionary with symbols
            for s in binary.symbols:
                if s.name != '' and s.size != 0 and s.section is not None and s.section.name in sections:
                    symbol_info = (s.name, s.value, lief_to_angr_type_map[s.type], s.size)
                    sections[s.section.name]['symbols'].append(symbol_info)

            live_sections = Kallsyms.read_live_module_sections(obj_name)

            for section_name, section_mapped_addr in live_sections.items():
                if section_name not in sections:
                    continue

                section = sections[section_name]

                symbols = section['symbols']
                if len(symbols) == 0:
                    continue

                self.exes[f'{obj_name}:{section_name}'] = {
                    'mapped_addr': section_mapped_addr,
                    'base_addr': section['address'],
                    'size': section['size'],
                    'symbols': symbols,
                    'path': self.parsed_modules[obj_name].get('path'),
                    'segments': [(section_mapped_addr, section_mapped_addr + section['size'])],
                }

        for exe, details in self.exes.items():
            self.intervals[details['mapped_addr']:details['mapped_addr'] + details['size']] = exe

        to_remove_exes = []
        for exe, details in self.exes.items():
            if exe in to_remove_exes:
                continue

            overlap = self.intervals.overlap(details['mapped_addr'], details['mapped_addr'] + details['size'])
            n_ovelapping = len(overlap)
            if n_ovelapping <= 1:
                continue

            # Remove this exe if it is an init section (probably removed)
            if ':.init' in exe:
                to_remove_exes.append(exe)
                for overlapping in overlap:
                    if overlapping.data == exe:
                        self.intervals.remove(overlapping)
                continue

            # Remove other init sections
            for overlapping in overlap:
                if ':.init' in overlapping.data:
                    assert exe not in to_remove_exes
                    to_remove_exes.append(overlapping.data)
                    self.intervals.remove(overlapping)
                    n_ovelapping -= 1
                if n_ovelapping == 1:
                    break
            if n_ovelapping > 1:
                pr_msg(f"Could not resolve overlapping sections for {exe}", level='ERROR')
                raise Exception(f"Could not resolve overlapping sections for {exe}")

        for exe in to_remove_exes:
            del self.exes[exe]

    def __read_vmlinux_syms(self, obj_basenames:Dict[str, io.BufferedReader]) -> Tuple[int, List[Tuple[str, int, str, Optional[int]]]]:
        path = obj_basenames['vmlinux'].name if 'vmlinux' in obj_basenames else None

        remapped_base = None
        with open('/proc/kcore', 'rb') as f:
            elffile = ELFFile(f)
            for segment in elffile.iter_segments():
                if segment['p_type'] == 'PT_LOAD':
                    remapped_base = segment['p_vaddr']
                    load_size = segment['p_memsz']
                    break

        if remapped_base is None:
            pr_msg(f"Could not find remapped base address for vmlinux", level='ERROR')
            raise Exception(f"Could not find remapped base address for vmlinux")

        if path is None:
            pr_msg(f'Could not find vmlinux file', level='ERROR')
            raise FileNotFoundError(f'Could not find vmlinux file')

        binary = lief.parse(path)
        build_id = Kallsyms.get_build_id(binary)
        live_build_id = Kallsyms.get_build_id_from_kernel_notes(pathlib.Path("/sys/kernel/notes"))
        if live_build_id != build_id:
            raise Exception(f"Build ID mismatch for vmlinux")

        sections = {section.name:section for section in binary.sections}
        sections_to_alloc = [section for section in binary.sections
                               if section.has(lief.ELF.Section.FLAGS.ALLOC)
                               and 'percpu' not in section.name
                               and '.note' not in section.name]
        sections_to_load = [section.name for section in sections_to_alloc
                            if not section.has(lief.ELF.Section.FLAGS.WRITE)]
        section_names_to_alloc = {section.name for section in sections_to_alloc}

        base_addr = min([section.virtual_address for section in sections_to_alloc])

        symbols = [s for s in binary.symbols if s.section is not None]
        symbols = [s for s in symbols if s.section.name in section_names_to_alloc]

        rebased_symbols = [(s.name, s.value - base_addr, lief_to_angr_type_map[s.type], s.size) for s in symbols]

        segments_to_load = [(sections[s].virtual_address - base_addr + remapped_base,
                             sections[s].virtual_address + sections[s].size - base_addr + remapped_base) for s in sections_to_load]

        try:
            idt_table_sym = [s for s in rebased_symbols if s[0] == 'idt_table'][0]
        except:
            pr_msg(f"Could not find idt_table symbol in vmlinux", level='WARN')

        segments_to_load.append((idt_table_sym[1] + remapped_base, idt_table_sym[1] + idt_table_sym[3] + remapped_base))

        self.exes['vmlinux'] = {
            'mapped_addr': remapped_base,
            'base_addr': base_addr,
            'size': load_size,
            'symbols': rebased_symbols,
            'path': obj_basenames['vmlinux'].name,
            'segments': segments_to_load,
        }

    def decompress_file(input_file, output_file):
        dctx = zstd.ZstdDecompressor()
        with open(input_file, 'rb') as ifh, open(output_file, 'wb') as ofh:
            dctx.copy_stream(ifh, ofh)

    def __find_modules(self):
        pathes = [f'/usr/lib/debug/lib/modules/{os.uname().release}']
        tmp_path = '/tmp/modules'
        if not os.path.exists(tmp_path):
            os.mkdir(tmp_path)

        for path in pathes:
            if not os.path.exists(path) or not os.path.isdir(path):
                continue

            for root, dirs, files in os.walk(path):
                for file in files:
                    zst = file.endswith('.ko.zst')
                    if not file.endswith('.ko.debug') and not file.endswith('.ko') and not zst:
                        continue

                    # In kallsyms modules show with underscores instead of dashes
                    basename = pathlib.Path(file).stem.split('.')[0]
                    basename_underscored = basename.replace('-', '_')

                    for obj_name in [basename, basename_underscored]:
                        if obj_name not in self.parsed_modules:
                            continue
                        if zst:
                            # check if the file is already decompressed
                            obj_path = os.path.join(tmp_path, obj_name + '.ko')
                            if not os.path.exists(obj_path):
                                Kallsyms.decompress_file(os.path.join(root, file), obj_path)
                        else:
                            obj_path = os.path.join(root, file)

                        self.parsed_modules[obj_name]['path'] = obj_path

    def __relative_symbol_tuples(self, syms:List[Tuple[str, int, str, Optional[int]]], base_addr:int, sz:int) -> List[Tuple[str, int, str, Optional[int]]]:
            max_addr = base_addr + sz

            return [(s[0], s[1] - base_addr, s[2], s[3]) for s in syms if s[1] >= base_addr and s[1] < max_addr]

    def __get_min_addr(self, syms:List[Tuple[str, int, str, Optional[int]]]) -> int:
        return min([s[1] for s in syms if s[2] in {'t', 'T', 'r', 'R'}])

    def __get_max_addr(self, syms:List[Tuple[str, int, str, Optional[int]]]) -> int:
        return max([s[1] + s[3] for s in syms if s[2] in {'t', 'T', 'r', 'R'} and s[3] is not None])


    def __read_symbols(self) -> Dict[str, List[Tuple[str, int, str, Optional[int]]]]:
        builtin_index:defaultdict[str, int] = defaultdict(int)
        global arch

        f = open("/proc/kallsyms", "rb")
        logging.info("reading symbols")
        f.seek(0)

        data = f.read().decode("ascii")

        raw = []
        for l in data.splitlines():
            name = l.split()[2]
            addr = int(l.split()[0], 16)
            sym_type = l.split()[1]
            module_name = 'vmlinux' if len(l.split()) < 4 else l.split()[3][1:-1]

            # Builtin sections can overlap each other, which angr doesn't like. So
            # we are not going to merge them. And instead we are creating each one a
            # unique name with a different suffix.
            if module_name.startswith('__builtin_ftrace'):
                pass
            if module_name.startswith('__builtin') or module_name in {'bpf'}:
                suffix = builtin_index[module_name]
                builtin_index[module_name] += 1
                module_name = f'{module_name}:{suffix}'

            raw.append((name, addr, sym_type, module_name))

        list.sort(raw, key=lambda x:x[1])
        if len(raw) == 0:
            pr_msg("cannot read symbol addresses from kallsyms", level="ERROR")
            raise Exception()

        syms = defaultdict(list)

        # Guess the sizes
        prev = raw[0]
        for sa in raw[1:]:
            syms[prev[3]].append((prev[0], prev[1], prev[2], sa[1] - prev[1])) 
            prev = sa

        remaining_in_page = arch.page_size - prev[1] % arch.page_size
        syms[prev[3]].append((prev[0], prev[1], prev[2], remaining_in_page))
        return syms # type: ignore
    
    @staticmethod
    def __get_basename(filename: str) -> str:
        if filename.startswith('vmlinux'):
            return 'vmlinux'
        
        stem = filename.split('.')[0]
        return stem.replace('-', '_')

    @staticmethod
    def extract_build_id(data) -> Optional[str]:
        build_id = None
        offset = 0
        while offset < len(data):
            namesz, descsz, note_type = struct.unpack_from('III', data, offset)
            offset += 12

            name_start = offset
            name_end = name_start + namesz
            name = data[offset:offset + namesz].rstrip(b'\x00')

            desc_start = (name_end + 3) & ~3
            desc_end = desc_start + descsz

            # Get it from the last note if there are multiple ones
            if note_type == lief.ELF.Note.TYPE.GNU_BUILD_ID and name == b"GNU":
                build_id = data[desc_start:desc_end]

            offset = (desc_end + 3) & ~3
        
        if build_id is None:
            return None
        
        build_id_hex = ''.join([format(byte, '02x') for byte in build_id])
        return build_id_hex

    @staticmethod
    def get_module_build_id(module_name) -> Optional[str]:
        build_id_path = pathlib.Path(f"/sys/module/{module_name}/notes/.note.gnu.build-id")
        
        if not build_id_path.exists():
            raise Exception(f"{build_id_path} not found. Ensure the module is loaded and you have the required permissions.")

        data = build_id_path.read_bytes()
        return Kallsyms.extract_build_id(data)

    @staticmethod
    def get_build_id_from_kernel_notes(kernel_notes_file:pathlib.Path):
        data = kernel_notes_file.read_bytes()
        return Kallsyms.extract_build_id(data)

    @staticmethod
    def read_live_module_sections(module:str) -> Dict[str, Dict[str, int]]:
        module_sections = {}

        module_path = os.path.join('/sys/module', module, 'sections')
        if not os.path.isdir(module_path):
            return module_sections

        for section_file in os.listdir(module_path):
            section_file_path = os.path.join(module_path, section_file)
            try:
                with open(section_file_path, 'r') as f:
                    value = int(f.read().strip(), 16)  # Assuming the values are in hexadecimal
                    module_sections[section_file] = value
            except (OSError, ValueError) as e:
                print(f"Error reading {section_file_path}: {e}")

        return module_sections

    def parse_proc_modules(self) -> Dict[str, Dict[str, Any]]:
        modules = dict()

        with open('/proc/modules', 'r') as f:
            for line in f:
                parts = line.strip().split()
                module_name = parts[0]
                module_size = int(parts[1])
                module_address = int(parts[5], 16)

                module_info = {
                    'size': module_size,
                    'address': module_address
                }
                modules[module_name] = module_info

        return modules

    def get_symbols(self, backend:cle.Backend, name:str) -> List[cle.Symbol]:
        syms = self.exes[name]['symbols']
        assert isinstance(syms, list)

        if name.startswith('__builtin') or name.startswith('bpf:'):
            syms = [cle.Symbol(owner = backend, name = s[0],
                    relative_addr = s[1],
                    sym_type = self.type_map[s[2]],
                    size = s[3]) for s in syms]
        else:
            syms = [cle.Symbol(owner = backend, name = s[0],
                    relative_addr = s[1],
                    sym_type = s[2],
                    size = s[3]) for s in syms]

        return syms
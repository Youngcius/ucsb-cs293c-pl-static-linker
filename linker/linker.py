"""Static Linker """
from typing import List, Tuple, Dict
from collections import Counter
from numpy import cumsum, ceil
import os
import stat
import lief

from .simpleelf import elf_consts
from .simpleelf.elf_builder import ElfBuilder

from .interface import Relocation
from .utils import display_relocations, display_sections, display_segments, display_symbols
from .utils import check_symbols, replace_content, RELA_TYPES , SEG_FLAGS

try:
    from rich.console import Console
    console = Console()
    print = console.print
    rule = console.rule
except:
    pass


SUPPORTED_SECTIONS = ['.text', '.rodata', '.data', '.bss']
START_SYM_NAME = '_start'
# MAP_SEC_TO_SEG = {'RX': '.text', 'R': '.rodata', 'RW': ['.data', '.bss']}
START_ADDR = 0x400000  # customized
# START_ADDR = 0x0  # customized
PAGE_SIZE = 0x1000  # page size is 4KB on Linux64
EHSIZE = 64  # ELF header size for x86_64
PHENTSIZE = 56  # Program header entry size for x86_64
SHENTSIZE = 64  # Section header entry size for x86_64

EMPTY_EXE = 'empty.out'


def init_exe_binary(entry_point: int) -> lief.ELF.Binary:
    from simpleelf import elf_consts
    from simpleelf.elf_builder import ElfBuilder
    e = ElfBuilder(elf_consts.ELFCLASS64)
    e.set_type(elf_consts.ET_DYN)
    e.set_endianity('<')
    e.set_machine(elf_consts.EM_X86_64)
    e.set_entry(entry_point)
    elf_raw = e.build()
    open(EMPTY_EXE, 'wb').write(elf_raw)
    empty = lief.parse(EMPTY_EXE)
    sec = empty.sections[0]
    sec.alignment = 0
    sec.offset = 0
    return empty


def parse_elf_info(binaries: List[lief.ELF.Binary], *sec_names: str) -> Tuple[List[lief.ELF.Symbol], List[lief.ELF.Relocation], Dict[str, List[lief.ELF.Section]]]:
    """
    Parse ELF information from binaries.
    :param binaries: a list of lief.ELF.Binary
    :param sec_names: determine which sections to be extracted
    """
    # .text section: 代码段
    # .data section: 已初始化的全局和静态 C 变量
    # .bss section: 未初始化的全局和静态 C 变量，以及所有被初始化为 0 的全局或静态变量
    # .rodata section: 只读数据，比如 printf 语句中的格式串和开关语句的跳转表
    all_sections = {sec_name: [] for sec_name in sec_names}
    symbols = []
    rela_infos = []
    for binary in binaries:
        for sec_name in sec_names:
            if binary.has_section(sec_name):
                all_sections[sec_name].append(binary.get_section(sec_name))
        symbols += binary.symbols
        rela_infos += binary.relocations
    symbols = list(filter(lambda sym: not (sym.binding == lief.ELF.SYMBOL_BINDINGS.LOCAL and sym.type == lief.ELF.SYMBOL_TYPES.SECTION), symbols))
    for shndx in range(len(sec_names), -1, -1):
        sec_sym = lief.ELF.Symbol()
        sec_sym.shndx = shndx
        sec_sym.type = lief.ELF.SYMBOL_TYPES.SECTION
        sec_sym.binding = lief.ELF.SYMBOL_BINDINGS.LOCAL
        symbols.insert(1, sec_sym)
    rela_infos = list(filter(lambda rela: rela.section.name in sec_names, rela_infos))
    rela_infos = [Relocation.from_lief(rela) for rela in rela_infos]
    return symbols, rela_infos, all_sections


def link_objs_to_exe(objs: List[str], exe: str) -> None:
    """Link relocatable object files to an executable file"""
    assert all(map(lambda obj: obj.endswith('.o'), objs)), "Not all input files are relocatable object files"
    obj_binaries: List[lief.ELF.Binary] = []
    for obj in objs:
        if not os.path.exists(obj):
            raise FileNotFoundError(f"{obj} not found")
        if not lief.is_elf(obj):
            raise ValueError(f"{obj} is not an ELF file")
        obj_binaries.append(lief.parse(obj))

    ######################################################
    # parse elf information
    ################
    symbols, rela_infos, all_sections = parse_elf_info(obj_binaries, *SUPPORTED_SECTIONS)


    ######################################################
    # resolving symbols
    ################
    symbols = resolve_symbols(symbols)
    print('Resolving symbols completed.')
    
    rule('Before merging and relocation')
    print('[blue]Relocation infos:')
    display_relocations(rela_infos)
    print()
    print('[blue]BSS sections:')
    display_sections(all_sections['.bss'])
    print()
    print('[blue]Text sections:')
    display_sections(all_sections['.text'])
    print()
    print('[blue]Data sections:')
    display_sections(all_sections['.data'])
    print()
    print('[blue]All symbols:')
    display_symbols(symbols)
    print()

    ######################################################
    # merging sections, update symbols and rela_infos
    ################
    none_section = obj_binaries[0].sections[0]
    text_section = merge_sections(all_sections['.text'], '.text')
    rodata_section = merge_sections(all_sections['.rodata'], '.rodata')
    data_section = merge_sections(all_sections['.data'], '.data')
    bss_section = merge_sections(all_sections['.bss'], '.bss')
    symbols = relocate_symbols_when_merging_sections(text_section, all_sections['.text'], symbols, SUPPORTED_SECTIONS.index('.text') + 1)
    symbols = relocate_symbols_when_merging_sections(rodata_section, all_sections['.rodata'], symbols, SUPPORTED_SECTIONS.index('.rodata') + 1)
    symbols = relocate_symbols_when_merging_sections(data_section, all_sections['.data'], symbols, SUPPORTED_SECTIONS.index('.data') + 1)
    symbols = relocate_symbols_when_merging_sections(bss_section, all_sections['.bss'], symbols, SUPPORTED_SECTIONS.index('.bss') + 1)
    rela_infos = relocate_relocations_when_merging_sections(text_section, all_sections['.text'], rela_infos, symbols, SUPPORTED_SECTIONS.index('.text') + 1)
    rela_infos = relocate_relocations_when_merging_sections(rodata_section, all_sections['.rodata'], rela_infos, symbols, SUPPORTED_SECTIONS.index('.rodata') + 1)
    rela_infos = relocate_relocations_when_merging_sections(data_section, all_sections['.data'], rela_infos, symbols, SUPPORTED_SECTIONS.index('.data') + 1)
    rela_infos = relocate_relocations_when_merging_sections(bss_section, all_sections['.bss'], rela_infos, symbols, SUPPORTED_SECTIONS.index('.bss') + 1)

    # update segments
    base_offset, segments = assemble_into_segments(START_ADDR, RX=[text_section], R=[rodata_section], RW=[data_section, bss_section])
    start_sym = [sym for sym in symbols if sym.name == START_SYM_NAME][0]
    entry_point = base_offset + start_sym.value  # TODO: 这里还没有将sym.value转换为virtual address (其实也没必要)
    print({'entry_point': entry_point})


    ######################################################
    # relocate addresses
    ################
    relocate_addresses([none_section, text_section, rodata_section, data_section], symbols, rela_infos)


    # update segments again
    base_offset, segments = assemble_into_segments(START_ADDR, RX=[text_section], R=[rodata_section], RW=[data_section, bss_section])
    start_sym = [sym for sym in symbols if sym.name == START_SYM_NAME][0]
    entry_point = base_offset + start_sym.value  # TODO: 这里还没有将sym.value转换为virtual address (其实也没必要)
    print({'entry_point': entry_point})


    rule('After merging and relocation')
    print('[blue]Sections:')
    display_sections([text_section, rodata_section, data_section, bss_section])
    print()
    print('[blue]Symbols:')
    display_symbols(symbols)
    print()

    ######################################################
    # build executable file (via lief)
    ################
    # exe_binary = init_exe_binary(entry_point)
    # exe_binary.add(text_section, loaded=True)
    # exe_binary.add(rodata_section, loaded=True)
    # exe_binary.add(data_section, loaded=True)
    # exe_binary.add(bss_section, loaded=True)
    # for seg in segments:
    #     exe_binary.add(seg)
    # length_sym_names = 0
    # for sym in symbols:
    #     exe_binary.add_static_symbol(sym)
    #     if len(sym.name) > 0:
    #         length_sym_names += len(sym.name) + 1

    # print({'length_sym_names': length_sym_names})

    # builder = lief.ELF.Builder(exe_binary)
    # builder.build()
    # rule('after building')
    # display_sections(exe_binary.sections)

    # exe_binary.write(exe)
    # st = os.stat(exe)
    # os.chmod(exe, st.st_mode | stat.S_IEXEC)
    # os.remove(EMPTY_EXE)

    ######################################################
    # build executable file (via simpleelf)
    ################
    e = ElfBuilder(elf_consts.ELFCLASS64)
    e.set_type(elf_consts.ET_DYN)
    e.set_endianity('<')
    e.set_machine(elf_consts.EM_X86_64)
    e.set_entry(entry_point)

    for seg in segments:
        e.add_segment(seg.virtual_address, seg.content.tobytes(), elf_consts.PF_R | elf_consts.PF_W | elf_consts.PF_X) # TODO: RWX might need to be modified

    e.add_code_section('.text', text_section.offset, text_section.size, )
    # e.add_section(elf_consts.SHT_PROGBITS, rodata_section.offset, rodata_section.size, '.rodata', elf_consts.SHF_ALLOC | elf_consts.SHF_WRITE)
    # e.add_section(elf_consts.SHT_NOBITS, data_section.offset, data_section.size, '.data', elf_consts.SHF_WRITE)
    # e.add_empty_data_section('.bss', bss_section.offset, bss_section.size)

    elf_raw = e.build()
    open(exe, 'wb').write(elf_raw)
    exe_binary = lief.parse(exe)
    sec = exe_binary.sections[0]  # remedy the first NULL section
    sec.alignment = 0
    sec.offset = 0
    exe_binary.write(exe)

    rule('after building')
    print('[blue]Sections:')
    display_sections(exe_binary.sections)
    print()
    print('[blue]Segments:')
    display_segments(exe_binary.segments)
    print()
    print('[blue]Symbols:')
    display_symbols(exe_binary.symbols)


def resolve_symbols(symbols: List[lief.ELF.Symbol]) -> List[lief.ELF.Symbol]:
    """
    Resolve symbols
    ---
    ! Suppose there is no WEAK symbol
    """
    local_symbols = list(filter(lambda sym: sym.binding == lief.ELF.SYMBOL_BINDINGS.LOCAL, symbols))
    global_symbols = list(filter(lambda sym: sym.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL, symbols))

    ######################################################
    # 1) resolve local symbols
    sym_indices_by_shndx_and_name = {}
    for idx, sym in enumerate(local_symbols):
        if (sym.shndx, sym.name) not in sym_indices_by_shndx_and_name:
            sym_indices_by_shndx_and_name[(sym.shndx, sym.name)] = []
        sym_indices_by_shndx_and_name[(sym.shndx, sym.name)].append(idx)
    
    sym_indices_with_unique_shndx = []
    for _, indices in sym_indices_by_shndx_and_name.items():
        if len(indices) > 1:
            sym_indices_with_unique_shndx.append(indices[0])
        else:
            sym_indices_with_unique_shndx.extend(indices)

    local_symbols = [local_symbols[idx] for idx in sym_indices_with_unique_shndx]
    local_symbols.sort(key=lambda sym: sym.shndx)

    ######################################################
    # 2) resolve global symbols
    name_counter = Counter([sym.name for sym in global_symbols])
    symbols_conflicted = list(filter(lambda name: name_counter[name] > 1, name_counter.keys()))
    print('Conflicted global symbols:', symbols_conflicted)
    for name in symbols_conflicted:
        symbols_with_same_name = list(filter(lambda sym: sym.name == name, global_symbols))
        assert len(list(filter(lambda sym: sym.type != lief.ELF.SYMBOL_TYPES.NOTYPE, symbols_with_same_name))) == 1, f"There should be only one defined symbol with name {name}"
        symbols_with_same_name.sort(key=lambda sym: int(sym.type))
        for sym in symbols_with_same_name[:-1]:
            global_symbols.remove(sym)
    global_symbols.sort(key=lambda sym: sym.shndx)

    symbols = local_symbols + global_symbols
    check_symbols(symbols)
    return symbols


def merge_sections(sections: List[lief.ELF.Section], section_name: str, alignment: int = None, flags: str = None) -> lief.ELF.Section:
    """
    Merge sections with the same type and name (the first part of relocation stage)
    ---
    Relocate sections' offsets
    Relocate symbols' values and rela_infos' offsets
    """
    if sections:
        section = lief.ELF.Section(section_name, sections[0].type)
        section.alignment = sections[0].alignment
        section.flags = sections[0].flags
    else:
        section = lief.ELF.Section(section_name)
        section.alignment = alignment if alignment else 4
        section.flags = SEG_FLAGS[flags] if flags else SEG_FLAGS['RWX']

    print('merging section {} ...'.format(section_name))

    
    # simply merge contents of same-name sections
    section.size = sum([sec.size for sec in sections])
    section.content = memoryview(b''.join([sec.content.tobytes() for sec in sections]))  # merge content (bytes) of all sections
    
    return section


def relocate_symbols_when_merging_sections(section: List[lief.ELF.Section], sections: List[lief.ELF.Section], symbols: List[lief.ELF.Symbol], shndx: int) -> lief.ELF.Symbol:

    print('relocating symbols when merging section {} ...'.format(section.name))
    # display_sections(sections)

    # merge the same-name sections
    cum_sizes = cumsum([sec.size for sec in sections]).tolist()
    cum_sizes = [0] + cum_sizes[:-1]

    # relocate symbols
    num_syms = len(symbols)
    for offset, sec in zip(cum_sizes, sections):
        for i in range(num_syms):
            sym = symbols[i]
            if sym.section and sym.section == sec:
                new_sym = lief.ELF.Symbol()  # create a new symbol and replace the origin one
                # new_sym.section = section # ! cannot set section attribute
                new_sym.shndx = shndx
                new_sym.value = offset + sym.value
                new_sym.binding, new_sym.name, new_sym.type, new_sym.size = sym.binding, sym.name, sym.type, sym.size
                print('has relocated symbol: {} when merging section {}'.format(new_sym, section.name))
                symbols[i] = new_sym
    print()
    return symbols


def relocate_relocations_when_merging_sections(section: List[lief.ELF.Section], sections: List[lief.ELF.Section], rela_infos: List[lief.ELF.Relocation], symbols: List[lief.ELF.Symbol], shndx: int) -> List[lief.ELF.Relocation]:
    print('relocating relocations when merging section {} ...'.format(section.name))

    cum_sizes = cumsum([sec.size for sec in sections]).tolist()
    cum_sizes = [0] + cum_sizes[:-1]

    # relocate relocation entries
    num_relas = len(rela_infos)
    for offset, sec in zip(cum_sizes, sections):
        for i in range(num_relas):
            rela = rela_infos[i]
            if rela.section and rela.section == sec:
                new_rela = Relocation()
                new_rela.shndx = shndx
                new_rela.offset = offset + rela.offset
                new_rela.symbol = [sym for sym in symbols if sym.name == rela.symbol.name][0]
                new_rela.addend, new_rela.type, new_rela.size = rela.addend, rela.type, rela.size
                print('has relocated rela_info: {} when merging section {}'.format(rela, section.name))
                rela_infos[i] = new_rela
    print()
    return rela_infos


def assemble_into_segments(start_addr: int, **asm_rules: Dict[str, List[lief.ELF.Section]]) -> Tuple[int, List[lief.ELF.Segment]]:
    #     1) reset sec.offset
    #     2) reset sec.virtual_address
    # TODO: set sym.value to its virtual address
    # ! alignment
    phnum = len(asm_rules)
    base_offset = start_addr + EHSIZE + phnum * PHENTSIZE
    base_offset = int(ceil(base_offset / PAGE_SIZE)) * PAGE_SIZE  # pagesize 的整数
    print({'phnum': phnum, 'base_offset - start_addr': base_offset - start_addr})

    segments = [lief.ELF.Segment() for _ in range(phnum)]
    seg_offset = base_offset
    for seg, (flags, sections) in zip(segments, asm_rules.items()):
        print('seg.offset:', seg_offset)
        sec_offset = seg_offset
        for sec in sections: 
            sec.offset, sec.virtual_address = sec_offset, sec_offset
            sec_offset += sec.size

        seg.file_offset, seg.virtual_address, seg.physical_address = seg_offset, seg_offset, seg_offset
        seg.type = lief.ELF.SEGMENT_TYPES.LOAD
        for flag in flags:
            seg.add(SEG_FLAGS[flag])
        print(int(seg.flags))
        seg.alignment = 0x1000
        seg.content = memoryview(b''.join([sec.content.tobytes() for sec in sections]))  # seg.physical_size will be updated automatically
        seg.virtual_size = seg.physical_size
        print('seg.physical_size:', seg.physical_size)
        print()
        seg_offset += seg.virtual_size
        seg_offset = int(ceil(seg_offset / PAGE_SIZE)) * PAGE_SIZE

    return base_offset, segments


def relocate_addresses(sections: List[lief.ELF.Section], symbols: List[lief.ELF.Symbol], rela_infos: List[Relocation]):
    """
    In this step (the second part of relocation stage), 
    the linker modifies references to each symbol in sections to point to the correct runtime address.
    ---
    For different relocation types, address replacement rules are:
        1) R_386_64_32: S + rela.addend (S := sym.addr)
        2) R_386_64_PC32: S + rela.addend - rela.addr
        3) R_386_PLT32: L + rela.addend - rela.addr (S == L for x86-64 platforms)
    """
    for rela in rela_infos:
        # rule('debugging relocating address for <{}>'.format(rela.symbol.name))
        # print(rela)
        sec = sections[rela.shndx]
        rela_addr = sec.virtual_address + rela.offset

        sym = rela.symbol
        assert sym in symbols
        sym_sec = sections[sym.shndx]
        sym_addr = sym_sec.virtual_address + sym.value

        if RELA_TYPES[rela.type] == lief.ELF.RELOCATION_X86_64.R32:
            sec.content = replace_content(sec.content, rela.offset, 4, sym_addr + rela.addend)
        elif RELA_TYPES[rela.type] == lief.ELF.RELOCATION_X86_64.PC32 or RELA_TYPES[rela.type] == lief.ELF.RELOCATION_X86_64.PLT32:
            sec.content = replace_content(sec.content, rela.offset, 4, sym_addr + rela.addend - rela_addr)
        else:
            raise NotImplementedError(f"Relocation type {RELA_TYPES[rela.type]} is not implemented yet")
        # print()



def generate_executable(fname, segments: List[lief.ELF.Segment]):
    # TODO: how to do it?
    if os.path.exists(fname): # TODO: delete this line
        st = os.stat(fname)
        os.chmod(fname, st.st_mode | stat.S_IEXEC)


def build_header(binary: lief.ELF.Binary, *args):
    """Build the header of an executable file"""
    ...

    # print(binary)

    build_file_header(binary, *args)
    build_section_header_table(binary, *args)  # TODO: section header table can be ignored
    build_program_header_table(binary, *args)


def build_file_header(binary: lief.ELF.Binary, *args):
    """Build the file header of an executable file"""
    # TODO: modify other header info
    # - start of program & section headers
    # - entry point
    # - size & number of program headers
    # - number of section headers & sh table index
    
    # binary.header.file_type = lief.ELF.E_TYPE.EXECUTABLE
    pass


def build_program_header_table(binary: lief.ELF.Binary, *args):
    """Build the program header table of an executable file"""
    pass


def build_section_header_table(binary: lief.ELF.Binary, *args):
    """Build the section header table of an executable file"""
    pass


# link_objs_to_exe(['start.o', 'main.o', 'sum.o'], 'main.out')













def link_objs_to_arc(objs: List[str], arc: str) -> None:
    """Link relocatable object files to an archive file"""
    assert all(map(lambda obj: obj.endswith('.o'), objs)), "Not all input files are relocatable object files"
    obj_binaries = []
    for obj in objs:
        if not os.path.exists(obj):
            raise FileNotFoundError(f"{obj} not found")
        if not lief.is_elf(obj):
            raise ValueError(f"{obj} is not an ELF file")
        obj_binaries.append(lief.parse(obj))


def link_objs_arcs_to_exe(objs: List[str], arcs: List[str], exe: str) -> None:
    """Link relocatable object files and archive files to an executable file"""
    # TODO: the archive files can be those generated by GNU or out linker
    assert all(map(lambda obj: obj.endswith('.o'), objs)), "Not all input files are relocatable object files"
    assert all(map(lambda arc: arc.endswith('.a'), arcs)), "Not all input files are archive files"
    obj_binaries = []
    arc_binary_tuples = parse_archives(arcs)
    for obj in objs:
        if not os.path.exists(obj):
            raise FileNotFoundError(f"{obj} not found")
        if not lief.is_elf(obj):
            raise ValueError(f"{obj} is not an ELF file")


def parse_archives(arcs: List[str]) -> List[Tuple[lief.ELF.Binary]]:
    """Parse archive files and return a list of tuples of obj binary instances"""
    pass


def link_objs_to_so(objs: List[str], so: str) -> None:
    """Link relocatable object files to a shared library file"""
    assert all(map(lambda obj: obj.endswith('.o'), objs)), "Not all input files are relocatable object files"
    obj_binaries = []
    for obj in objs:
        if not os.path.exists(obj):
            raise FileNotFoundError(f"{obj} not found")
        if not lief.is_elf(obj):
            raise ValueError(f"{obj} is not an ELF file")
        obj_binaries.append(lief.parse(obj))


"""
Compilers, assemblers, and linkers treat ELF as a set of sections described in the section header table.

The loader treats ELF as a set of segments described by the program header table.

A segment typically contains one or more sections, and a section typically contains one or more symbols.

The section is used for subsequent processing of the linker, and the segment will be reflected in memory.

1) Linkable sections:

    =============================================
    --- ELF Header 
    =============================================
    --- Program Header Table (optional, ignored)
    =============================================
    --- section: .text
    --- section: .data
    --- section: .rodata
    --- section: .bss
    --- section: .symtab
    --- section: .strtab
    --- section: .rel.text
    --- section: .rel.data
    --- section: .rel.rodata
    --- section: .line
    --- section: .debug
    --- ...
    =============================================
    --- Section Header Table
    =============================================

2) Executable segments:

    =============================================
    --- ELF Header
    =============================================
    --- Program Header Table
    =============================================
    --- segment: read-only
    --- segment: read-write
    --- segment: non-loadable and optional info
    --- ...
    =============================================
    --- Section Header Table (optional, ignored)
    =============================================
"""

from typing import List
import lief

from rich.console import Console
from prettytable import PrettyTable

console = Console()



RELA_TYPES = {
    0: lief.ELF.RELOCATION_X86_64.NONE,
    1: lief.ELF.RELOCATION_X86_64.R64,
    2: lief.ELF.RELOCATION_X86_64.PC32,
    3: lief.ELF.RELOCATION_X86_64.GOT32,
    4: lief.ELF.RELOCATION_X86_64.PLT32,
    5: lief.ELF.RELOCATION_X86_64.COPY,
    6: lief.ELF.RELOCATION_X86_64.GLOB_DAT,
    7: lief.ELF.RELOCATION_X86_64.JUMP_SLOT,
    8: lief.ELF.RELOCATION_X86_64.RELATIVE,
    9: lief.ELF.RELOCATION_X86_64.GOTPCREL,
    10: lief.ELF.RELOCATION_X86_64.R32
}

SEG_FLAGS = {
    'R': lief.ELF.SEGMENT_FLAGS.R,  # 4
    'W': lief.ELF.SEGMENT_FLAGS.W,  # 2
    'X': lief.ELF.SEGMENT_FLAGS.X,  # 1
    'RW': lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W,  # 6
    'RX': lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.X,  # 5
    'RWX': lief.ELF.SEGMENT_FLAGS.R | lief.ELF.SEGMENT_FLAGS.W | lief.ELF.SEGMENT_FLAGS.X  # 7
}


def check_symbols(symbols: List[lief.ELF.Symbol]):
    # assert all([sym.shndx > 0 for sym in symbols if sym.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL]), "There still exists undefined global symbols"
    # assert all([sym.type != lief.ELF.SYMBOL_TYPES.NOTYPE for sym in symbols if sym.binding == lief.ELF.SYMBOL_BINDINGS.GLOBAL]), "There still exists undefined global symbols"
    ...


def display_segments(segments: List[lief.ELF.Segment]):     
    table = PrettyTable()
    table.field_names = ['Num', 'Type', 'Offset', 'VirtAddr', 'PhysAddr', 'MemSiz', 'FileSiz', 'Align']
    table.align['Num'] = 'r'
    table.align['Type'] = 'l'
    table.align['Offset'] = 'r'
    table.align['VirtAddr'] = 'r'
    table.align['PhysAddr'] = 'r'
    table.align['MemSiz'] = 'r'
    table.align['FileSiz'] = 'r'
    table.align['Align'] = 'r'
    for n, seg in enumerate(segments):
        table.add_row([str(n), str(seg.type), str(seg.file_offset), str(seg.virtual_address), str(seg.physical_address), str(seg.virtual_size), str(seg.physical_size), str(seg.alignment)])
    console.print(table)

def display_symbols(symbols: List[lief.ELF.Symbol]):
    # print('{:>3s} {:10s} {:25s} {:25s} {:>5s} {:>10s} {:>10s}'.format('Num', 'Name', 'Type', 'Bind', 'Value', 'Size', 'Ndx'))
    # print('------------------------------------------------------------------------------------------------')
    # for n, sym in enumerate(symbols):
    #         print('{:3} {:10} {:25} {:25} {:5} {:10} {:10}'.format(n, sym.name, str(sym.type), str(sym.binding), sym.value, sym.size, sym.shndx))
    table = PrettyTable()
    table.field_names = ['Num', 'Name', 'Type', 'Bind', 'Value', 'Size', 'Ndx']
    table.align['Num'] = 'r'
    table.align['Name'] = 'l'
    table.align['Type'] = 'l'
    table.align['Bind'] = 'l'
    table.align['Value'] = 'r'
    table.align['Size'] = 'r'
    table.align['Ndx'] = 'r'
    for n, sym in enumerate(symbols):
        table.add_row([str(n), sym.name, str(sym.type), str(sym.binding), str(sym.value), str(sym.size), str(sym.shndx)])
    console.print(table)

def display_sections(sections: List[lief.ELF.Section]):
    # print('{:>3s} {:20s} {:25s} {:>10s} {:>10s} {:>10s} {:>10s} {:>10s}'.format('Num', 'Name', 'Type', 'Offset', 'Size', 'VirtAddr', 'Align', 'EntSize'))
    # print('-----------------------------------------------------------------------------------------------------------')
    # for n, sec in enumerate(sections):
        # print('{:3} {:20} {:25} {:10} {:10} {:10} {:10} {:10}'.format(n, sec.name, str(sec.type), sec.file_offset, sec.size, sec.virtual_address, sec.alignment, sec.entry_size))
    table = PrettyTable()
    table.field_names = ['Num', 'Name', 'Type', 'Offset', 'Size', 'VirtAddr', 'Align', 'EntSize']
    table.align['Num'] = 'r'
    table.align['Name'] = 'l'
    table.align['Type'] = 'l'
    table.align['Offset'] = 'r'
    table.align['Size'] = 'r'
    table.align['VirtAddr'] = 'r'
    table.align['Align'] = 'r'
    table.align['EntSize'] = 'r'
    for n, sec in enumerate(sections):
        table.add_row([str(n), sec.name, str(sec.type), str(sec.file_offset), str(sec.size), str(sec.virtual_address), str(sec.alignment), str(sec.entry_size)])
    console.print(table)

def display_relocations(relocations: List[lief.ELF.Relocation]):
    # print('{:>3s} {:<20s} {:<15s} {:<25s} {:>10s} {:>10s} {:>6s}'.format('Num', 'Symbol', 'Section', 'Type', 'Offset', 'Addend', 'Size'))
    # print('-------------------------------------------------------------------------------------------------')
    # for n, rela in enumerate(relocations):
        # print('{:3} {:20} {:15} {:25} {:10} {:10} {:6}'.format(n, rela.symbol.name if rela.symbol else 'None', rela.section.name if rela.section else 'None', str(RELA_TYPES[rela.type]), rela.address, rela.addend, rela.size))
    table = PrettyTable()
    table.field_names = ['Num', 'Symbol', 'Section', 'Type', 'Offset', 'Addend', 'Size']
    table.align['Num'] = 'r'
    table.align['Symbol'] = 'l'
    table.align['Section'] = 'l'
    table.align['Type'] = 'l'
    table.align['Offset'] = 'r'
    table.align['Addend'] = 'r'
    table.align['Size'] = 'r'
    for n, rela in enumerate(relocations):
        table.add_row([str(n), rela.symbol.name if rela.symbol else 'None', rela.section.name if rela.section else 'None', str(RELA_TYPES[rela.type]), str(rela.address), str(rela.addend), str(rela.size)])
    console.print(table)

def replace_content(content: memoryview, start: int, length: int, subcontent: int) -> memoryview:
    """
    :param content: the original content
    :param start: the start position of the subcontent (in bytes)
    :param length: the length of the subcontent to be replaced (in bytes)
    :param subcontent: the new subcontent in type of int
    """
    content_bytes = content.tobytes()
    subcontent_hex = hex(subcontent & int('0x{}'.format(''.join(['f'] * length * 2)), 16))[2:].zfill(length * 2)
    # Intel x86-64 is little-endian bytes order: e.g. -24 --> 0xffffffe8 --> 0xe8ffffff
    subcontent_bytes = bytes.fromhex(subcontent_hex)[::-1]
    content_bytes = content_bytes[:start] + subcontent_bytes + content_bytes[(start+length):]
    # console.rule('debugging replace_content')
    # console.print(subcontent, subcontent_hex, bytes.fromhex(subcontent_hex), '|', subcontent_bytes)
    return memoryview(content_bytes)

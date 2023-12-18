"""Data structures about ELF files"""
import lief
from .utils import RELA_TYPES


class Relocation:
    def __init__(self, shndx=0, symbol=None, type=0, offset=0, addend=0, size=0, section=None) -> None:
        self.shndx = shndx
        self.symbol = symbol
        self.type = type
        self.offset = offset
        self.address = offset  # to be compatible with lief.ELF.Relocation
        self.addend = addend
        self.size = size
        self.section = section

    def __repr__(self):
        return 'Relocation(shndx={}, symbol={}, type={}, offset={}, addend={}, size={})'.format(
            self.shndx, self.symbol.name if self.symbol else 'None', RELA_TYPES[self.type], self.offset, self.addend, self.size
        )
    
    @classmethod
    def from_lief(cls, rela: lief.ELF.Relocation):
        new_rela = cls()
        new_rela.offset = rela.address
        new_rela.section, new_rela.symbol = rela.section, rela.symbol
        new_rela.addend, new_rela.type, new_rela.size = rela.addend, rela.type, rela.size
        return new_rela

# -----------------------------------------------------
# File Formats
# -----------------------------------------------------
# - PE and ELF are supported
# We extract the following information from the 
# executables formats:
# - path
# - entrypoint
# - arch
# - relocations
# - sections
#   - name
#   - address (offset from the start of the file)
#   - size
# - symbols
#   - name
#   - address
#
# important note here: this functions work with the 
# addresses as an offsets from the start of the binary
# file as it is in the filesystem!
# -----------------------------------------------------
# ELF
# -----------------------------------------------------
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection
from elftools.elf.elffile import ELFFile

import sys
import os
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from disasm import *

def __find_section(elf, name, exactly=True):
    results = []
    for section in elf['sections']:
        if exactly:
            if section['name'] != name: continue
        else:
            if name not in section['name']: continue
        results.append(section)
    return results

def __find_relocation_by_address(elf, address):
    for relocation in elf['relocations']:
        if relocation['address'] == address:
            return relocation
    return None

def elf_init(path):
    elf_details = {}
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)

            elf_details['path'] = path
            elf_details["entrypoint"] = elf.header.e_entry
            elf_details["arch"] = elf.header.e_machine

            # extracting the sections
            elf_details["sections"] = []
            for section in elf.iter_sections():
                elf_details["sections"].append({
                    'name':section.name, 
                    # this is the offset from the begining of the 
                    # file in the filesystem!
                    'address': section['sh_addr'], 
                    'size': section.data_size,
                })

            # extracting the symbols
            elf_details["symbols"] = []
            for section in elf.iter_sections():
                if not isinstance(section, SymbolTableSection): continue

                for symbol in section.iter_symbols():
                    if symbol.name == "": continue
                    symbol_address = symbol.entry['st_value']

                    elf_details["symbols"].append({
                        'address': symbol_address,
                        'name': symbol.name
                    })

            elf_details["relocations"] = []
            for section in elf.iter_sections():
                # only relocations are interesting for this one.
                if not isinstance(section, RelocationSection):
                    continue
                
                symbols_section = elf.get_section(section["sh_link"])
                for relocation in section.iter_relocations():
                    symbol = symbols_section.get_symbol(relocation["r_info_sym"])
                    address = relocation['r_offset']

                    # ignore symbols with no name for now...
                    if symbol.name == "": continue

                    elf_details["relocations"].append({
                        'address': address,
                        'name': symbol.name
                    })

    except Exception as e:
        return None

    create_plt_symbols(elf_details)
    return elf_details
# -----------------------------------------------------

def _print_instruction(instruction, level=0):
    # print("\t"*level + "0x{:x}: {}\t{} {}".format(  instruction['address'], 
                                                    # instruction['bytes'].hex(),
                                                    # instruction['mnemonic'], 
                                                    # instruction['op_str']))
    addr = instruction['address']
    _bytes = instruction['bytes']
    mnemonic = instruction['mnemonic']
    op = instruction['op_str']

    comment = ""
    if instruction['ref']: 
        ref = f"{hex(instruction['ref'])}"
        comment = f"; {ref}"

    level = '\t'*level
    print(f"{level}{hex(addr)}: {mnemonic} {op} {comment}")

# -----------------------------------------------------
# NOTE
# the .got table is where the linker is going to replace the content with the
# imported and needed functions (and structures) from external sources. the plt
# on the other hand is stay exatcly where it is and just point to the got
# entries. This technique is used to make it easier and feasible for the linker
# to replace all function calls in one place instead of all the places a
# function is called from. 
# With that out of the way, it is mandatory that we will be able to translate
# calls to the plt table to the corresponding got entry. the got entries have
# symbols attached to them in the symbols section of the elf, or in the case of
# a functions pointers, the symbols are located in the relocations sections.
# The relocations are the elf's way to tell the linker where to put the
# functions in the got sections.
# The plt entries (which are essentially jump tables) have no symbols. 
# this is what we are fixing here. it is very helpful (mandatory even) to be
# able to translate a jump to the plt - to the corresponding got symbol
# instantaneously.
# The translation is simple, we go to all plt sections in the elf, going
# through all instructions there (it is code the jumps after all) and get the
# addresses used to jump into the got section. now that we have the
# corresponding got address, we can simply search the relevant symbol in the
# relocations.
# -----------------------------------------------------
def create_plt_symbols(elf):
    # search in all plt sections
    for plt in __find_section(elf, '.plt', exactly=False):
        start = plt['address']
        end = start + plt['size']
        size_of_entry = 16

        for i in range(start, end, size_of_entry):
            for ins in file_get_instructions(   elf,
                                                start=i,
                                                end=i+size_of_entry):
                if not ins['ref']: continue

                relocation = __find_relocation_by_address(elf, ins['ref'])
                if not relocation: continue

                name = f"{relocation['name']}@plt"
                elf['symbols'].append({ 'name': name, 'address': i})

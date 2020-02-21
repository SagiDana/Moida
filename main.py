# -----------------------------------------------------
# General functions to do common tasks.
# -----------------------------------------------------

def read_bytes_from_file(file_path, offset, size):
    try:
        ret = None
        with open(file_path, 'rb') as f:
            f.seek(offset)
            ret = f.read(size)
    except Exception as e:
        print("Exception: {}".format(e))
        return None

    return ret

def print_instructions(instructions):
    for i in instructions:
        print("{}: {} {}".format(i['address'], i['mnemonic'], i['op_str']))

# -----------------------------------------------------

# -----------------------------------------------------
# File Formats
# -----------------------------------------------------
# - PE and ELF are supported
# We extract the following information from the 
# executables formats:
# - entrypoint
# - architecture
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


def elf_extract_details(path):
    elf_details = {}
    try:
        with open(path, 'rb') as f:
            elf = ELFFile(f)

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

                # only relocations are interesting for this one.
                if not isinstance(section, RelocationSection):
                    continue
                
                symbols_section = elf.get_section(section["sh_link"])
                for relocation in section.iter_relocations():
                    symbol = symbols_section.get_symbol(relocation["r_info_sym"])
                    symbol_address = relocation['r_offset']
                    symbol_address = symbol_address

                    # ignore symbols with no name for now...
                    if symbol.name == "":
                        continue

                    elf_details["symbols"].append({
                        'address': symbol_address,
                        'name': symbol.name
                    })

    except Exception as e:
        return None

    return elf_details
# -----------------------------------------------------



# -----------------------------------------------------
# PE
# -----------------------------------------------------
from pefile import PE

def pe_extract_details(path):
    pe_details = {}

    try:
        pe = PE(path)

        pe_details["entrypoint"] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if pe.OPTIONAL_HEADER.Magic == 0x20b:
            pe_details["arch"] = "X86_64"
        else:
            pe_details["arch"] = "X86"

        # extracing sections.
        pe_details["sections"] = []
        for section in pe.sections:
            pe_details["sections"].append({
                'name': section.Name.decode('utf-8').rstrip('\0'),
                'address': section.PointerToRawData,
                'size': section.SizeOfRawData
            })

        # extracting symbols
        pe_details["symbols"] = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            # might be needed in the future..
            # dll_name = entry.dll.decode('utf-8').rstrip('\0')
            
            for func in entry.imports:
                # ignore empty imports..
                if not func.name:
                    continue
                symbol_name = func.name.decode('utf-8').rstrip('\0')
                # is this the right address (as in the offset in the file?)
                symbol_address = pe.OPTIONAL_HEADER.ImageBase + func.address
 
                pe_details["symbols"].append({
                    'address': symbol_address,
                    'name': symbol_name
                })

    except Exception as e:
        print("Exception: {}".format(e))
        return None

    return pe_details

# -----------------------------------------------------



# -----------------------------------------------------
# Language Analyzers
# -----------------------------------------------------
# - X86_64 assembly language only for now.
# -----------------------------------------------------
from base64 import b64encode
from capstone import *

def x86_64_disassemble(code_as_bytes, start_address):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # Auto-skip errors in assembly
    md.skipdata = True

    try:
        instructions = []
        for i in md.disasm(code_as_bytes, start_address, 0):
            instructions.append({
                    'address': '0x{:x}'.format(i.address),
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str,
                    'bytes': str(b64encode(i.bytes)),
                    'size': i.size
                    })
        return instructions
    except Exception as e:
        print("Exception: {}".format(e))
        return None


# -----------------------------------------------------

def main():
    file_path = "files/js60"

    elf_details = elf_extract_details(file_path)
    # print(elf_details)

    # pe_details = pe_extract_details("files/disk2vhd.exe")
    # print(pe_details)

    
    # code_section = [s for s in elf_details["sections"] if s["name"] == ".text"][0]
    # code_address = code_section["address"]
    # code_size = code_section["size"]

    code_address = elf_details["entrypoint"]
    code_size = 1000

    code = read_bytes_from_file(file_path, code_address, code_size)

    instructions = x86_64_disassemble(code, code_address)

    print_instructions(instructions)



if __name__ == '__main__':
    main()

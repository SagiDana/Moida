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
                    'address': '0x{:x}'.format(section['sh_addr']), 
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
                    symbol_address = "0x{:x}".format(symbol_address)

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
                'address': '0x{:x}'.format(section.PointerToRawData),
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

# -----------------------------------------------------

def main():
    # elf_details = elf_extract_details("files/ls")
    elf_details = elf_extract_details("files/js60")
    print(elf_details)

    # pe_details = pe_extract_details("files/disk2vhd.exe")
    # print(pe_details)



if __name__ == '__main__':
    main()

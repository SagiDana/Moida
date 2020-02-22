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

def get_section_by_name(sections, name):
    for section in sections:
        if name in section["name"]:
            return section
    return None

def get_section_data(file_path, section):
    return read_bytes_from_file(file_path, section["address"], section["size"])

# -----------------------------------------------------
# some cross file functions, like cross references
# and searches that require scanning the entire file.
# these functions needs to be implemented in a way that
# is scalable and optimized to large files.
# -----------------------------------------------------
# file_get_bytes retreiving n bytes at a time.
def file_get_bytes( file_path, 
                    start_address=0, 
                    end_address=-1, 
                    at_a_time=8, 
                    buffering=1024):

    if buffering % at_a_time != 0: 
        return None

    try:
        f = open(file_path, 'rb')

        # starting at the start address
        f.seek(start_address)

        while True:
            prev_position = f.tell()

            data = f.read(buffering)

            # reached the end.
            if not data: break
            
            curr_position = f.tell()

            if end_address != -1:
                if curr_position > end_address:
                    curr_position = end_address

            num_of_bytes_to_send = curr_position - prev_position

            data = data[:num_of_bytes_to_send]
            
            if len(data) % at_a_time != 0:
                num_of_iterations = int((len(data) / at_a_time)) + 1
            else:
                num_of_iterations = int((len(data) / at_a_time))

            # do somthing
            for i in range(num_of_iterations):
                if ((i*at_a_time) + at_a_time) > len(data):
                    yield data[(i*at_a_time):len(data)]
                else:
                    yield data[(i*at_a_time):(i*at_a_time)+at_a_time]

            if end_address != -1:
                if curr_position >= end_address:
                    break

    except Exception as e:
        print("Exception: {}".format(e))


# -----------------------------------------------------
# Printers
# -----------------------------------------------------

# hexdump is always usefull :)
from hexdump import hexdump

def print_sections(sections):
    print("----------------------------------------")
    for section in sections:
        print("Name: {}".format(section["name"]))
        print("Address: {}".format(section["address"]))
        print("Size: {}".format(section["size"]))
        print("----------------------------------------")

def print_instruction(instruction):
    print("0x{:x}: {} {}".format(   instruction['address'], 
                                    instruction['mnemonic'], 
                                    instruction['op_str']))

def print_instructions(instructions):
    for i in instructions:
        print_instruction(i)

def print_symbols(symbols):
    for symbol in symbols:
        print("{}:\t 0x{:x}".format(symbol["name"], symbol["address"]))

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
                    'address': i.address,
                    'mnemonic': i.mnemonic,
                    'op_str': i.op_str,
                    'bytes': str(b64encode(i.bytes)),
                    'size': i.size
                    })
        return instructions
    except Exception as e:
        print("Exception: {}".format(e))
        return None


# file_get_instructions retrieving 1 instructions at a time
def x86_64_file_get_instructions(   file_path, 
                                    start_address=0, 
                                    num_of_instructions=-1, 
                                    end_address=-1, 
                                    buffering=1024):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # Auto-skip errors in assembly
    md.skipdata = True

    current_address = start_address
    num_of_passed_instructions = 0
    is_finished = False
    try:
        at_a_time = 64
        size_left = 0
        data_from_last_iteration = None
        for code_as_bytes in file_get_bytes(file_path, 
                                            start_address=start_address,
                                            end_address=end_address,
                                            at_a_time=at_a_time,
                                            buffering=buffering):

            size_left += at_a_time
            size_of_curr_buff = size_left

            if data_from_last_iteration and len(data_from_last_iteration) > 0:
                code_as_bytes = data_from_last_iteration + code_as_bytes

            for i in md.disasm(code_as_bytes, current_address, 0):
                # only return the instruction in case the size of it
                # did not reached the end of the buffer (make sure
                # buffer didnt cut the instruction)
                if size_left != i.size:
                    instruction = { 'address': i.address,
                                    'mnemonic': i.mnemonic,
                                    'op_str': i.op_str,
                                    'bytes': str(b64encode(i.bytes)),
                                    'size': i.size}
                    yield instruction

                    num_of_passed_instructions += 1
                    if num_of_instructions != -1:
                        if num_of_passed_instructions == num_of_instructions:
                            is_finished = True
                            break

                    current_address += i.size

                    # increase the address
                    size_left -= i.size
                else:
                    data_from_last_iteration = code_as_bytes[size_of_curr_buff - size_left:]

            if is_finished: break

    except Exception as e:
        print("Exception: {}".format(e))
        return None

# -----------------------------------------------------

def main():
    # elf
    # file_path = "files/js60"
    file_path = "files/ls"
    file_details = elf_extract_details(file_path)

    # pe
    # file_path = "files/disk2vhd.exe"
    # file_details = pe_extract_details(file_path)

    # print(file_details)

    code_section = [s for s in file_details["sections"] if s["name"] == ".text"][0]
    code_address = code_section["address"]
    code_size = code_section["size"]

    # code_address = file_details["entrypoint"]
    # code_size = 1000

    # code = read_bytes_from_file(file_path, code_address, code_size)

    # instructions = x86_64_disassemble(code, code_address)
    # print_instructions(instructions)
    
    # file_symbols = file_details["symbols"]
    # print_symbols(file_symbols)

    # print_sections(file_details["sections"])
    
    # section = get_section_by_name(file_details["sections"], "data")
    # data = get_section_data(file_path, section)
    # hexdump(data)

    # for data in file_get_bytes(file_path, 
                                # start_address=0, 
                                # end_address=-1, 
                                # at_a_time=1,
                                # buffering=1024):
        # print("data: {}".format(data))


    # for instruction in x86_64_file_get_instructions(    file_path, 
                                                        # num_of_instructions=50,
                                                        # start_address=code_address,
                                                        # end_address=-1,
                                                        # buffering=1024):
        # print_instruction(instruction)

if __name__ == '__main__':
    main()

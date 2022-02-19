#!/usr/bin/python3
# -----------------------------------------------------
# Printers
# -----------------------------------------------------

# hexdump is always usefull :)
from hexdump import hexdump

def print_sections(binary):
    print("----------------------------------------")
    for section in binary['sections']:
        print("Name: {}".format(section["name"]))
        print("Address: {}".format(hex(section["address"])))
        print("Size: {}".format(section["size"]))
        print("----------------------------------------")

def print_symbols(binary):
    for symbol in binary['symbols']:
        print("{}:\t 0x{:x}".format(symbol["name"], symbol["address"]))

def print_relocations(binary):
    for reloc in binary['relocations']:
        print("{}:\t 0x{:x}".format(reloc["name"], reloc["address"]))

def print_instruction(instruction, level=0):
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

def print_instructions(instructions):
    for i in instructions:
        print_instruction(i)

# -----------------------------------------------------

from disasm import *
from binary import *
from common import *


from vimapp import Vimapp
import vimable
import json

commands = {}
completer = {}
binary = None
settings = {}
settings["file_path"] = "/home/s/github/Promody/tracee/tracee"
settings["base_addr"] = None

def print_sections_handler(vapp, commands):
    global binary
    print_sections(binary)
    return True

def print_symbols_handler(vapp, commands):
    global binary
    print_symbols(binary)
    return True

def set_file_path_handler(vapp, commands):
    global settings, binary

    settings["file_path"] = commands[2]
    binary = binary_init(settings["file_path"])

    return True

def set_base_addr_handler(vapp, commands):
    global settings

    settings["base_addr"] = int(commands[2], base=16)

    return True

def get_settings_handler(vapp, commands):
    global settings

    print(f"{json.dumps(settings, indent=4)}")

    return True

def disassemble_function_handler(vapp, commands):
    global completer
    # completer['disassemble']['function'] = {}
    # completer['disassemble']['function']['a'] = None
    # completer['disassemble']['function']['b'] = None

    return True

def translate_address(addr):
    global settings
    if not settings['base_addr']: return None
    return addr + settings['base_addr']

def init():
    global settings, binary
    binary = binary_init(settings['file_path'])

def exports():
    global settings, binary

    # export variables
    vimable.export("settings", settings)
    vimable.export("binary", binary)

    # # export functions
    vimable.export("init", init)

    vimable.export("hexdump", hexdump)
    vimable.export("print_symbols", print_symbols)
    vimable.export("print_relocations", print_relocations)
    vimable.export("print_sections", print_sections)
    vimable.export("print_instruction", print_instruction)
    vimable.export("print_instructions", print_instructions)

    vimable.export("get_cross_refs", get_cross_refs)
    vimable.export("file_get_instructions", file_get_instructions)
    vimable.export("file_get_bytes", file_get_bytes)


def main():
    global settings, binary, commands, completer

    try:
        vimable.start("moi")

        init()
        exports()

        completer['disassemble'] = {}
        completer['disassemble']['function'] = None

        commands["print"] = {}
        commands["print"]["sections"] = print_sections_handler
        commands["print"]["symbols"] = print_symbols_handler
        
        commands["set"] = {}
        commands["set"]["file_path"] = set_file_path_handler
        commands["set"]["base_addr"] = set_base_addr_handler

        commands["get"] = {}
        commands["get"]["settings"] = get_settings_handler

        commands["disassemble"] = {}
        commands["disassemble"]["function"] = disassemble_function_handler

        vapp = Vimapp("moi", commands, completer)
        vapp.run()

    finally:
        vimable.stop()
    
    # # binary
    # # file_path = "files/ls"
    # file_details = binary_extract_details(file_path)

    # pe
    # file_path = "files/disk2vhd.exe"
    # file_details = pe_extract_details(file_path)

    # print(file_details)

    # code_section = [s for s in file_details["sections"] if s["name"] == ".text"][0]
    # code_address = code_section["address"]
    # code_size = code_section["size"]


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

    # x86_64_analyze_function(file_path, file_details["entrypoint"])

    # for instruction in x86_64_file_get_instructions(    file_path, 
                                                        # num_of_instructions=-1,
                                                        # start_address=code_address,
                                                        # end_address=code_address + code_size,
                                                        # buffering=1024):
        # print_instruction(instruction)

if __name__ == '__main__':
    main()


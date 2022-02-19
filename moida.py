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
    global binary_map

    addr = instruction['address']
    _bytes = instruction['bytes']
    mnemonic = instruction['mnemonic']
    op = instruction['op_str']
    level = '\t'*level

    if not instruction['ref']: 
        print(f"{level}{hex(addr)}: {mnemonic} {op}")
        return

    ref = instruction['ref']
    if ref not in binary_map:
        print(f"{level}{hex(addr)}: {mnemonic} {op} ; {hex(ref)}")
        return 

    print(f"{level}{hex(addr)}: {mnemonic} {op} ; {binary_map[ref]}")

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

binary_map = {}
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

def init():
    global settings, binary, binary_map
    binary = binary_init(settings['file_path'])

    for symbol in binary['symbols']:
        binary_map[symbol['address']] = symbol['name']


def exports():
    global settings, binary

    # export variables
    vimable.export("settings", settings)
    vimable.export("binary", binary)

    # # export functions
    vimable.export("init", init)

    # prints
    vimable.export("hexdump", hexdump)
    vimable.export("print_symbols", print_symbols)
    vimable.export("print_relocations", print_relocations)
    vimable.export("print_sections", print_sections)
    vimable.export("print_instruction", print_instruction)
    vimable.export("print_instructions", print_instructions)

    # binary
    vimable.export("find_section", find_section)
    vimable.export("get_section_data", get_section_data)
    vimable.export("find_symbol_by_address", find_symbol_by_address)
    vimable.export("find_relocation_by_address", find_relocation_by_address)

    # disasm
    vimable.export("get_cross_refs", get_cross_refs)
    vimable.export("file_get_instructions", file_get_instructions)

    # common
    vimable.export("file_get_bytes", file_get_bytes)
    vimable.export("file_strings", file_strings)
    vimable.export("file_hexdump", file_hexdump)

def main():
    global settings, binary, commands, completer

    try:
        vimable.start("moida")

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

        vapp = Vimapp("moida", commands, completer)
        vapp.run()

    finally:
        vimable.stop()

if __name__ == '__main__':
    main()


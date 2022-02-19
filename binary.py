from format.elf import *


def get_section_data(file_path, section):
    return file_get_bytes(file_path, section["address"], section["size"])

def find_section(binary, name, exactly=True):
    results = []
    for section in binary['sections']:
        if exactly:
            if section['name'] != name: continue
        else:
            if name not in section['name']: continue
        results.append(section)
    return results

def find_symbol_by_address(binary, address):
    for symbol in binary['symbols']:
        if symbol['address'] == address:
            return symbol
    return None

def find_relocation_by_address(binary, address):
    for relocation in binary['relocations']:
        if relocation['address'] == address:
            return relocation
    return None

def binary_init(path):
    return elf_init(path)

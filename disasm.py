from arch.x86_64 import *

# Instruction structure
# { 
        # 'address': <int>,
        # 'mnemonic': <str>,
        # 'op_str': <str>,
        # 'bytes': <bytes>,
        # 'size': <int>,
        # 'ref': <int>,
# }
def file_get_instructions(  file_path,
                            start_address=0,
                            num_of_instructions=-1,
                            end_address=-1,
                            buffering=1024):

    return x86_64_file_get_instructions(    file_path,
                                            start_address,
                                            num_of_instructions,
                                            end_address,
                                            buffering)

def get_cross_refs(elf, address):
    refs = []
    for i in file_get_instructions(elf['path']):
        if i['ref'] != address: continue
        refs.append(i['address'])
        
    return refs

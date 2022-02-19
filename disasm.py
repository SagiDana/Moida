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
def file_get_instructions(  binary,
                            start=0,
                            num_ins=-1,
                            end=-1,
                            buffering=1024):

    return x86_64_file_get_instructions(    binary['path'],
                                            start,
                                            num_ins,
                                            end,
                                            buffering)

def get_cross_refs(binary, address):
    refs = []
    for i in file_get_instructions(binary):
        if i['ref'] != address: continue
        refs.append(i['address'])
        
    return refs

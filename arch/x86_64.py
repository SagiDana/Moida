from capstone import *
import re

import sys
import os
sys.path.insert(1, os.path.join(sys.path[0], '..'))

from common import file_get_bytes
from common import _file_get_bytes

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
        at_a_time = 64 # buffering must be a multiplication of that.
        data_from_last_iteration = None
        for code_as_bytes in _file_get_bytes(file_path, 
                                            start_address=start_address,
                                            end_address=end_address,
                                            at_a_time=at_a_time,
                                            buffering=buffering):
            if data_from_last_iteration:
                code_as_bytes = data_from_last_iteration + code_as_bytes
                data_from_last_iteration = None

            size_left = len(code_as_bytes)

            for i in md.disasm(code_as_bytes, current_address, 0):
                # only return the instruction in case the size of it
                # did not reached the end of the buffer (make sure
                # buffer didnt cut the instruction)
                if size_left <= 15: # x86_64 instruction max length
                    data_from_last_iteration = code_as_bytes[-size_left:]
                    break

                instruction = { 'address': i.address,
                                'mnemonic': i.mnemonic,
                                'op_str': i.op_str,
                                'bytes': i.bytes,
                                'size': i.size,
                                'ref': None }
                instruction['ref'] = x86_64_instruction_get_ref(instruction)
                yield instruction

                num_of_passed_instructions += 1
                if num_of_instructions != -1:
                    if num_of_passed_instructions == num_of_instructions:
                        is_finished = True
                        break

                # increase the address
                current_address += i.size
                size_left -= i.size

            if is_finished: break

    except Exception as e:
        print("Exception: {}".format(e))
        return None

def x86_64_instruction_get_ref(instruction):
    address = instruction['address']
    mnemonic = instruction['mnemonic']
    op_str = instruction['op_str']
    size = instruction['size']
    ref_address = None

    # if instruction ref relative to to current
    if re.match(r'.*rip \+ 0x[0-9A-Fa-f]+.*', op_str):
        ref_address = re.findall(r'0x[0-9A-F]+', op_str, re.I)[0]
        ref_address = int(ref_address, 0)
        rip = address + size
        ref_address = rip + ref_address
    elif re.match(r'.*rip \- 0x[0-9A-Fa-f]+.*', op_str):
        ref_address = re.findall(r'0x[0-9A-F]+', op_str, re.I)[0]
        ref_address = int(ref_address, 0)
        rip = address + size
        ref_address = rip - ref_address
    # if instruction absolute
    elif re.match(r'0x[0-9A-Fa-f]+', op_str):
        ref_address = re.findall(r'0x[0-9A-F]+', op_str, re.I)[0]
        ref_address = int(ref_address, 0)
    return ref_address

















# def x86_64_analyze_function(file_path, start_address, level=0):
    # num_of_instructions = 0
    # num_of_nops = 0
    # num_of_wierd_nops = 0
    # is_ret = False
    # current_address = start_address

    # print(("\t"*level)+("-"*10))
    # for instruction in x86_64_file_get_instructions(    file_path, 
                                                        # num_of_instructions=-1,
                                                        # start_address=start_address,
                                                        # end_address=-1,
                                                        # buffering=1024):

        # print_instruction(instruction, level)
        # ref_address = x86_64_instruction_get_ref(instruction)
        # # if ref_address:
            # # x86_64_analyze_function(file_path, ref_address, level+1)

        # address = instruction['address']
        # mnemonic = instruction['mnemonic']
        # op_str = instruction['op_str']
                
        # if mnemonic == 'nop': num_of_nops += 1
        # if mnemonic == 'nop' and op_str != '': num_of_wierd_nops += 1


        # num_of_instructions += 1
        # current_address += instruction["size"]
        # if mnemonic == 'ret': 
            # is_ret = True
            # break        

        # if num_of_instructions > 100:
            # break


    # print(("\t"*level)+("-"*10))

# def x86_64_disassemble(code_as_bytes, start_address):
    # md = Cs(CS_ARCH_X86, CS_MODE_64)
    
    # # Auto-skip errors in assembly
    # md.skipdata = True

    # try:
        # instructions = []
        # for i in md.disasm(code_as_bytes, start_address, 0):
            # instructions.append({
                    # 'address': i.address,
                    # 'mnemonic': i.mnemonic,
                    # 'op_str': i.op_str,
                    # 'bytes': str(b64encode(i.bytes)),
                    # 'size': i.size
                    # })
        # return instructions
    # except Exception as e:
        # print("Exception: {}".format(e))
        # return None


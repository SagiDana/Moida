# -----------------------------------------------------
# PE
# -----------------------------------------------------
from pefile import PE

def pe_init(path):
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

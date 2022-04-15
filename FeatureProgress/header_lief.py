from datetime import datetime
from collections import defaultdict
import lief

import logging

logging.basicConfig(level=logging.INFO, format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fromTimestampToDate(timestamp):
        """
            Conversion of timestamp into printable date
            :param (int) timestamp : Timestamp to be converted
            :return (str) : Formatted date : Jan 01 2019 at 00:00:00
        """
        if not timestamp:
            return None
        return datetime.utcfromtimestamp(timestamp).strftime("%b %d %Y at %H:%M:%S")


def header(binary, type_of_file):
        """
            Display header of ELF, PE, Mach-O
        """    
        feature_set = defaultdict(list)
        if type_of_file == 'machofile':
            flags = []
            
            if binary.has_entrypoint:
                entrypoint = binary.entrypoint
                feature_set['entrypoint'] = entrypoint
            
            
            feature_set['Platform'] = type_of_file
            feature_set['CPU type'] =  str(binary.header.cpu_type)
            feature_set['File type'] =  str(binary.header.file_type)
            feature_set['Number of commands'] =  binary.header.nb_cmds
            feature_set['Size of commands'] =  binary.header.sizeof_cmds
            
            feature_set['Flags'] = ':'.join(str(flag) for flag in binary.header.flags_list)    
        
        elif type_of_file == 'EXEfile' or type_of_file == 'DLLfile':
            

            feature_set['Platform'] = type_of_file
            feature_set['Magic'] = binary.header.signature
            feature_set['CPU type'] = str(binary.header.machine)
            feature_set["Number of sections"] = binary.header.numberof_sections
            feature_set['Number of symbols'] = binary.header.numberof_symbols
            feature_set["Pointer to symbol table"] = hex(binary.header.pointerto_symbol_table)
            feature_set["Date of compilation"] = fromTimestampToDate(binary.header.time_date_stamps)
            feature_set["Size of optional header"] = binary.header.sizeof_optional_header
            feature_set['Entrypoint'] = binary.entrypoint
            feature_set['Imphash'] = lief.PE.get_imphash(binary)
            
            feature_set["Optional header"] = {}
            if binary.header.sizeof_optional_header > 0:
                #print("success", "Optional header : ")
                feature_set["Optional header"]["Entrypoint"] = hex(binary.optional_header.addressof_entrypoint)
                feature_set["Optional header"]["Base of code"] = hex(binary.optional_header.baseof_code)
                feature_set["Optional header"]["Checksum"] = hex(binary.optional_header.checksum)
                feature_set["Optional header"]["Base of image"] = hex(binary.optional_header.imagebase)
                feature_set["Optional header"]["Magic"] = str(binary.optional_header.magic)
                feature_set["Optional header"]["Subsystem"] = str(binary.optional_header.subsystem)
                feature_set["Optional header"]["Min OS version"] = binary.optional_header.minor_operating_system_version
                feature_set["Optional header"]["Max OS version"] = binary.optional_header.major_operating_system_version
                feature_set["Optional header"]["Min Linker version"] = binary.optional_header.minor_linker_version
                feature_set["Optional header"]["Max Linker version"] = binary.optional_header.major_linker_version
                feature_set["Optional header"]["Min Image version"] = binary.optional_header.minor_image_version
                feature_set["Optional header"]["Max Image version"] = binary.optional_header.major_image_version
                feature_set["Optional header"]["Size of code"] = binary.optional_header.sizeof_code
                feature_set["Optional header"]["Size of headers"] = binary.optional_header.sizeof_headers
                feature_set["Optional header"]["Size of heap commited"] = binary.optional_header.sizeof_heap_commit
                feature_set["Optional header"]["Size of heap reserved"] = binary.optional_header.sizeof_heap_reserve
                feature_set["Optional header"]["Size of image"] = binary.optional_header.sizeof_image
                feature_set["Optional header"]["Size of Initialized data"] = binary.optional_header.sizeof_initialized_data
                feature_set["Optional header"]["Size of Uninitialized data"] = binary.optional_header.sizeof_uninitialized_data
                feature_set["Optional header"]["Size of stack commited"] = binary.optional_header.sizeof_stack_commit
                feature_set["Optional header"]["Size of stack reserved"] =binary.optional_header.sizeof_stack_reserve


                
        elif type_of_file == 'elffile':
            
            if binary.header.mips_flags_list:
                mipsFlags = ':'.join(str(flag) for flag in binary.header.mips_flags_list)
            else:
                mipsFlags = "No flags"
            #print("info", "ELF header : ")
            feature_set['Platform'] = type_of_file
            feature_set["Magic"] = binary.header.identity
            feature_set["Type"] = str(binary.header.file_type)
            feature_set["Entrypoint"] = hex(binary.header.entrypoint)
            feature_set["ImageBase"] = (hex(binary.imagebase) if binary.imagebase else '-')
            feature_set["Header size"] = binary.header.header_size
            feature_set["Endianness"] = str(binary.header.identity_data)
            feature_set["Class"] = str(binary.header.identity_class)
            feature_set["OS/ABI"]= str(binary.header.identity_os_abi)
            feature_set["Version"]= str(binary.header.identity_version)
            feature_set["Architecture"] = str(binary.header.machine_type)
            feature_set["MIPS Flags"] = mipsFlags
            feature_set["Number of sections"] = binary.header.numberof_sections
            feature_set["Number of segments"] = binary.header.numberof_segments
            feature_set["Program header offet"]= hex(binary.header.program_header_offset)
            feature_set["Program header size"] = binary.header.program_header_size
            feature_set["Section Header offset"]  = hex(binary.header.section_header_offset)
            feature_set["Section header size"] = binary.header.section_header_size
    
        else:
            logging.info("Warning : No header found")



        return feature_set


    
            
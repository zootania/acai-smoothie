from collections import defaultdict
import lief

def get_sections(binary, type_of_binary):
        """
           Display sections of ELF, PE, Mach-O
        """
        rows = []
        feature_set = defaultdict(list)
        if type_of_binary == 'elffile':
            feature_set['Sections'] = {}
            for section in binary.sections:
                rows.append([
                    section.name,
                    hex(section.offset),
                    hex(section.virtual_address),
                    "{0:<6} bytes".format(section.size),
                    str(section.type),
                    ':'.join(str(flag) for flag in section.flags_list),
                    round(section.entropy, 4)
                ])
           
            
            feature_set['Sections']['Name'] = [item[0] for item in rows]
            feature_set['Sections']['Offset'] = [item[1] for item in rows]
            feature_set['Sections']['Virtual address'] = [item[2] for item in rows]
            feature_set['Sections']['Size'] = [item[3] for item in rows]
            feature_set['Sections']['Type'] = [item[4] for item in rows]
            feature_set['Sections']['Flags'] = [item[5] for item in rows]
            feature_set['Sections']['Entropy'] = [item[6] for item in rows]
                
                
            #print("info", "Sections : ")
            #print("table", dict(header=["Name", "Address", "RVA", "Size", "Type", "Flags", "Entropy"], rows=rows))
        
        elif type_of_binary == 'EXEfile' or type_of_binary == 'DLLfile':
            feature_set['Sections'] = {}
            for section in binary.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    "{0:<6} bytes".format(section.virtual_size),
                    hex(section.offset),
                    "{0:<6} bytes".format(section.size),
                    round(section.entropy, 4)
                ])
                
                #print(rows)
            
                              
            feature_set['Sections']['Name'] = [item[0] for item in rows]
            feature_set['Sections']['Virtual address'] = [item[1] for item in rows]
            feature_set['Sections']['Virtual size'] = [item[2] for item in rows]
            feature_set['Sections']['Offset'] = [item[3] for item in rows]
            feature_set['Sections']['size'] = [item[4] for item in rows]
            feature_set['Sections']['Entropy'] = [item[5] for item in rows]           
                
                
                
            #print("info", "PE sections : ")
            #print("table", dict(header=["Name", "RVA", "VirtualSize", "PointerToRawData", "RawDataSize", "Entropy"], rows=rows))
        
        elif type_of_binary == 'machofile':
            feature_set['Sections'] = {}
            for section in binary.sections:
                rows.append([
                    section.name,
                    hex(section.virtual_address),
                    str(section.type),
                    "{:<6} bytes".format(section.size),
                    hex(section.offset),
                    round(section.entropy, 4)
                ])
                
            feature_set['Sections']['Name'] = [item[0] for item in rows]
            feature_set['Sections']['Virtual address'] = [item[1] for item in rows]
            feature_set['Sections']['Type'] = [item[2] for item in rows]
            feature_set['Sections']['Size'] = [item[3] for item in rows]
            feature_set['Sections']['Offset'] = [item[4] for item in rows]           
            feature_set['Sections']['Entropy'] = [item[5] for item in rows]
                
                
                
                
            #print("info", "MachO sections : ")
            #print("table", dict(header=["Name", "Virt Addr", "Type", "Size", "Offset", "Entropy"], rows=rows))
        else:
            print("warning", "No section found")



        return feature_set
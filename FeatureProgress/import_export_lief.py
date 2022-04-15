from collections import defaultdict
import lief
import logging

logging.basicConfig(level=logging.INFO, format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def exportedFunctions(binary, type_of_file):
        """
            Display ELf, PE, Mach-O exported functions if any
        """
        feature_set = defaultdict(list)
        function_list = []
        if (( type_of_file == 'machofile' and binary.exported_functions)
                or (type_of_file == 'elffile' and binary.exported_functions)
                or ((type_of_file == 'EXEfile' or type_of_file == 'DLLfile') and binary.exported_functions)):
            #print("info", "Exported functions : ")
            for function in binary.exported_functions:
                #print("info", function)
                #function_list.append(function)
                #dict_[key_a].append(item.data)
                feature_set['Exported functions'].append(str(function))
        else:
            logging.info("Warning : No exported function found")


        return feature_set
            
            
def importedFunctions(binary, type_of_file):
        """
            Display ELF, PE, Mach-O imported functions if any
        """
        feature_set = defaultdict(list)
        if ((type_of_file == 'machofile' and binary.imported_functions)
                or (type_of_file == 'elffile' and binary.imported_functions)
                or ((type_of_file == 'EXEfile' or type_of_file == 'DLLfile')  and binary.imported_functions)):
            #print("info", "Imported functions : ")
            for function in binary.imported_functions:
                #print("info", function)
                feature_set['Imported functions'].append(str(function))
        else:
            logging.info("Warning : No imported function found")
        return feature_set



def printElfSymbols(symbols, title):
        """
            Code factorisation for elf symbols display
            :param (list) symbols : List of symbols
            :param (str) title : Title for the display
        """

        feature_set_sub = defaultdict(list)
        rows = []
        if symbols:
            feature_set_sub [title] = {}
            for symbol in symbols:
                rows.append([
                    symbol.name,
                    str(symbol.type),
                    hex(symbol.value),
                    hex(symbol.size),
                    str(symbol.visibility),
                    "Yes" if symbol.is_function else "No",
                    "Yes" if symbol.is_static else "No",
                    "Yes" if symbol.is_variable else "No"
                ])
            #print("info", "{0} : ".format(title))
            #print("table", dict(header=["Name", "Type", "Val", "Size", "Visibility", "isFun", "isStatic", "isVar"], rows=rows))
            feature_set_sub[title]['Name'] = [item[0] for item in rows]
            feature_set_sub[title]['Type'] = [item[1] for item in rows]
            feature_set_sub[title]['Value'] = [item[2] for item in rows]
            feature_set_sub[title]['Size']   = [item[3] for item in rows]        
            feature_set_sub[title]['Visibility'] = [item[4] for item in rows]
            feature_set_sub[title]['isFun'] = [item[5] for item in rows]
            feature_set_sub[title]['isStatic'] = [item[6] for item in rows]
            feature_set_sub[title]['isVariable'] = [item[7] for item in rows]

        else:
            logging.info("Warning : No elf-symbol found")
            

        return feature_set_sub



def exportedSymbols(binary, type_of_file):
        """
            Display ELF, Mach-O  exported symbols if any
        """
        feature_set = defaultdict(list)
        if (type_of_file == 'elffile') and binary.exported_symbols:
            feature_set = printElfSymbols(binary.exported_symbols, "Exported symbols")
        elif type_of_file == 'machofile' and binary.exported_symbols:
            feature_set['Exported symbols'] = {}
            rows = []
            for symbol in binary.exported_symbols:
                rows.append([
                    symbol.name,
                    symbol.numberof_sections,
                    hex(symbol.value),
                    str(symbol.origin)
                ])
            #print("info", "MachO exported symbols : ")
            #print("table", dict(header=["Name", "Nb section(s)", "Value", "Origin"], rows=rows))
            
            feature_set['Exported symbols']['Name'] = [item[0] for item in rows]
            feature_set['Exported symbols']['Number of sections'] = [item[1] for item in rows]
            feature_set['Exported symbols']['Value'] = [item[2] for item in rows]
            feature_set['Exported symbols']['Origin'] = [item[3] for item in rows]
            
        else:
            logging.info("Warning : No exported symbol found")


        return feature_set



def importedSymbols(binary, type_of_file):
        """
            Display ELF, Mach-O  imported symbols if any
        """
        feature_set = defaultdict(list)
        rows = []
        if (type_of_file == 'elffile') and binary.imported_symbols:
            feature_set = printElfSymbols(binary.imported_symbols, "Imported symbols")
        elif type_of_file == 'machofile' and binary.imported_symbols:
            feature_set['Imported symbols'] = {}
            for symbol in binary.imported_symbols:
                rows.append([
                    symbol.name,
                    symbol.numberof_sections,
                    hex(symbol.value),
                    str(symbol.origin)
                ])
            #print("info", "MachO imported symbols : ")
            #print("table", dict(header=["Name", "Nb section(s)", "Value", "Origin"], rows=rows))
            
            feature_set['Imported symbols']['Name'] = [item[0] for item in rows]
            feature_set['Imported symbols']['Number of sections'] = [item[1] for item in rows]
            feature_set['Imported symbols']['Value'] = [item[2] for item in rows]
            feature_set['Imported symbols']['Origin'] = [item[3] for item in rows]
        else:
            logging.info("Warning : No imported symbols found")



        return feature_set

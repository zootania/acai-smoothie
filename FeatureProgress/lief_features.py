import lief
import os
import json
from pathlib import Path
from collections import defaultdict
from threading import Thread
from queue import Queue
import time

from header_lief import header
from pesignature import signature
from import_export_lief import importedFunctions, exportedFunctions, importedSymbols, exportedSymbols
from sections_lief import get_sections
from peresources_lief import resources, dlls, imports, loadConfiguration

import logging




logging.basicConfig(level=logging.INFO, format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class LiefWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue


    def run(self):
        while True:
            subdir, sample = self.queue.get()

            try:
                lief_features(subdir, sample)

            finally:
                self.queue.task_done()


def check_binary(binary):
    result = 'null'
    if binary:
            if binary.format == lief.EXE_FORMATS.PE:
                if lief.PE.DLL_CHARACTERISTICS:
                    if binary.header.characteristics & lief.PE.HEADER_CHARACTERISTICS.DLL:
                        result = 'DLLfile'
                    else:
                        result = 'EXEfile'
            elif binary.format == lief.EXE_FORMATS.MACHO:
                result = 'machofile'
            elif binary.format == lief.EXE_FORMATS.ELF:
                result = 'elffile'
    return result


# def pelangs(binary, type_of_file):
#         """
#             Display PE used langs and sublangs
#         """
    
#         feature_set = defaultdict(list)
#         if (type_of_binary == 'EXEfile' or type_of_binary == 'DLLfile') and binary.has_resources and binary.resources_manager.langs_available:
            
#             feature_set['Resource manager'] = {}
#             langsAvailable = ", ".join(str(lang) for lang in binary.resources_manager.langs_available)
#             sublangsAvailable = ", ".join(str(sublang) for sublang in binary.resources_manager.sublangs_available)
#             #print("info", "Langs availables      : {0}".format(langsAvailable))
#             #print("info", "Sublangs availables   : {0}".format(sublangsAvailable))
            
#             feature_set['Resource manager']['Language'] = langsAvailable
#             feature_set['Resource manager']['Sub-language'] = sublangsAvailable
#         else:
#             print("warning", "No lang found")
        
#         return feature_set

def codeSignature(binary, type_of_binary):
        """
            Display Mach-O code signature if any
        """
        feature_set = defaultdict(list)
        if type_of_binary == 'machofile' and binary.has_code_signature:
            rows = []
            feature_set['Code signature'] = {}
            rows.append([
                str(binary.code_signature.command),
                hex(binary.code_signature.command_offset),
                "{:<6} bytes".format(binary.code_signature.size),
                hex(binary.code_signature.data_offset),
                "{:<6} bytes".format(binary.code_signature.data_size)
            ])
            #print("info", "MachO code signature : ")
            
            feature_set['Code signature']['Command'] = str(binary.code_signature.command)
            feature_set['Code signature']['Command offset'] = hex(binary.code_signature.command_offset)
            feature_set['Code signature']['Command size'] = binary.code_signature.size
            feature_set['Code signature']['Data offset'] = hex(binary.code_signature.data_offset)
            feature_set['Code signature']['Data size'] = binary.code_signature.data_size
            
            
            #print("table", dict(header=["Command", "Cmd offset", "Cmd size", "Data offset", "Date size"], rows=rows))
        else:
            logging.info("Warning : No code signature found")
        
        return feature_set

def sourceVersion(binary, type_of_binary):
        """
            Display Mach-O source version if any
        """
        feature_set = defaultdict(list)
        if type_of_binary == 'machofile' and binary.has_source_version:
            feature_set["Source version"] = {}
            
            
            feature_set["Source version"]["Command"] = str(binary.source_version.command)
            feature_set["Source version"]["Offset"] = hex(binary.source_version.command_offset)
            feature_set["Source version"]["Size"] = binary.source_version.size
            feature_set["Source version"]["Version"] = listVersionToDottedVersion(binary.source_version.version)
        else:
            
            logging.info("Warning : No source version found")
        
        return feature_set


def listVersionToDottedVersion(listVersion):
        """
            Conversion of a version represented as a list into dotted representation
            :param (list) listVersion : List of version values
            :return (str) : Formatted version : 0.0.0.0....
        """
        if not listVersion:
            return None
        else:
            version = ""
            for index, elt in enumerate(listVersion):
                if index == 0:
                    version += str(elt)
                else:
                    version += '.' + str(elt)
        return version


def interpreter(binary, type_of_binary):
        """
            Display interpreter of ELF and OAT formats
        """
        feature_set = defaultdict(list)
        if (type_of_binary == 'elffile') and binary.has_interpreter:
            #feature_set['interpreter'] = {}
            #print("info", "Interpreter : {0}".format(binary.interpreter))
            feature_set['Interpreter'] = binary.interpreter
        else:
            logging.info("Warning : No interpreter found")

        return feature_set


def lief_features(subdir, sample):
    try:
                    binary = lief.parse(sample)
                    type_of_binary = check_binary(binary)
                    final_result = {}
                    
                    header_dict = header(binary, type_of_binary)
                    #pelangs_dict = pelangs(binary, type_of_binary)
                    codesignature_dict = codeSignature(binary, type_of_binary)
                    sourceversion_dict = sourceVersion(binary, type_of_binary)
                
                    pesignaturet_dict= signature(binary, type_of_binary)

                    elfinterpreter_dict = interpreter(binary,type_of_binary)
                    sections_dict = get_sections(binary, type_of_binary)

                    importedfunctions_dict = importedFunctions(binary, type_of_binary)
                    exportedfunctions_dict = exportedFunctions(binary, type_of_binary)
        
                    importedsymbols_dict = importedSymbols(binary, type_of_binary)
                    exportedsymbols_dict = exportedSymbols(binary, type_of_binary)

                    

                    resources_dict= resources(binary, type_of_binary)
                    dlls_dict = dlls(binary, type_of_binary)
                    peimports_dict = imports(binary, type_of_binary)
                    peconfiguration_dict = loadConfiguration(binary, type_of_binary)
                    
                    for e in [header_dict,codesignature_dict,sourceversion_dict, pesignaturet_dict,elfinterpreter_dict, sections_dict,importedfunctions_dict, exportedfunctions_dict,importedsymbols_dict,exportedsymbols_dict, resources_dict, dlls_dict, peimports_dict, peconfiguration_dict]:
                        final_result.update(e)
                    
                    if final_result:
                            
                        filename = 'lief_features_Apr_queue.json'
                        path_to_file = os.path.join(subdir, filename)
                        #if os.path.exists(path_to_file):
                        #    pass
                        with open(path_to_file, 'w+') as f:
                            json.dump(final_result, f, indent=4)

    except Exception as e:
                    logging.info("Warning : Exception occurced", e)



def main():
                
    ts = time.time()
    #root_dir = 'C:\\Users\\ricewater\\Documents\\flattenDataset'
    root_dir= 'C:\\Users\\ricewater\\Documents\\testDatasetStaticanalyse'
    queue = Queue()
    for x in range(20):
        worker = LiefWorker(queue)
        worker.daemon = True
        worker.start()


    for subdir, dirs, files in os.walk(root_dir):
        for file in files:
            sample = os.path.join(subdir, file)
            if os.path.isfile(sample) and Path(sample).suffix != '.json' and Path(sample).suffix != '.txt':
                logger.info('Queueing {}'.format(sample))
                queue.put((subdir, sample))

    queue.join()
    logging.info('Took %s', time.time() - ts)


if __name__ == '__main__':
    main()


                
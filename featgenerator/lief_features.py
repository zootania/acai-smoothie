import json
import os
import warnings

import dateparser as dp
import numpy as np
import pandas as pd

from .config import Config
# from config import Config

warnings.filterwarnings("ignore")

import numpy as np
import textstat


class Util:
    def lexical_features(self, test_data):
        def get_lexical_feature(method_name, value):
            try:
                method = getattr(textstat, method_name)
                return method(value)
            # Attribute error means function does not exist in textstat
            except (ValueError, TypeError, ZeroDivisionError, AttributeError):
                return 0.0
        method_names = {
            "automated_readability_index": 0,
            "dale_chall_readability_score": 0,
            "difficult_words": 0,
            "monosyllabcount": 0,
            "syllable_count": 0
        }
        for k in method_names:
            method_names[k] = get_lexical_feature(k, test_data)
        return method_names

def get_features_from_function_lists(exported_func_list, prefix):
    exported_func_dist = dict()
    list_of_list = [set(i) for i in exported_func_list]
    for item in list_of_list:
        for i in item:
            cnt = exported_func_dist.get(i)
            if not cnt:
                exported_func_dist.setdefault(i, 1)
            if cnt:
                exported_func_dist[i] = cnt + 1

    one_occurrence = dict()
    more_than_one_occurence = dict()
    for exported_function in exported_func_dist:
        func_val = exported_func_dist.get(exported_function)
        if func_val == 1:
            one_occurrence[exported_function] = func_val
        if func_val > 5:
            more_than_one_occurence[exported_function] = func_val

    res = []
    for exported_functions in exported_func_list:
        result_dict = more_than_one_occurence.copy()
        occurences = '_low_total_occurences'
        presence =  '_low_occurence_'
        result_dict.setdefault(presence,0)
        result_dict.setdefault(occurences,0)
        set_of_our_functions = set(exported_functions)
        for _function in result_dict:
            if _function not in set_of_our_functions:
                result_dict[_function] = 0
            
        for exported_function in exported_functions:
            highly_occ_func = more_than_one_occurence.get(exported_function)
            lowly_occ_func = one_occurrence.get(exported_function)
            if lowly_occ_func and not highly_occ_func:
                result_dict[presence]  = 1
                result_dict[occurences] += 1
            if highly_occ_func:
                result_dict[exported_function] = 1

        result_dict = {f"{prefix}_{i}":result_dict[i] for i in result_dict}
        res.append(result_dict)
    return res

class LiefFeatures():
    def __init__(self):
        conf = Config()
        self.root_dir = conf.get_root_dir()
        self.lief_filename = conf.get_lief_filename()

    def get_dataset(self):
        list_of_sections = []
        hashes_df = []
        hash_list = []

        for subdir, dirs, files in os.walk(self.root_dir):
                for file in files:
                    file_hash = os.path.basename(os.path.normpath(subdir))
                    hash_list.append(file_hash)
                    if file_hash != file:
                        continue
                    lief_file = os.path.join(subdir, self.lief_filename)

                    hashed_obj = {
                        "hash": file_hash, 
                        "CPUType": "",
                        "Platform":"",
                        "Architecture":"",
                        "DateOfCompilation": np.NaN,
                        "Sections":[],
                        "Entropy":[],
                        "ImportedFunctions":[],
                        "ExportedFunctions":[],
                        "Libraries":[],
                        "Imphash":"",
                        "ImageBase": "",
                        "NumberofCommands":"",
                        "SizeofCommands":"",
                        "Flags":[],
                        "HeaderSize":"",
                        "OSType":"",
                        "Entrypoint":"",
                        "OptionalHeaderSize":"",
                        "Checksum":"",
                        "MinOSVersion":"",
                        "MaxOSVersion":"",
                        "SizeofCode":"",
                        "SizeofInitializedData":"",
                        "SignatureMD5":"",
                        "SignatureSHA1":"",
                        "ResourceName":"",
                        "ResourceNumberofChild":"",
                        "ResourceManagerType":[],
                        "ResourceManagerLanguage":[],
                        "ResourceManagerSubLanguage":[],
                        "ConfigurationVersion": ""
                        }
                    try: 
                        if os.path.isfile(lief_file):
                            with open(lief_file) as f:
                                data = json.load(f)
                            if 'Imported functions' in data:
                                clean_import_list = []
                                for value in data['Imported functions']:
                                    clean_import_list.append(value.split("-")[0].strip())
                                hashed_obj['ImportedFunctions'] = clean_import_list


                            if 'Exported functions' in data:
                                clean_export_list = []
                                for value in data['Exported functions']:
                                    clean_export_list.append(value.split("-")[0].strip())
                                hashed_obj['ExportedFunctions'] = clean_export_list

                            if 'Configuration' in data:    
                                hashed_obj['ConfigurationVersion'] = data.get('Configuration', {}).get('Version', '')

                            hashes_df.append(hashed_obj)

                        break
                    except Exception as e:
                        print('#######Exception:', e)
                        break
        return hashes_df


    def get_features(self):
        hashed_obj = self.get_dataset()
        if len(hashed_obj) == 0:
            return pd.DataFrame()
        df = pd.DataFrame(hashed_obj)
        return df
    
lief_feat = LiefFeatures()
lcf = lief_feat.get_features()

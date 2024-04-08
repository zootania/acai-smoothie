import json
import os

import pandas as pd

from .config import Config
from .util import Util
# from config import Config
# from util import Util


class DocFeatures:

    def __init__(self, doc_filename="oletool_features_updated.json"):
        conf = Config()
        self.root_dir = conf.get_root_dir()
        self.doc_filename = conf.get_oletool_filename()

    def get_dataset(self, root_dir, doc_filename):
        hashes_df = []
        for subdir, dirs, files in os.walk(root_dir):
            for file in files:
                file_hash = os.path.basename(os.path.normpath(subdir))

                if file_hash != file:
                    continue
                ole_file = os.path.join(subdir, doc_filename)
                try:
                    if os.path.isfile(ole_file):
                        with open(ole_file) as f:
                            data = json.load(f)

                        hashed_obj = {
                            "hash": file_hash,
                            "FileFormat": "",
                            "FlashObject": "",
                            "VBAMacro": "",
                            "XLMMacro": "",
                            "Encrypted": "",
                            "ObjectPool": "",
                            "ExternalRelationship": "",
                            "ApplicationName": "",
                            "PropertiesCodePage": "",
                            "Author": "",
                            "OLEStream": [],
                            "VBAFiles": [],
                            "AutoExecKeyword": "",
                            "SuspiciousKeyword": "",
                            "Base64ObfuscatedStrings": "",
                            "HexObfuscatedStrings": "",
                            "DridexObfuscatedStrings": "",
                            "VBAObfuscatedStrings": "",
                            "IOCs": "",
                            "Keywords": [],
                        }
                        if "File format" in data[file_hash]:
                            hashed_obj["FileFormat"] = data[file_hash]["File format"]
                        if "Encrypted" in data[file_hash]:
                            hashed_obj["Encrypted"] = data[file_hash]["Encrypted"]
                        if "VBA Macros" in data[file_hash]:
                            if data[file_hash]["VBA Macros"] == "Yes, suspicious":
                                data[file_hash]["VBA Macros"] = "Yes"
                            hashed_obj["VBAMacro"] = data[file_hash]["VBA Macros"]
                        if "XLM Macros" in data[file_hash]:
                            hashed_obj["XLMMacro"] = data[file_hash][
                                "XLM Macros"
                            ].strip("'")
                        if "Flash objects" in data[file_hash]:
                            hashed_obj["FlashObject"] = data[file_hash]["Flash objects"]
                        if "ObjectPool" in data[file_hash]:
                            hashed_obj["ObjectPool"] = data[file_hash]["ObjectPool"]
                        if "External Relationships" in data[file_hash]:
                            hashed_obj["ExternalRelationship"] = data[file_hash][
                                "External Relationships"
                            ]
                        if "Application name" in data[file_hash]:
                            hashed_obj["ApplicationName"] = data[file_hash][
                                "Application name"
                            ]
                        if "Properties code page" in data[file_hash]:
                            hashed_obj["PropertiesCodePage"] = data[file_hash][
                                "Properties code page"
                            ]
                        if "Author" in data[file_hash]:
                            hashed_obj["Author"] = data[file_hash]["Author"]
                        if "VBAMacro" in data[file_hash]:
                            if "OLEstream" in data[file_hash]["VBAMacro"]:
                                hashed_obj["OLEStream"] = data[file_hash]["VBAMacro"][
                                    "OLEstream"
                                ]
                            if "VBAfilename" in data[file_hash]["VBAMacro"]:
                                hashed_obj["VBAFiles"] = data[file_hash]["VBAMacro"][
                                    "VBAfilename"
                                ]
                            if "AutoExec keywords" in data[file_hash]["VBAMacro"]:
                                hashed_obj["AutoExecKeyword"] = data[file_hash][
                                    "VBAMacro"
                                ]["AutoExec keywords"]
                            if "Suspicious keywords" in data[file_hash]["VBAMacro"]:
                                hashed_obj["SuspiciousKeyword"] = data[file_hash][
                                    "VBAMacro"
                                ]["Suspicious keywords"]
                            if "Hex obfuscated strings" in data[file_hash]["VBAMacro"]:
                                hashed_obj["HexObfuscatedStrings"] = data[file_hash][
                                    "VBAMacro"
                                ]["Hex obfuscated strings"]
                            if (
                                "SBase64 obfuscated strings"
                                in data[file_hash]["VBAMacro"]
                            ):
                                hashed_obj["Base64ObfuscatedStrings"] = data[file_hash][
                                    "VBAMacro"
                                ]["SBase64 obfuscated strings"]
                            if (
                                "Dridex obfuscated strings"
                                in data[file_hash]["VBAMacro"]
                            ):
                                hashed_obj["DridexObfuscatedStrings"] = data[file_hash][
                                    "VBAMacro"
                                ]["Dridex obfuscated strings"]
                            if "VBA obfuscated strings" in data[file_hash]["VBAMacro"]:
                                hashed_obj["VBAObfuscatedStrings"] = data[file_hash][
                                    "VBAMacro"
                                ]["VBA obfuscated strings"]
                            if "IOCs" in data[file_hash]["VBAMacro"]:
                                hashed_obj["IOCs"] = data[file_hash]["VBAMacro"]["IOCs"]
                            keyword_values = data[file_hash].get("Keyword Found", [])
                            list_of_keywords = []
                            for k in keyword_values:
                                list_of_keywords.append(k)
                            hashed_obj["Keywords"] = list_of_keywords
                        hashes_df.append(hashed_obj)
                    break
                except Exception as e:
                    continue
        return hashes_df

    def get_features(self):
        hashed_obj = self.get_dataset(self.root_dir, self.doc_filename)
        if len(hashed_obj) == 0:
            return pd.DataFrame()
        df = pd.DataFrame(hashed_obj)
        ut = Util()

        cat_features_df = ut.convert_list_columns_to_categorical(df, ['Keywords', 'VBAFiles', 'OLEStream'])
        cat_features_df['hash'] = df.hash.copy()
        # Convert non boolean or numeric features to one hot.
        features_to_one_hot = ut.get_dummies_for_columns(
            df, 
            ["PropertiesCodePage", "VBAMacro", "XLMMacro", "Author"]
        )
        features_to_one_hot["hash"] = df.hash.copy()

        df_features = pd.merge(cat_features_df, features_to_one_hot, on="hash")

        return df_features

# doc_feat = DocFeatures()
# dcf = doc_feat.get_features()

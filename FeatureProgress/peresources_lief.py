from collections import defaultdict
import lief

from datetime import datetime
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


def resources(binary, type_of_file):
        """
            Display PE resources if any
        """
        feature_set = defaultdict(list)

        if (type_of_file == 'EXEfile' or type_of_file == 'DLLfile') and binary.has_resources:
            feature_set['Resources'] = {}
            if binary.resources.is_directory:
                resourceType = "Directory"
            elif binary.resources.is_data:
                resourceType = "Data"
            else:
                resourceType = "Unknown"
            
            #print("info", "PE resources : ")
            feature_set['Resources']['Name'] = binary.resources.name if binary.resources.has_name else "No name"
            feature_set['Resources']["Number of childs"] = len(binary.resources.childs)
            feature_set['Resources']["Depth"] = binary.resources.depth
            feature_set['Resources']["Type"] = resourceType
            feature_set['Resources']["Id"] = hex(binary.resources.id)
            feature_set['Resource manager'] = {}
            
            if binary.resources_manager.has_type:
 
                resourceType = ", ".join(str(rType) for rType in binary.resources_manager.types_available)
                feature_set['Resource manager']["Type"] = resourceType
                
            if binary.resources_manager.langs_available:
                
                langsAvailable = ", ".join(str(lang) for lang in binary.resources_manager.langs_available)
                sublangsAvailable = ", ".join(str(sublang) for sublang in binary.resources_manager.sublangs_available)
                feature_set['Resource manager']['Language'] = langsAvailable
                feature_set['Resource manager']['Sub-language'] = sublangsAvailable

        else:
            logging.info("Warning : No resource found")

        return feature_set




def dlls(binary, type_of_file):
        """
            Display PE binary imported dlls if any
        """
        feature_set = defaultdict(list)
        if (type_of_file == 'EXEfile' or type_of_file == 'DLLfile') and binary.libraries:
            for lib in binary.libraries:
                feature_set['Libraries'].append(lib)
        else:
            logging.info("Error : No dll found")

        return feature_set



def imports(binary, type_of_file):
        """
            Display Pe imports if any
        """
        feature_set = defaultdict(list)
        if (type_of_file == 'EXEfile' or type_of_file == 'DLLfile') and binary.imports:
            #feature_set['Imports'] = {}
            for imp in binary.imports:
                feature_set['Imports Name'].append(imp.name)
                for function in imp.entries:
                    feature_set['Imports Function IAT'].append(hex(function.iat_address))
                    feature_set['Imports Function name'].append(function.name)
                    #self.log("item", "{0} : {1}".format(hex(function.iat_address), function.name))
        else:
            logging.info("Warning : No import found")

        return feature_set


def loadConfiguration(binary, type_of_file):
        """
            Display PE load configuration if any
        """


        feature_set = defaultdict(list)
        if (type_of_file == 'EXEfile' or type_of_file == 'DLLfile') and binary.has_configuration:
            feature_set['Configuration'] = {}
            feature_set['Configuration']["Version"] = str(binary.load_configuration.version)
            feature_set['Configuration']["Characteristics"] = hex(binary.load_configuration.characteristics)
            feature_set['Configuration']["Timedatestamp"] = fromTimestampToDate(binary.load_configuration.timedatestamp)
            feature_set['Configuration']["Major version"] = binary.load_configuration.major_version
            feature_set['Configuration']["Minor version"] = binary.load_configuration.minor_version
            feature_set['Configuration']["Security cookie"] = hex(binary.load_configuration.security_cookie)
        else:
            logging.info("Warning : No load configuration found")


        return feature_set
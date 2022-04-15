import json
import os
from collections import defaultdict
import ast
floss_filename='flossresults_reduced_6.json'
filename = 'floss_6_newregex.json'
checked_info = defaultdict(list)
details = defaultdict(list)
details_unique = defaultdict(list)
import pprint
pp = pprint.PrettyPrinter(indent=1)
import re

def regex_fun(file_name,file_hash):
   
    #doc = nlp("The United States of America (USA) are commonly known as the United States (U.S. or US) or America.")
    #doc = nlp("you got me 192.3.4.0")
    #file_name = 'floss_2.json'
    introduction_file_text = open(file_name).read()
    details_unique = defaultdict(list)
    
    ##pattern for urls
    expression_url = r"(https?|ftp|telnet|ldap|file):\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)"
    #expression_ip = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    IPV4_REGEX = r"(?P<ipaddress>(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    #IPV6_REGEX = r"(?<![:.\w])(?:[A-F0-9]{0,4}:){2,7}[A-F0-9]{0,4}(?![:.\w])"
    #DNS_REGEX = r"((?=[a-z0-9-]{1,63}\.)[a-z0-9]+(-[a-z0-9]+)*\.){1,126}[a-z]{2,63}"

    URL_REGEX = r"""
            (?P<protocol>(https?|ftp|telnet|ldap|file)://)
            (?P<userinfo>([a-z0-9-._~!$&\'()*+,;=:]|%[0-9A-F]{2})*@)?
            (?P<host>([a-z0-9-._~!$&\'()*+,;=]|%[0-9A-F]{2})*)
            (:(?P<port>\d*))?
            (/(?P<path>([^?\#"<>\s]|%[0-9A-F]{2})*/?))?
            (\?(?P<query>([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?
            (\#(?P<fragment>([a-z0-9-._~!$&'()*+,;=:/?@]|%[0-9A-F]{2})*))?"""

    
    MD5_REGEX = r"(?:^|[^A-Fa-f0-9])(?P<md5>[A-Fa-f0-9]{32})(?:$|[^A-Fa-f0-9])"
    SHA1_REGEX = r"(?:^|[^A-Fa-f0-9])(?P<sha1>[A-Fa-f0-9]{40})(?:$|[^A-Fa-f0-9])"
    SHA256_REGEX = r"(?:^|[^A-Fa-f0-9])(?P<sha256>[A-Fa-f0-9]{64})(?:$|[^A-Fa-f0-9])"




    #expression_filepathw = r"(?:[\w]\:|\\)(\\[a-z_\-\s0-9\.]+)+\.(txt|gif|pdf|doc|docx|xls|xlsx)"
    expression_filepathw = r"(?:[\w]\:|\\)(\\[a-z_\-\s0-9\.]+)+\.(txt|gif|pdf|doc|docx|xls|xlsx|msg|log|rtf|key|dat|jpg|png|exe|bat|apk|jar|js|php|htm|html|dll|lnk)"
    #expression_filepathl= r"(/[^/ ]{0,255})+/?"
    #^(/[^/ ]*)+/?$
    
    #LinuxfilePath =  r"\/[\w]{3,10}[\/]+[\w]{1,40}[\/]+.*\/[\w|+|-|%|\.|~|_|-]{1,255}"
    LinuxfilePath =  r"\/[\w]{3,10}[\/]+[\w]{1,40}[\/]+([\w|+|-|%|\.|~|_|-|\/])*[\w|+|-|%|\.|~|_|-]{1,255}"

    Ethereum = r"^0x[a-fA-F0-9]{40}"
    #Bitcoin = r"/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}"
    Bitcoin = r"([13]|bc1)[A-HJ-NP-Za-km-z1-9]{25,39}"

    # Slack_Token = r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})"
    # RSA_private_key = r"-----BEGIN RSA PRIVATE KEY-----"
    # SSH_DSA_private_key = r"-----BEGIN DSA PRIVATE KEY-----"
    # SSH_private_key = r"-----BEGIN EC PRIVATE KEY-----"
    # PGP_private_key = r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
    # GitHub = r"[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]"
    # Generic_API_Key = r"[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]"
    # Google_API_Key = r"AIza[0-9A-Za-z\\-_]{35}"
    # Google_GCP_Service_account = r"\"type\": \"service_account\""
    # Google_Gmail_API_Key = r"AIza[0-9A-Za-z\\-_]{35}"
    # PayPal_Braintree_Access_Token = r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}"
    # Twitter_Access_Token = r"[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}"
    # Twitter_OAuth = r"[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"


    regexes = {
    "Slack Token": "(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",  
    "GitHub": "[gG][iI][tT][hH][uU][bB].*['|\"][0-9a-zA-Z]{35,40}['|\"]",
    "Generic API Key": "[aA][pP][iI]_?[kK][eE][yY].*['|\"][0-9a-zA-Z]{32,45}['|\"]", 
    "Google API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google (GCP) Service-account": "\"type\": \"service_account\"",
    "Google Gmail API Key": "AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": "[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "PayPal Braintree Access Token": "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Twitter Access Token": "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter OAuth": "[tT][wW][iI][tT][tT][eE][rR].*['|\"][0-9a-zA-Z]{35,44}['|\"]"
}


    try:
        #newPattern = f"(?P<URL>{expression_url})|(?P<IPADDRESS>{expression_ip})|(?P<FilePath_1>{expression_filepathw})|(?P<FilePath_2>{expression_filepathl})"
        #newPattern = f"(?P<URL>{URL_REGEX})|(?P<IPADDRESS>{IPV4_REGEX})|(?P<FilePath_1>{expression_filepathw})|(?P<FilePath_2>{LinuxfilePath})|(?P<IPV6ADDRESS>{IPV6_REGEX})|(?P<DNS>{DNS_REGEX})|(?P<MD5>{MD5_REGEX})|(?P<SHA1>{SHA1_REGEX})|(?P<SHA256>{SHA256_REGEX})|(?P<Ethereum>{Ethereum})|(?P<Bitcoin>{Bitcoin})"
        
        for regex in regexes:
            pattern = re.compile(regexes[regex], re.MULTILINE|re.DOTALL)

        newPattern = f"(?P<URL>{expression_url})|({IPV4_REGEX})|(?P<FilePath_1>{expression_filepathw})|(?P<FilePath_2>{LinuxfilePath})|({MD5_REGEX})|({SHA1_REGEX})|({SHA256_REGEX})|(?P<Ethereum>{Ethereum})|(?P<Bitcoin>{Bitcoin})"
        mre = re.compile(newPattern)

        for match in re.finditer(newPattern, introduction_file_text, re.MULTILINE|re.IGNORECASE):
            if match.groupdict():
                ##Only returning the last match use detauls.append
                #details = match.groupdict()
                details[file_hash].append(match.groupdict())


        


        #details_unique[file_hash] =  [ast.literal_eval(el1) for el1 in set([str(el2) for el2 in details[file_hash]])]
    


    except Exception as e:
        print(e)
    
    return details

root_dir= 'C:\\Users\\ricewater\\Documents\\testDatasetStaticanalyse'

for subdir, dirs, files in os.walk(root_dir):
    for file in files:
         file_hash = os.path.basename(os.path.normpath(subdir))

         if file_hash in checked_info:
                continue        
         floss_file = os.path.join(subdir, floss_filename)
         if os.path.isfile(floss_file):
            #print("grabbing die result")
            print(file_hash)
            floss_result = regex_fun(floss_file,file_hash)
            #entity_extractor = spacy_ent(floss_file)
            #user_agent = useragent_fun(floss_file)
            checked_info[file_hash].append('Yes')
            # Extract Unique values dictionary values

            #print(floss_result)
            
            with open(filename, 'w+') as f:
                 json.dump(floss_result, f, indent=4)
                    
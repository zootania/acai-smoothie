import os
from pathlib import Path
from collections import defaultdict
import json
import exiftool
import time

import oletools.oleid
from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML, TYPE_Word2003_XML, TYPE_MHTML
from oletools import rtfobj


import logging
from threading import Thread
from queue import Queue


logging.basicConfig(level=logging.INFO, format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class OletoolsWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue


    def run(self):
        while True:
            metadata, subdir, sample = self.queue.get()

            try:
                doc_feature(metadata, subdir, sample)

            finally:
                self.queue.task_done()



def doc_feature(metadata, subdir,  file):

    olefeatures = defaultdict(list)
    sample_hash = os.path.basename(os.path.normpath(file))
    try: 
            if metadata[0]['File:FileType'] == 'DOC' or \
               metadata[0]['File:FileType'] == 'DOCX' or \
               metadata[0]['File:FileType'] == 'DOTM' or \
               metadata[0]['File:FileType'] == 'PPT' or \
               metadata[0]['File:FileType'] == 'PDF' or \
               metadata[0]['File:FileType'] == 'RTF' or \
               metadata[0]['File:FileType'] == 'XLS' or \
               metadata[0]['File:FileType'] == 'XLSX' or \
               metadata[0]['File:FileType'] == 'FPX' or \
               metadata[0]['File:FileType'] == 'ZIP':

                oid = oletools.oleid.OleID(file)
                
                indicators = oid.check()

                olefeatures[sample_hash] = {}
 
                olefeatures[sample_hash]["IndicatorId"] = []
                #olefeatures[sample_hash]["IndicatorName"] = {}
                #olefeatures[sample_hash]["IndicatorValue"] = []
                olefeatures[sample_hash]["IndicatorDescription"] = []
                #Details.update({"Age": [18, 20, 25, 29, 30]})
                for i in indicators:
                    olefeatures[sample_hash]["IndicatorId"].append(i.id)
                    olefeatures[sample_hash][i.name] = repr(i.value)
                    #olefeatures[sample_hash].append(i.type)
                    #olefeatures[sample_hash][0].append(repr(i.value))
                    olefeatures[sample_hash]["IndicatorDescription"].append(i.description)
            
            
                if metadata[0]['File:FileType'] == 'RTF':
                    olefeatures[sample_hash]["rtfobject"] = {}
                    for index, orig_len, data in rtfobj.rtf_iter_objects(file):
                        #print('found object size %d at index %08X' % (len(data), index))
                        #print(data)
                        olefeatures[sample_hash]["rtfobject"][hex(index)]= "size " + str(len(data)) 

                else:
                    vbaparser = VBA_Parser(file)
                    if vbaparser.detect_vba_macros():
                        #print('VBA Macros found')
                        olefeatures[sample_hash]["VBAMacro"] = {}
                        olefeatures[sample_hash]["VBAMacro"]["Filename"] = []
                        olefeatures[sample_hash]["VBAMacro"]["OLEstream"] = []
                        olefeatures[sample_hash]["VBAMacro"]["VBAfilename"] = []
                        for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                            #print ('-'*79)
                            olefeatures[sample_hash]["VBAMacro"]["Filename"].append(filename)
                            olefeatures[sample_hash]["VBAMacro"]["OLEstream"].append(stream_path)
                            olefeatures[sample_hash]["VBAMacro"]["VBAfilename"].append(vba_filename)
                            #print ('Filename    :', filename)
                            #print ('OLE stream  :', stream_path)
                            #print ('VBA filename:', vba_filename)
                            #print ('- '*39)
                            #print (vba_code)


                        results = vbaparser.analyze_macros()
                        olefeatures[sample_hash]["VBAMacro"]["Keyword Types"] = []
                        olefeatures[sample_hash]["VBAMacro"]["Keyword Found"] = {}
                        for kw_type, keyword, description in results:
                            #print ('type=%s - keyword=%s - description=%s' % (kw_type, keyword, description))
                            #olefeatures[sample_hash]["VBAMacro"][kw_type].update({keyword:description})
                            olefeatures[sample_hash]["VBAMacro"]["Keyword Types"].append(kw_type)
                            olefeatures[sample_hash]["VBAMacro"]["Keyword Found"][keyword] = description
                            


                        #print ('AutoExec keywords: %d' % vbaparser.nb_autoexec)
                        olefeatures[sample_hash]["VBAMacro"]["AutoExec keywords"] = vbaparser.nb_autoexec
                        #print ('Suspicious keywords: %d' % vbaparser.nb_suspicious)
                        olefeatures[sample_hash]["VBAMacro"]["Suspicious keywords"] = vbaparser.nb_suspicious
                        #print ('IOCs: %d' % vbaparser.nb_iocs)
                        olefeatures[sample_hash]["VBAMacro"]["IOCs"] = vbaparser.nb_iocs
                        #print ('Hex obfuscated strings: %d' % vbaparser.nb_hexstrings)
                        olefeatures[sample_hash]["VBAMacro"]["Hex obfuscated strings"] = vbaparser.nb_hexstrings
                        #print ('Base64 obfuscated strings: %d' % vbaparser.nb_base64strings)
                        olefeatures[sample_hash]["VBAMacro"]["SBase64 obfuscated strings"] = vbaparser.nb_base64strings
                        #print ('Dridex obfuscated strings: %d' % vbaparser.nb_dridexstrings)
                        olefeatures[sample_hash]["VBAMacro"]["Dridex obfuscated strings"] = vbaparser.nb_dridexstrings
                        #print ('VBA obfuscated strings: %d' % vbaparser.nb_vbastrings)
                        olefeatures[sample_hash]["VBAMacro"]["VBA obfuscated strings"] = vbaparser.nb_vbastrings
                        
                        
                        #if vbaparser.nb_base64strings >= 1:
                        #    print(vbaparser.reveal())
                    else:
                        logging.info('The file {} doesn\'t have VBA macros'.format(file))

            if olefeatures:                       
                        filename = "oletool_features.json"
                        path_to_file = os.path.join(subdir, filename)    

                        with open(path_to_file, 'w+') as f:
                             json.dump(olefeatures, f, indent=4)


    except Exception as e:
           logging.info('Exception occured for sample {}'.format(file))


def main():
    ts = time.time()
    #root_dir = 'C:\\Users\\ricewater\\Documents\\flattenDataset'
    root_dir= 'C:\\Users\\ricewater\\Documents\\testDatasetStaticanalyse'
    queue = Queue()
    for x in range(50):
        worker = OletoolsWorker(queue)
        worker.daemon = True
        worker.start()

    for subdir, dirs, files in os.walk(root_dir):
        for file in files:
            sample = os.path.join(subdir, file)
            if os.path.isfile(sample) and Path(sample).suffix != '.json' and Path(sample).suffix != '.txt':
                        sample_hash = os.path.basename(os.path.normpath(sample))
                        with exiftool.ExifToolHelper(executable="exiftool/exiftool(-k).exe") as et:
                            metadata = et.get_metadata(sample)
                        logger.info('Queueing {}'.format(sample))
                        queue.put((metadata, subdir, sample))   
                        #document_feature = docfeature(metadata, sample)


    queue.join()
    logging.info('Took %s', time.time() - ts)


if __name__ == '__main__':
    main()




                    



                
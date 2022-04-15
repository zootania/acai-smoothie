import os
import json
from pathlib import Path
import logging
from threading import Thread
from queue import Queue
import time
import iocextract

logging.basicConfig(level=logging.INFO, format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class IocExtractorWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue


    def run(self):
        while True:
            subdir, floss_file = self.queue.get()

            try:
                IoCExtractor(subdir, floss_file)

            finally:
                self.queue.task_done()



def IoCExtractor(subdir,floss_file):
                #floss_filename = "flossresults_reduced_6.json"
                #path_to_file = os.path.join(subdir, floss_filename)
                IocOutput_file =  os.path.join(subdir, "IoCExtractor.json")
                IoC = {}
                try:
                        #print(sample)
                        #f = magic.from_file(sample)
                        #sample_hash = os.path.basename(os.path.normpath(sample))
                        #generic_feature[sample_hash] = f
                        #print(f)
                        file_text = open(floss_file).read()
                        urls = list(iocextract.extract_urls(file_text, refang = True))
                        emails = list(iocextract.extract_emails(file_text,  refang = True))
                        ips = list(iocextract.extract_ips(file_text,  refang = True))
                        #ipv4 = list(iocextract.extract_ipv4s(file_text))
                        hashes = list(iocextract.extract_hashes(file_text))
                        yararules = list(iocextract.extract_yara_rules(file_text))

                        IoC['Urls'] = urls
                        IoC['IPs'] = ips
                        IoC['Emails'] = emails
                        IoC['Hashes'] = hashes
                        IoC['YaraRules'] = yararules


                        with open(IocOutput_file, 'w+') as f:
                            json.dump(IoC, f, indent=4)
                                            
                except Exception as e:
                    logging.info("Exception occured", e)

def main():
    ts = time.time()
    root_dir = 'C:\\Users\\ricewater\\Documents\\testDatasetStaticanalyse'
    floss_filename = "flossresults_reduced_7.json"
    #content = ["adjfhjkdfsjhfsdjflsdkfjsdjfsdljfldfsdjfhjdskffs"]
    queue = Queue()
    for x in range(10):
        worker = IocExtractorWorker(queue)
        worker.daemon = True
        worker.start()


    for subdir, dirs, files in os.walk(root_dir):
        for file in files:
            file_hash = os.path.basename(os.path.normpath(subdir))       
            floss_file = os.path.join(subdir, floss_filename)
            if os.path.isfile(floss_file):
                logger.info('Queuing {}'.format(file_hash))
                #emails = list(iocextract.extract_emails(content))
                queue.put((subdir, floss_file))

    queue.join()
    logging.info('Took %s', time.time() - ts)


if __name__ == '__main__':
    main()



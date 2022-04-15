import os
import json
import exiftool
from pathlib import Path
import logging
from threading import Thread
from queue import Queue
import time

logging.basicConfig(level=logging.INFO, format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ExifWorker(Thread):
    def __init__(self, queue):
        Thread.__init__(self)
        self.queue = queue


    def run(self):
        while True:
            subdir, sample = self.queue.get()

            try:
                exif_features(subdir, sample)

            finally:
                self.queue.task_done()



def exif_features(subdir, sample):
                filename = "exif_features.json"
                path_to_file = os.path.join(subdir, filename)
                try:
                        #print(sample)
                        #f = magic.from_file(sample)
                        sample_hash = os.path.basename(os.path.normpath(sample))
                        #generic_feature[sample_hash] = f
                        #print(f)
                        with exiftool.ExifToolHelper(executable="exiftool/exiftool(-k).exe") as et:
                            metadata = et.get_metadata(sample)

                        with open(path_to_file, 'w+') as f:
                            json.dump(metadata, f, indent=4)
                                            
                except Exception as e:
                    logging.info('The file {} could not be validated'.format(sample))

def main():
    ts = time.time()
    root_dir = 'C:\\Users\\ricewater\\Documents\\flattenDataset'
    queue = Queue()
    for x in range(50):
        worker = ExifWorker(queue)
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

import os
import subprocess
import warnings
import asyncio
import lief
import os
import magic
from pathlib import Path
from collections import defaultdict
#filecount = 0
warnings.filterwarnings('ignore')

root_dir= 'C:\\Users\\ricewater\\Documents\\testDatasetStaticanalyse'
#root_dir= 'C:\\Users\\ricewater\\Documents\\flattenDataset'
print("Files and directories in a specified path:")

async def checkFloss(subdir, sample):
    #filePath = r'C:\Users\ricewater\Documents\testDatasetStaticanalyse\5e40d106977017b1ed235419b1e59ff090e1f43ac57da1bb5d80d66ae53b1df8\5e40d106977017b1ed235419b1e59ff090e1f43ac57da1bb5d80d66ae53b1df8'
    fileName = 'flossresults_reduced_7.json'
    path_to_file = os.path.join(subdir, fileName)
    #print(path_to_file)
    if os.path.exists(path_to_file):
        return    
    try:
        proc = await asyncio.create_subprocess_shell(
        f"floss.exe -n 7 {sample} -o {path_to_file}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

        stdout, stderr = await proc.communicate()
        #print(f'[{cmd!r} exited with {proc.returncode}]')
        #print(f'[exited with return code {proc.returncode}]')
        # if stdout:
        #     print(f'[stdout]\n{stdout.decode()}')
        # if stderr:
        #     print(f'[stderr]\n{stderr.decode()}')

        #subprocess.run(f"floss.exe -n 8 {sample} -o {path_to_file}"))
    except Exception as e:
        print("An exception occurred", e)


from joblib import parallel_backend


for subdir, dirs, files in os.walk(root_dir):
    for file in files:
         sample = os.path.join(subdir, file)
         if os.path.isfile(sample):
            try:
                if Path(sample).suffix != '.json' and Path(sample).suffix != '.txt':
                    #print(sample)
                    #f = magic.from_file(sample)
                    #sample_hash = os.path.basename(os.path.normpath(sample))
                    #generic_feature[sample_hash] = f
                    #print(generic_feature)
                    asyncio.run(checkFloss(subdir, sample))
            except Exception as e:
                print(e)
import asyncio
import os
import time

def main():
    """
        Controller that calls the task schedule
    """
    asyncio.run(scheduler())
    
async def execute_command(queue):
   while True:
      filename, cmd = await queue.get()
      proc = await asyncio.create_subprocess_shell(
                   cmd,
                   stdout=asyncio.subprocess.PIPE,
                   stderr=asyncio.subprocess.PIPE
             )

      stdout, stderr = await proc.communicate()
      queue.task_done()

async def scheduler():
    """
        Scheduler: takes a list of a directories and creates a set of tasks.
    """ 
    commands = {}
    rootPath = r""
    for file in os.listdir(rootPath):
            commands[file] = f"powershell strings {rootPath}\\{file}\\metadata.json > results\\{file}"
    q = asyncio.Queue()
    for f in commands:
        q.put_nowait((f, commands[f]))
    tasks = []
    for i in range(10):
        task = asyncio.create_task(execute_command(q))
        tasks.append(task)
    
    # Wait until the queue is fully processed.
    queue_begun = time.monotonic()
    await q.join()
    queue_creation_ended = time.monotonic() - queue_begun

    # Cancel all pending tasks.
    for task in tasks:
        task.cancel()

    # Ensure that tasks are cancelled and then gather them. Allow for exceptions.
    await asyncio.gather(*tasks, return_exceptions=True)

import cProfile

with cProfile.Profile() as pr:
    asyncio.run(scheduler())
pr.print_stats()

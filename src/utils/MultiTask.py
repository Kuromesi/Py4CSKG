import multiprocessing
from utils.Logger import logger

class MultiTask:
    def __init__(self) -> None:
        pass

    def create_pool(self, size=32):
        self.pool = multiprocessing.Pool(size)

    def apply_task(self, function, tasks):
        logger.info("Starting to apply multitask")
        result = []
        for task in tasks:
            result.append(self.pool.apply_async(function, task))
        ret = []
        for res in result:
            ret.append(res.get())
        return ret
        
    def delete_pool(self):
        self.pool.close()
        self.pool.join()

def test(a, b):
    return (a, b)

if __name__ == "__main__":
    mt = MultiTask()
    mt.create_pool()
    
    args = [i for i in range(100)]
    args = list(zip(args, args))
    result = mt.apply_task(test, args)
    mt.delete_pool()
import numpy as np

a = np.array([[1,4,3,5,2], [1,4,3,5,2]])
b = np.argsort(a, axis=1)
print(b)
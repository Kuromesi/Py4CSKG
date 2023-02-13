import pandas as pd
import matplotlib.pyplot as plt

def plot1(path):
    '''
    Plot comparison results.
    '''
    df = pd.read_csv(path)
    x = [i + 1 for i in range(10)]
    for k in df:
        y = df[k][0: 10].to_list()
        plt.plot(x, y, label=k)
    plt.legend()
    plt.show()

if __name__ == '__main__':
    plot1('./myData/learning/CVE2CAPEC/comparison.csv')
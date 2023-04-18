import pandas as pd
import matplotlib.pyplot as plt

def plot1(path):
    '''
    Plot comparison results.
    '''
    df = pd.read_csv(path)
    x = [i + 1 for i in range(15)]
    plt.figure(figsize=(15, 6))
    for k in df:
        if k == 'f1_bert': continue
        y = df[k][0: 15].to_list()
        plt.plot(x, y, label=k)
    plt.legend()
    plt.savefig('./myData/thesis/cve2capec/image/fig1.png',dpi=1000, bbox_inches='tight')
    plt.show()

if __name__ == '__main__':
    plot1('./myData/learning/CVE2CAPEC/comparison.csv')
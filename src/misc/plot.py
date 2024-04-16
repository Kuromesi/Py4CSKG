import pandas as pd
import matplotlib.pyplot as plt

def plot1(path):
    '''
    Plot cve and cwe yearly.
    '''
    width = 0.4
    df = pd.read_csv(path)
    year = df['year'].tolist()
    total = df['total'].tolist()
    linked = df['linked'].tolist()
    unlinked = [a - b for a, b in zip(total, linked)]
    plt.rcParams['font.sans-serif'] = ['SimSun']
    plt.figure(figsize=(9, 3.2))
    for i in range(len(year)):
        year[i] -= width / 2
    plt.bar(year, total, width=width, label='CVE总数', color='white', alpha=1, edgecolor='k')
    for i in range(len(year)):
        year[i] += width
    plt.bar(year, unlinked, width=width, label='缺失关系的CVE数量', color='k', alpha=0.5, edgecolor='k')
    plt.legend()
    plt.xticks([i for i in range(1999, 2022)], rotation=300)
    plt.savefig('./myData/thesis/cve2cwe/image/unclassified_cve.pdf',dpi=1000, bbox_inches='tight')
    # plt.show()

def plot2(path):
    '''
    Plot comparison results for different models of CVE2CAPEC.
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
    # plot2('./myData/learning/CVE2CAPEC/comparison.csv')
    plot1('./myData/thesis/cve2cwe.csv')
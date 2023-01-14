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
    plt.figure(figsize=(9, 3.2))
    for i in range(len(year)):
        year[i] -= width / 2
    plt.bar(year, total, width=width, label='Total CVE entries', color='white', alpha=1, edgecolor='k')
    for i in range(len(year)):
        year[i] += width
    plt.bar(year, linked, width=width, label='Classified CVE entries', color='k', alpha=0.5, edgecolor='k')
    plt.legend()
    plt.xticks([i for i in range(1999, 2022)], rotation=300)
    plt.savefig('./myData/thesis/cve2cwe/image/fig1.png',dpi=1000, bbox_inches='tight')
    plt.show()


if __name__ == '__main__':
    plot1('./myData/thesis/cve2cwe.csv')
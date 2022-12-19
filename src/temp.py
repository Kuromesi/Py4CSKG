import pandas as pd

def toML(path, save_path):
    '''
    Convert current tain file to Machine Learning format
    '''
    
    text = []
    i = 0
    j = 0
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            i += 1
            line = line.split(' , ')
            if len(line[0].split('|')) == 1:
                text.append([line[0], line[1].strip()])
                j += 1


    df = pd.DataFrame(text, columns=['label', 'text'])
    df.to_csv(save_path, index=False)

    print("Number of full dataset: %d"%i)
    print("Number of used dataset: %d"%j)

toML('myData/learning/CVE2CWE/cve.train', 'myData/learning/CVE2CWE/cve.csv')

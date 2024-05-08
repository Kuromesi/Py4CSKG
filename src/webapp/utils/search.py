from whoosh.fields import *
import os
from whoosh.index import create_in
from whoosh.index import open_dir
import pandas as pd
from tqdm import tqdm
from whoosh.qparser import QueryParser

def search_product(query):
    '''
    Search CVE related product (keyword matching)
    '''
    myindex = open_dir('data/index')
    qp = QueryParser("product", schema=myindex.schema)
    q = qp.parse(query)
    with myindex.searcher() as s:
        results = s.search(q)
        recommend = []
        for res in results:
            recommend.append(res['product'])
    return recommend

def create_product_index():
    '''
    Create index for CVE related products
    '''
    schema = Schema(product=TEXT(stored=True))
    if not os.path.exists('data/index'):     #如果目录index不存在则创建
        os.mkdir('index') 
    ix = create_in("data/index", schema)      #按照schema模式建立索引目录
    ix = open_dir("data/index")
    writer = ix.writer()

    df = pd.read_csv('data/CVE/product.csv')
    product = df['product'].to_list()
    product = tqdm(product)
    for pro in product:
        writer.add_document(product=pro)
    writer.commit()

if __name__ == "__main__":
    # create()
    results = search_product("mysql")
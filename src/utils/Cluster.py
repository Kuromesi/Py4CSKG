from service.GDBSaver import GDBSaver
from service.RDBSaver import RDBSaver
from sklearn.cluster import DBSCAN
from sklearn import datasets
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt
import numpy as np

class Cluster:
    def __init__(self):
        self.gdb = GDBSaver()
        self.rdb = RDBSaver()
    
    def findCluster(self):
        query = "MATCH (n:cons) RETURN n"
        nodes = self.gdb.sendQuery(query)
        self.rdb.select_database(4)
        self.rdb.r.flushdb()
        
        # Find cluster
        for node in nodes:
            des = node[0].get('des')
            id = node[0].id
            if (id == 67589):
                print(1)
            print(id)
            if (self.rdb.checkSet('visited', id)):
                continue
            self.rdb.addSet('visited', id)
            query = "MATCH (n:cons) WHERE "
            words = des.split(" ")
            if (len(words) < 2):
                continue
            for word in words:
                query += "n.des CONTAINS \"%s\" AND "%word
            query = query.strip("AND ")
            query += " RETURN n"
            try:
                related_nodes = self.gdb.sendQuery(query)
            except:
                continue
            if len(related_nodes) == 1:
                    continue
            for related_node in related_nodes:
                related_id = related_node[0].id
                if (id == related_id):
                    continue
                if (self.rdb.r.scard(related_id)):
                    for temp in self.rdb.r.smembers(related_id):
                        self.rdb.addSet(id, temp)
                    self.rdb.removeKey(related_id)
                self.rdb.addSet('visited', related_id)
                self.rdb.addSet(id, related_id)
    
    def createCluster(self):            
        # Create cluster
        self.rdb.select_database(4)
        keys = self.rdb.r.keys()
        for key in keys:
            key = int(key)
            print(key)
            query = "MATCH (n) WHERE id(n)=%d RETURN n"%key
            node = self.gdb.sendQuery(query)[0]
            des = node[0].get('des')
            node_dict = {}
            node_dict['des'] = des
            node_dict['prop'] = "consCluster"
            node_dict['type'] = "cons"
            src_id = self.gdb.addNode(node_dict)
            members = self.rdb.r.smembers(key)
            for member in members:
                member = int(member)
                rel = "has_subCons"
                self.gdb.addRelation(src_id, member, rel)
                
    def node2vec(self):
        # query = "CALL gds.beta.node2vec.stream('clusterGraph', {embeddingDimension: 200}) \
        #         YIELD nodeId, embedding \
        #         WHERE nodeId=13404 OR nodeId=30930\
        #         RETURN nodeId, embedding"        
        query = "CALL gds.beta.node2vec.stream('clusterGraph', {embeddingDimension: 200}) \
                YIELD nodeId, embedding \
                RETURN nodeId, embedding"
        vecs = []
        results = self.gdb.sendQuery(query)
        # dist = np.linalg.norm(vec1 - vec2)
        # for i in range(100):
        #     id = results[i][0]
        #     vec = results[i][1]
        #     vecs.append(vec)
        #     print(id)
        # for res in results:
        #     id = res[0]
        #     vec = res[1]
        #     vecs.append(vec)
        #     print(id)
        # vecs = np.array(vecs)
        # np.save("data/node2vec.npy", vecs)
        vecs = np.load("data/node2vec.npy")
        dbscan = DBSCAN(eps=0.024, min_samples=1)
        # iris = datasets.load_iris()
        # dbscan.fit(vecs)
        dbscan.fit(vecs)
        pca = PCA(n_components=2).fit(vecs)
        pca_2d = pca.transform(vecs)
        plt.scatter(pca_2d[:, 0], pca_2d[:, 1])
        plt.show()
        print(1)
              
            
    
    def test(self):
        query = "MATCH (n:Vulnerability) WHERE n.id=\"CVE-2021-0215\" RETURN n"
        node = self.gdb.sendQuery(query)
        des = node[0][0].get('des')
        text = self.nlp(des)
        for ent in text.ents:
            print(ent.text, ent.label_)

if __name__=="__main__":
    nlp = NLP()
    
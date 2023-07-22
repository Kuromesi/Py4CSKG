import networkx as nx

import pandas as pd

# 创建示例 DataFrame
df = pd.DataFrame({
    'column_name': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
})

# 定义多个值的列表
values = [2, 4, 6]

# 使用 isin() 方法筛选满足多个值的对应行
filtered_df = df[df['column_name'].isin(values)]

# 打印筛选结果
print(filtered_df)


def find_nodes_with_attribute(graph, attribute):
    nodes_with_attribute = []
    
    for node in graph.nodes:
        if attribute in graph.nodes[node]:
            nodes_with_attribute.append(node)
    
    return nodes_with_attribute

# 创建一个示例图
G = nx.Graph()
G.add_node(1, color='red')
G.add_node(2, color='blue')
G.add_node(3, size=10)
G.add_node(4, color='green')

# 查找包含指定属性的节点
attribute = 'color'
nodes_with_attribute = find_nodes_with_attribute(G, attribute)

# 输出结果
print(f"包含属性 '{attribute}' 的节点：")
for node in nodes_with_attribute:
    print(node)
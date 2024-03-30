import networkx as nx
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties


font = FontProperties(fname=r"./simsun.ttc", size=12)  #设置中文字体

def readGraph(graph_path):
    elist = []  #边集
    #读入数据
    if(graph_path[-3:]=='txt'):
        # 读取txt文件
        df = pd.read_csv(graph_path, sep='\t', skiprows=4, names=['FromNodeId', 'ToNodeId'])
        print(df)
    elif(graph_path[-3:]=='csv'):
        # 读取csv文件
        df = pd.read_csv(graph_path, header=0)
        print(df)
    df.to_csv('./graph/network_'+graph_path[2:-4]+'.csv', index=False)
    for index, row in df.iterrows():
        node_1 = row['FromNodeId']
        node_2 = row['ToNodeId']
        elist.append((node_1,node_2))   
    G = nx.Graph()
    G.add_edges_from(elist)
    # 保存为 .net 文件
    file_path = "./graph/"+graph_path[2:-4]+".net"
    nx.write_pajek(G, file_path)
    return G

#计算网络连通性
def connectivity(G):
    ccs = sorted([cc for cc in nx.strongly_connected_components(G)], key=len, reverse=True)
    largest_cc = ccs[0] if ccs else []
    second_largest_cc = ccs[1] if len(ccs) > 1 else []
    return len(largest_cc), len(second_largest_cc)

#计算节点重要性
def importance(G):
    degree_centrality = nx.degree_centrality(G)  #所有节点的度中心性
    degree_centrality = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)  #按度中心性从大到小排序
    nbc = nx.betweenness_centrality(G)  #所有节点的介数
    nbc = sorted(nbc.items(), key=lambda x: x[1], reverse=True)
    katz = nx.katz_centrality(G)  #所有节点的Katz中心性
    katz = sorted(katz.items(), key=lambda x: x[1], reverse=True)
    cc = nx.closeness_centrality(G, u=None, distance=None, wf_improved=True)  #所有节点的接近中心性
    cc = sorted(cc.items(), key=lambda x: x[1], reverse=True)
    coreness = nx.core_number(G)  #所有节点的核数
    coreness = sorted(coreness.items(), key=lambda x: x[1], reverse=True)
    return degree_centrality, nbc, katz, cc, coreness

def degree_centrality_importance(G):
    degree_centrality = nx.degree_centrality(G)  #所有节点的度中心性
    degree_centrality = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)  #按度中心性从大到小排序
    return degree_centrality
def nbc_importance(G):
    nbc = nx.betweenness_centrality(G, normalized=True, weight=2/((len(G)-1)*(len(G)-2)))  #所有节点的介数
    nbc = sorted(nbc.items(), key=lambda x: x[1], reverse=True)
    return nbc
def katz_importance(G):
    katz = nx.katz_centrality(G)  #所有节点的Katz中心性
    katz = sorted(katz.items(), key=lambda x: x[1], reverse=True)
    return katz
def cc_importance(G):
    cc = nx.closeness_centrality(G, u=None, distance=None, wf_improved=True)  #所有节点的接近中心性
    cc = sorted(cc.items(), key=lambda x: x[1], reverse=True)
    return cc
def coreness_importance(G):
    coreness = nx.core_number(G)  #所有节点的核数
    coreness = sorted(coreness.items(), key=lambda x: x[1], reverse=True)
    return coreness 

def attack(G, importance, name):
    V = len(G)
    fc_results = []
    sc_results = []
    for f in np.arange(0.00, 1.00, 0.01):
        #for f in range(0,0.5,0.01):
        G_attack = G.copy()  # 创建 G 的副本以保持原始网络
        num_nodes_to_remove = int(len(G) * f)  #计算需要移除的节点数量（即被攻击）
        nodes_to_remove = [node for node, centrality in importance[:num_nodes_to_remove]]
        G_attack.remove_nodes_from(nodes_to_remove)  #实施恶意攻击
        gcc_size, css_size = connectivity(G_attack)
        fc_results.append((f, gcc_size/V))
        sc_results.append((f, css_size/V))
    # 绘制结果图像
    plt.plot([x[0] for x in fc_results], [x[1] for x in fc_results], marker='o', label='最大连通分量')
    plt.plot([x[0] for x in sc_results], [x[1] for x in sc_results], marker='o', label='第二大连通分量')
    plt.xlabel('攻击比例 ($f$)', fontproperties=font)
    plt.ylabel('连通分量占比', fontproperties=font)
    plt.title('连通分量占比随攻击比例变化图', fontproperties=font)
    plt.legend(prop=font)  # 设置图例的字体
    plt.grid(True)
    plt.savefig("./graph/images/"+name+"_connectivity_attack.png")  #保存图片
    plt.show()



if __name__=='__main__':
    graph_path = "./p2p-Gnutella31.txt"
    G = readGraph(graph_path)  #构建网络
    gcc_len, css_len = connectivity(G)  #计算网络连通性
    print(f"初始最大连通分量占比：{gcc_len/len(G)}")
    print(f"第二大连通分量占比：{css_len/len(G)}")  
    #degree_centrality, nbc, katz, cc, coreness = importance(G)  #计算节点的重要性指标
    importance = degree_centrality_importance(G)  #重要性度量方法---degreecentrality
    attack(G, importance, "degree_centrality")  #实施恶意攻击
    importance = nbc_importance(G)  #重要性度量方法---nbc
    attack(G, importance, "nbc")  #实施恶意攻击
    importance = katz_importance(G)  #重要性度量方法---katz
    attack(G, importance, "katz")  #实施恶意攻击
    importance = cc_importance(G)  #重要性度量方法---cc
    attack(G, importance, "cc")  #实施恶意攻击
    importance = coreness_importance(G)  #重要性度量方法---coreness
    attack(G, importance, "coreness")  #实施恶意攻击


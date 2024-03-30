import networkx as nx
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties


font = FontProperties(fname=r"./times.ttf", size=12)  #设置中文字体

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
    df.to_csv('./digraph/'+graph_path[2:-4]+'/network_'+graph_path[2:-4]+'.csv', index=False)
    for index, row in df.iterrows():
        node_1 = row['FromNodeId']
        node_2 = row['ToNodeId']
        elist.append((node_1,node_2))   
    G = nx.DiGraph()  #有向图
    G.add_edges_from(elist)
    # 保存为 .net 文件
    file_path = "./digraph/"+graph_path[:-4]+"/"+graph_path[:-4]+".net"
    nx.write_pajek(G, file_path)
    return G

#计算网络连通性
def strongly_connectivity(G):
    ccs = sorted([cc for cc in nx.strongly_connected_components(G)], key=len, reverse=True)
    largest_cc = ccs[0] if ccs else []
    second_largest_cc = ccs[1] if len(ccs) > 1 else []
    return len(largest_cc), len(second_largest_cc)

#计算节点重要性
def importance(G):
    in_degree_centrality = nx.in_degree_centrality(G)  #所有节点的度中心性
    in_degree_centrality = sorted(in_degree_centrality.items(), key=lambda x: x[1], reverse=True)  #按度中心性从大到小排序
    out_degree_centrality = nx.out_degree_centrality(G)  #所有节点的度中心性
    out_degree_centrality = sorted(out_degree_centrality.items(), key=lambda x: x[1], reverse=True)  #按度中心性从大到小排序
    nbc = nx.betweenness_centrality(G)  #所有节点的介数
    nbc = sorted(nbc.items(), key=lambda x: x[1], reverse=True)
    eigenvector = nx.eigenvector_centrality(G, max_iter=100, tol=1e-06, nstart=None, weight=None)
    eigenvector = sorted(eigenvector.items(), key=lambda x: x[1], reverse=True)
    pagerank = nx.pagerank(G)
    pagerank = sorted(pagerank.items(), key=lambda x: x[1], reverse=True)
    katz = nx.katz_centrality(G)  #所有节点的Katz中心性
    katz = sorted(katz.items(), key=lambda x: x[1], reverse=True)
    cc = nx.closeness_centrality(G, u=None, distance=None, wf_improved=True)  #所有节点的接近中心性
    cc = sorted(cc.items(), key=lambda x: x[1], reverse=True)
    coreness = nx.core_number(G)  #所有节点的核数
    coreness = sorted(coreness.items(), key=lambda x: x[1], reverse=True)
    return in_degree_centrality, out_degree_centrality, nbc, eigenvector, pagerank, katz, cc, coreness

def attack_gcc(G, importances, graph):
    V = len(G)
    names = ['in_degree_centrality', 'out_degree_centrality', 'nbc', 'eigenvector', 'pagerank', 'katz', 'cc', 'coreness']
    results = {importance_name: [] for importance_name in names}  #存储攻击结果
    importance_dict = dict(zip(names, importances))
    for importance_name, importance in importance_dict.items():
        for f in np.arange(0.00, 1.00, 0.01):
            G_attack = G.copy()  # 创建 G 的副本以保持原始网络
            num_nodes_to_remove = int(len(G) * f)  #计算需要移除的节点数量（即被攻击）
            nodes_to_remove = [node for node, centrality in importance[:num_nodes_to_remove]]
            G_attack.remove_nodes_from(nodes_to_remove)  #实施恶意攻击
            gcc_size, css_size = strongly_connectivity(G_attack)
            results[importance_name].append((f, gcc_size / V))            
    # 绘制结果图像
    plt.figure(figsize=(10, 6))
    for importance_name, result_data in results.items():
        f_values = [x[0] for x in result_data]
        gcc_sizes = [x[1] for x in result_data]
        plt.plot(f_values, gcc_sizes, label=importance_name)
    plt.xlabel('Attack Ratio ($f$ )', fontproperties=font)
    plt.ylabel('The Proportion of Largest CC', fontproperties=font)
    plt.title('Network Robustness: '+graph, fontproperties=font)
    plt.legend(prop=font)  # 设置图例的字体
    plt.grid(True)
    plt.savefig("./digraph/"+graph+"/largest_strong_connectivity_attack.png")  #保存图片
    #plt.show()

def attack_css(G, importances, graph):
    V = len(G)
    names = ['in_degree_centrality', 'out_degree_centrality', 'nbc', 'eigenvector', 'pagerank', 'katz', 'cc', 'coreness']
    results = {importance_name: [] for importance_name in names}  #存储攻击结果
    importance_dict = dict(zip(names, importances))
    for importance_name, importance in importance_dict.items():
        for f in np.arange(0.00, 1.00, 0.01):
            G_attack = G.copy()  # 创建 G 的副本以保持原始网络
            num_nodes_to_remove = int(len(G) * f)  #计算需要移除的节点数量（即被攻击）
            nodes_to_remove = [node for node, centrality in importance[:num_nodes_to_remove]]
            G_attack.remove_nodes_from(nodes_to_remove)  #实施恶意攻击
            gcc_size, css_size = strongly_connectivity(G_attack)
            results[importance_name].append((f, css_size / V))            
    # 绘制结果图像
    plt.figure(figsize=(10, 6))
    for importance_name, result_data in results.items():
        f_values = [x[0] for x in result_data]
        css_sizes = [x[1] for x in result_data]
        plt.plot(f_values, css_sizes, label=importance_name)
    plt.xlabel('Attack Ratio ($f$ )', fontproperties=font)
    plt.ylabel('The Proportion of Second CC', fontproperties=font)
    plt.title('Network Robustness: '+graph, fontproperties=font)
    plt.legend(prop=font)  # 设置图例的字体
    plt.grid(True)
    plt.savefig("./digraph/"+graph+"/second_strong_connectivity_attack.png")  #保存图片
    #plt.show()


if __name__=='__main__':
    for graph_path in ["./p2p-Gnutella04.txt",  "./p2p-Gnutella05.txt",  "./p2p-Gnutella06.txt", 
                       "./p2p-Gnutella08.txt",  "./p2p-Gnutella09.txt",  "./p2p-Gnutella24.txt", 
                       "./p2p-Gnutella25.txt",  "./p2p-Gnutella30.txt",  "./p2p-Gnutella31.txt"]:
        G = readGraph(graph_path)  #构建网络
        graph = graph_path[2:-4]  #网络名称
        print(graph)
        gcc_len, css_len = strongly_connectivity(G)  #计算网络连通性
        print(f"初始最大强连通分量占比：{gcc_len/len(G)}")
        print(f"第二大强连通分量占比：{css_len/len(G)}")  
        in_degree_centrality, out_degree_centrality, nbc, eigenvector, pagerank, katz, cc, coreness  = importance(G)  #计算节点的重要性指标
        importances = [in_degree_centrality, out_degree_centrality, nbc, eigenvector, pagerank, katz, cc, coreness]  #重要性指标
        attack_gcc(G, importances, graph)
        attack_css(G, importances, graph)

import json
import sys
import numpy as np
import matplotlib.pyplot as plt

def count_cwe(cwe_list):
    flat_list = [item for sublist in cwe_list for item in sublist]
    my_dict = {i:flat_list.count(i) for i in flat_list}
    my_dict.pop('NVD-CWE-noinfo', None)
    my_dict.pop('NVD-CWE-Other', None)

    return my_dict

def get_cwes(scanner_name):
    cwe_file = open('../results/cve_cwe_mapping.json','r')
    cve_cwe_mapping = json.load(cwe_file)

    # unique_cves = get_total_unique_cves()
    unique_cves = get_cves_per_scanner(scanner_name)
    cwe_list = []
    for index in range(len(cve_cwe_mapping)):
        for x in unique_cves:
            if cve_cwe_mapping[index]['id'] == x:
                cwe_list.append(cve_cwe_mapping[index]['cwe'])

    cwe_count = count_cwe(cwe_list)
    return cwe_count

def get_cves_per_scanner(scanner_name):
    read_config = open(f'../results/overview/results_{scanner_name}.json')
    result_data = json.load(read_config)
    unique_cves = result_data['unique_cves']

    return unique_cves

def get_total_unique_cves():
    read_config = open('../results/overview/results_trivy.json')
    cves = json.load(read_config)
    trivy_cves = cves['unique_cves']

    read_config = open('../results/overview/results_docker_scout.json')
    cves = json.load(read_config)
    docker_scout_cves = cves['unique_cves']

    read_config = open('../results/overview/results_grype.json')
    cves = json.load(read_config)
    grype_cves = cves['unique_cves']


    all_unique_cves = list(set(trivy_cves + grype_cves + docker_scout_cves))
    return all_unique_cves 

def graph_total_cwes():
    detected_cwes = get_cwes()
    width = 0.6  # the width of the bars: can also be len(x) sequence

    plt.style.use('_mpl-gallery-nogrid')

    # make data
    labels = []
    x = []
    for cwe,count in detected_cwes.items():
        labels.append(cwe)
        x.append(count)
    colors = plt.get_cmap('Blues')(np.linspace(0.2, 0.7, len(x)))

    # plot
    fig, ax = plt.subplots()
    ax.pie(x, labels=labels, colors=colors, autopct='%1.1f%%', radius=3, center=(4, 4),
            wedgeprops={"linewidth": 1, "edgecolor": "white"})

    ax.set(xlim=(0, 8), xticks=np.arange(1, 8),
            ylim=(0, 8), yticks=np.arange(1, 8))

    plt.show()

def graph_cwes_per_scanner(scanner_name):
    detected_cwes = get_cwes(scanner_name)

    plt.style.use('_mpl-gallery-nogrid')

    # make data
    labels = []
    x = []
    for cwe,count in detected_cwes.items():
        labels.append(cwe)
        x.append(count)

    colors = plt.get_cmap('inferno')(np.linspace(0.2, 0.7, len(x)))

    # plot
    fig, ax = plt.subplots()
    ax.pie(x, labels=labels, colors=colors, autopct='%1.1f%%', radius=3, center=(4, 4),
            wedgeprops={"linewidth": 1, "edgecolor": "white"})

    ax.set(xlim=(0, 8), xticks=np.arange(1, 8),
            ylim=(0, 8), yticks=np.arange(1, 8))

    plt.show()

graph_cwes_per_scanner('docker_scout')


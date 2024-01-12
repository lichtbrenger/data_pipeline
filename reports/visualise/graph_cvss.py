import json
import numpy as np
import matplotlib.pyplot as plt

def count_cvss(cvss_list):
    low = 0
    medium = 0
    high = 0
    critical = 0
    for cvss in cvss_list:
        match cvss:
            case 'low':
                low += 1
            case 'medium':
                medium += 1
            case 'high':
                high += 1
            case 'critical':
                critical += 1

    return [low,medium,high,critical]

def get_cvss(scanner_name):
    test = open('./results/cvss_severity_levels.json','r')
    test2 = json.load(test)

    tset = open(f'./results/overview/results_{scanner_name}.json','r')
    tset2 = json.load(tset)

    cvss_list = []
    for index in range(len(test2)):
        for x in tset2['unique_cves']:
            if test2[index]['id'] == x:
                cvss_list.append(test2[index]['cvss'])

    severity_levels = count_cvss(cvss_list)
    return severity_levels

def graph_cvss_level(level):
    trivy_cvss = get_cvss('trivy')
    grype_cvss = get_cvss('grype')
    docker_scout_cvss = get_cvss('docker_scout')
    scanners = np.array(['Trivy', 'Grype', 'Docker Scout'])
    levels = np.array([trivy_cvss[level], grype_cvss[level], docker_scout_cvss[level]])
    small_percentiles = [trivy_cvss[level], grype_cvss[level], docker_scout_cvss[level]] 


    fig, ax1 = plt.subplots(figsize=(9, 7), layout='constrained')
    ax1.set_xlabel('amount of vulnerabilities')
    rects = plt.barh(scanners, levels, align='center', height=0.3, color='tan')
    ax1.bar_label(rects, small_percentiles,
                  padding=-64, color='white', fontweight='bold')
    ax1.xaxis.grid(True, linestyle='--', which='major',
                   color='black', alpha=.25)
    
    plt.savefig(f'cvss_level_{level}.png')

# accepts 0,1,2,3 -> 'low','medium,'high','critical'
graph_cvss_level(3)

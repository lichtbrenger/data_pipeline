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

    tset = open(f'./results/results_{scanner_name}.json','r')
    tset2 = json.load(tset)

    cvss_list = []
    for index in range(len(test2)):
        for x in tset2['unique_cves']:
            if test2[index]['id'] == x:
                cvss_list.append(test2[index]['cvss'])

    severity_levels = count_cvss(cvss_list)
    return severity_levels


def graph_severity_levels():
    scanners = ['trivy','grype','docker_scout']
    trivy_cvss = get_cvss('trivy')
    grype_cvss = get_cvss('grype')
    docker_scout_cvss = get_cvss('docker_scout')
    sev_levels = {
        'Low': np.array([trivy_cvss[0], grype_cvss[0], docker_scout_cvss[0]]),
        'Medium': np.array([trivy_cvss[1], grype_cvss[1], docker_scout_cvss[1]]),
        'High': np.array([trivy_cvss[2], grype_cvss[2], docker_scout_cvss[2]]),
        'Critical': np.array([trivy_cvss[3], grype_cvss[3], docker_scout_cvss[3]]),
    }
    width = 0.6  # the width of the bars: can also be len(x) sequence

    fig, ax = plt.subplots()
    bottom = np.zeros(3)

    for level, amount in sev_levels.items():
        p = ax.bar(scanners, amount, width, label=level, bottom=bottom)
        bottom += amount

        ax.bar_label(p, label_type='center')

    ax.set_title('CVSS levels')
    ax.legend()

    plt.show()

graph_severity_levels()

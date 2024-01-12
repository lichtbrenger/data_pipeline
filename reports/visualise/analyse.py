# get all cves
# total vs scanned per scanner
# make graphs
import json
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.ticker import (MultipleLocator, 
                               FormatStrFormatter, 
                               AutoMinorLocator)

def get_common_cves():
    cves = { 'trivy': {}, 'grype': {}, 'docker_scout': {} }
    scanners = ['trivy','grype','docker_scout']
    for scanner in scanners:
        read_config = open(f'./results/cves_count_{scanner}.json')
        config = json.load(read_config)
        cves[scanner] = config
    
    for scanner in scanners:
        most_detected = sorted(cves[scanner], reverse=True)[:5]
        

def get_shared_cves():
    read_config = open('../results/cves_count/cves_count_trivy.json')
    cves = json.load(read_config)
    max_cve_list_trivy = get_most_detected(cves)

    read_config = open('../results/cves_count/cves_count_docker_scout.json')
    cves = json.load(read_config)
    max_cve_list_docker_scout = get_most_detected(cves)

    read_config = open('../results/cves_count/cves_count_grype.json')
    cves = json.load(read_config)
    max_cve_list_grype = get_most_detected(cves)

    scanner_top_five = {
        'trivy': max_cve_list_trivy,
        'docker_scout': max_cve_list_docker_scout,
        'grype': max_cve_list_grype
    }

    # all_shared_cves = len(trivy_set & grype_set & docker_scout_set)
    # all_shared_cves_2 = len(set(trivy + grype + docker_scout))
    return scanner_top_five 

def get_most_detected(cves):
    max_cve_list = []
    for i in range(0,20):
        max_cve = { 'cve': '', 'times_detected': 0 }
        highest_times_detected = 1
        for cve,times_detected in cves.items():
            try:
                if times_detected > highest_times_detected:
                    highest_times_detected = times_detected
                    max_cve['cve'] = cve
                    max_cve['times_detected'] = times_detected
            except:
                import pdb;pdb.set_trace()

        cves[max_cve['cve']] = 0 
        max_cve_list.append(max_cve)
 
    return max_cve_list

def get_cves(format):
    read_config = open('../results/overview/results_trivy.json')
    config = json.load(read_config)
    trivy = config[f'{format}_cves']
    if format == 'unique':
        trivy = len(trivy)

    read_config = open('../results/overview/results_docker_scout.json')
    config = json.load(read_config)
    docker_scout = config[f'{format}_cves']
    if format == 'unique':
        docker_scout = len(docker_scout)

    read_config = open('../results/overview/results_grype.json')
    config = json.load(read_config)
    grype = config[f'{format}_cves']
    if format == 'unique':
        grype = len(grype)

    scanner_cves = {
        'trivy': trivy,
        'grype': grype,
        'docker_scout': docker_scout,
    }
    return scanner_cves

def get_severity_levels():
    severity_levels = {
        'trivy': {
            'negligible': 0,
            'low': 0,
            'medium': 0,
            'high': 0
        },
        'grype': {
            'negligible': 0,
            'low': 0,
            'medium': 0,
            'high': 0
        },
        'docker_scout': {
            'negligible': 0,
            'low': 0,
            'medium': 0,
            'high': 0
        },
        'depscan': {
            'negligible': 0,
            'low': 0,
            'medium': 0,
            'high': 0
        }
    }

    read_config = open('./results/overview/results_trivy.json')
    config = json.load(read_config)
    severity_levels['trivy']['negligible'] = float(config['severity']['negligible'])
    severity_levels['trivy']['low'] = float(config['severity']['low'])
    severity_levels['trivy']['medium'] = float(config['severity']['medium'])
    severity_levels['trivy']['high'] = float(config['severity']['high'])
    severity_levels['trivy']['critical'] = float(config['severity']['critical'])
    

    read_config = open('./results/overview/results_grype.json')
    config = json.load(read_config)
    severity_levels['grype']['negligible'] = float(config['severity']['negligible'])
    severity_levels['grype']['low'] = float(config['severity']['low'])
    severity_levels['grype']['medium'] = float(config['severity']['medium'])
    severity_levels['grype']['high'] = float(config['severity']['high'])
    severity_levels['grype']['critical'] = float(config['severity']['critical'])

    read_config = open('./results/overview/results_docker_scout.json')
    config = json.load(read_config)
    severity_levels['docker_scout']['negligible'] = float(config['severity']['negligible'])
    severity_levels['docker_scout']['low'] = float(config['severity']['low'])
    severity_levels['docker_scout']['medium'] = float(config['severity']['medium'])
    severity_levels['docker_scout']['high'] = float(config['severity']['high'])
    severity_levels['docker_scout']['critical'] = float(config['severity']['critical'])

    return severity_levels

def graph_total_cves():
    all_cves = get_cves('total')
    width = 0.6  
    fig, ax = plt.subplots()
    bottom = np.zeros(4)

    color = (0.2, # redness
         0.2, # greenness
         0.4, # blueness
         0.4 # transparency
         )

    color_2 = (0.3, # redness
         0.3, # greenness
         0.5, # blueness
         0.8 # transparency
         )
    for scanner_name,detected_cves in all_cves.items():
        p = ax.bar(scanner_name, detected_cves, width, bottom=bottom, color=color)
        for bar in p:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 22000,
                round(bar.get_height(), 1),
                horizontalalignment='center',
                color=color,
                weight='bold',
                fontsize=25
            )
    
    ax.yaxis.set_major_locator(MultipleLocator(100000)) 
    ax.yaxis.set_major_formatter(FormatStrFormatter('% d'))

    plt.xticks(color=color_2, weight='bold', fontsize=12) 
    plt.yticks( weight='bold', fontsize=12) 
    plt.margins(0.05)
    plt.show()


def graph_unique_cves():
    all_cves = get_cves('unique')
    width = 0.8  
    fig, ax = plt.subplots()
    bottom = np.zeros(4)
    color = (0.2, # redness
         0.4, # greenness
         0.2, # blueness
         0.4 # transparency
         )

    color_2 = (0.3, # redness
         0.5, # greenness
         0.3, # blueness
         0.8 # transparency
         )
    for scanner_name,detected_cves in all_cves.items():
        p = ax.bar(scanner_name, detected_cves, width, bottom=bottom, color=color)
        for bar in p:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 70,
                round(bar.get_height(), 1),
                horizontalalignment='center',
                color=color,
                weight='bold',
                fontsize=25
            )
    
    ax.yaxis.set_major_locator(MultipleLocator(2000)) 
    ax.yaxis.set_major_formatter(FormatStrFormatter('% d'))

    plt.xticks(color=color_2, weight='bold', fontsize=12) 
    plt.yticks( weight='bold', fontsize=12) 
    plt.margins(0.05)
    plt.show()

def graph_top_five_cves(scanner_name):
    all_cves = get_shared_cves()
    plt.style.use('_mpl-gallery-nogrid')

    # make data
    labels = []
    x = []
    for cves in all_cves[scanner_name]:
        labels.append(cves['cve'])
        x.append(cves['times_detected'])
    colors = plt.get_cmap('inferno')(np.linspace(0.2, 0.7, len(x)))

    # plot
    fig, ax = plt.subplots()
    ax.pie(x, labels=labels, colors=colors, autopct='%1.1f%%', radius=3, center=(4, 4),
            wedgeprops={"linewidth": 1, "edgecolor": "white"})

    ax.set(xlim=(0, 8), xticks=np.arange(1, 8),
            ylim=(0, 8), yticks=np.arange(1, 8))

    plt.show()

def graph_severity_levels(level):
    severity_levels = get_severity_levels()
    scanners = np.array(['Trivy', 'Grype', 'Docker Scout'])
    levels = np.array([severity_levels['trivy'][level],severity_levels['grype'][level],severity_levels['docker_scout'][level]])
    small_percentiles = [severity_levels['trivy'][level],severity_levels['grype'][level],severity_levels['docker_scout'][level]]

    fig, ax1 = plt.subplots(figsize=(9, 7), layout='constrained')
    ax1.set_xlabel('amount of vulnerabilities')
    rects = plt.barh(scanners, levels, align='center', height=0.3, color='tan')
    ax1.bar_label(rects, small_percentiles,
                  padding=-64, color='white', fontweight='bold')
    ax1.xaxis.grid(True, linestyle='--', which='major',
                   color='black', alpha=.25)
    
    plt.savefig(f'severity_level_{level}.png')

def graph_severity_levels_relative():
    all_cves = get_cves('unique')
    severity_levels = get_severity_levels()
    scanners = ('Trivy', 'Grype', 'Docker Scout')
    total_cves_per_scanner = []
    for scanner in severity_levels:
        if scanner == 'depscan':
            continue
        total_cves = severity_levels[scanner]['negligible'] + severity_levels[scanner]['low'] + severity_levels[scanner]['medium'] + severity_levels[scanner]['high'] + severity_levels[scanner]['critical']
        total_cves_per_scanner.append(total_cves)
    sev_levels = {
        'Negligible': np.array([(severity_levels['trivy']['negligible']/total_cves_per_scanner[0])*all_cves['trivy'], (severity_levels['grype']['negligible']/total_cves_per_scanner[1])*all_cves['grype'], (severity_levels['docker_scout']['negligible']/total_cves_per_scanner[2])*all_cves['docker_scout']]),
        'Low': np.array([(severity_levels['trivy']['low']/total_cves_per_scanner[0])*all_cves['trivy'], (severity_levels['grype']['low']/total_cves_per_scanner[1])*all_cves['grype'], (severity_levels['docker_scout']['low']/total_cves_per_scanner[2])*all_cves['docker_scout']]),
        'Medium': np.array([(severity_levels['trivy']['medium']/total_cves_per_scanner[0])*all_cves['trivy'], (severity_levels['grype']['medium']/total_cves_per_scanner[1])*all_cves['grype'], (severity_levels['docker_scout']['medium']/total_cves_per_scanner[2])*all_cves['docker_scout']]),
        'High': np.array([(severity_levels['trivy']['high']/total_cves_per_scanner[0])*all_cves['trivy'], (severity_levels['grype']['high']/total_cves_per_scanner[1])*all_cves['grype'], (severity_levels['docker_scout']['high']/total_cves_per_scanner[2])*all_cves['docker_scout']]),
        'Critical': np.array([(severity_levels['trivy']['critical']/total_cves_per_scanner[0])*all_cves['trivy'], (severity_levels['grype']['critical']/total_cves_per_scanner[1])*all_cves['grype'], (severity_levels['docker_scout']['critical']/total_cves_per_scanner[2])*all_cves['docker_scout']]),
    }
    width = 0.6  # the width of the bars: can also be len(x) sequence

    fig, ax = plt.subplots()
    bottom = np.zeros(3)

    for level, amount in sev_levels.items():
        p = ax.bar(scanners, amount, width, label=level, bottom=bottom)
        bottom += amount

        ax.bar_label(p, label_type='center')

    ax.set_title('relative severity levels')
    ax.legend()

    plt.show()


# graph_total_cves()
# graph_unique_cves()
# acceptable levels 'neglibile','low','medium','high','critical'
graph_severity_levels('high')
#graph_severity_levels_relative()
# get_common_cves()
# graph_top_five_cves('docker_scout')

import os
import re
import glob
import json
import requests

paths = ['./trivy/*','./grype/*','./docker_scout/*','./depscan/scanned_images/*']
json_file = { 'total_cves': 0,'unique_cves': [], 'severity': { 'negligible': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0 } }

def find_cve(report):
    with open(report,'r') as f:
        file = f.read()
        cves = re.findall(r'CVE-[0-9]*-[0-9]*', file)
        return list(set(cves))

def find_severity_levels(report, scanner_name):
    with open(report,'r') as f:
        severity_levels = []
        file = f.read()
        if scanner_name == 'trivy':
            severity_levels = re.findall(r'(MEDIUM|LOW|HIGH)', file)
        if scanner_name == 'grype':
            severity_levels = re.findall(r'(Negligible|Low|Medium|High)', file)
        if scanner_name == 'docker_scout':
            severity_levels = os.popen("cat " + report + " | tail -n 5 | awk '{print $2}'").read().split('\n')
            severity_levels = list(filter(None, severity_levels))
            for index in range(0, len(severity_levels)):
                if severity_levels[index] == 'Packages' or severity_levels[index] == 'vulnerable':
                    continue
                severity_levels[index] = int(severity_levels[index])

            severity_levels = severity_levels[0:4] 
            # sev = { 'low': severity_levels[0], 'medium': severity_levels[1], 'high': severity_levels[2], 'critical': severity_levels[3] }
        return severity_levels

def commit_severity_levels_to_json_file(severity_levels, scanner_name):
        if scanner_name == 'trivy':
            for level in severity_levels:
                if level == 'LOW':
                    json_file['severity']['low'] += 1
                if level == 'MEDIUM':
                    json_file['severity']['medium'] += 1
                if level == 'HIGH':
                    json_file['severity']['high'] += 1
        if scanner_name == 'docker_scout':
            if isinstance(severity_levels[0], str):
                os.system(f'ls {report} >> testfile')
                return 
            json_file['severity']['low'] += severity_levels[0]
            json_file['severity']['medium'] += severity_levels[1] 
            json_file['severity']['high'] += severity_levels[2]
            json_file['severity']['critical'] += severity_levels[3]
        if scanner_name == 'grype':
            for level in severity_levels:
                if level == 'Negligible':
                    json_file['severity']['negligible'] += 1
                if level == 'Low':
                    json_file['severity']['low'] += 1
                if level == 'Medium':
                    json_file['severity']['medium'] += 1
                if level == 'High':
                    json_file['severity']['high'] += 1


def write_file(json_file,scanner_name):
    with open(f'./results/results_{scanner_name}.json','w') as file:
        json.dump(json_file ,file)

def get_scanner_name(path):
    scanner_name = ''
    if 'trivy' in p:
        scanner_name = 'trivy'
    if 'grype' in p:
        scanner_name = 'grype'
    if 'depscan' in p:
        scanner_name = 'depscan'
    if 'docker_scout' in p:
        scanner_name = 'docker_scout'

    return scanner_name

def write_cves_count(scanner_name):
    # max(my_dict, key=my_dict.get)
    my_dict = {i:json_file['unique_cves'].count(i) for i in json_file['unique_cves']}
    with open(f'./results/cves_count_{scanner_name}.json','w') as file:
        json.dump(my_dict,file)
    

for p in paths:
    reports = glob.glob(p)
    scanner_name = get_scanner_name(p)
    for report in reports:
        cves = find_cve(report)
        severity_levels = find_severity_levels(report, scanner_name)
        commit_severity_levels_to_json_file(severity_levels, scanner_name)
        json_file['unique_cves'].extend(cves)


    # write_cves_count(scanner_name)
    json_file['total_cves'] = len(json_file['unique_cves'])
    unique_cves = list(set(json_file['unique_cves']))
    json_file['unique_cves'] = unique_cves 
    write_file(json_file, scanner_name)
    json_file = { 'total_cves': 0, 'unique_cves': [], 'severity': { 'negligible': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0 } }


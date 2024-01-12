import json
import requests
import re
import os

def get_cvss_level(cves):
    cve_cvss = []
    for cve in cves:
        cve_detail = { 'id': '', 'cvss': '' }
        score = 0
        file = os.popen(f'grep -rnw "./nvd" -e {cve}').read().split(':')[0]
        if file == '':
            continue
        test = open(file,'r')
        test2 = json.load(test)
        for index in range(len(test2["CVE_Items"])):
            if test2["CVE_Items"][index]["cve"]["CVE_data_meta"]["ID"] == cve:
                try:
                    values = []
                    for value in test2["CVE_Items"][index]["impact"]: values.append(value)
                    if values[0] == 'baseMetricV3':
                        score = test2["CVE_Items"][index]["impact"][values[0]]["cvssV3"]["baseScore"]
                    if values[0] == 'baseMetricV2':
                        score = test2["CVE_Items"][index]["impact"][values[0]]["cvssV2"]["baseScore"]
                except:
                    os.system(f'echo "{cve}" >> remaining')
                    continue

        index = 0
        cvss = 'none'
        if score >= 0.1 and score <= 3.9:
            cvss = 'low'
        if score >= 4.0 and score <= 6.9:
            cvss = 'medium'
        if score >= 7.0 and score <= 8.9:
            cvss = 'high'
        if score >= 9.0:
            cvss = 'critical'

        cve_detail['id'] = cve
        cve_detail['cvss'] = cvss
        cve_cvss.extend([cve_detail])
        write_file(cve_cvss)

    return cve_cvss



        

def get_cves():
    read_config = open('./results/results_trivy.json')
    config = json.load(read_config)
    trivy = config['unique_cves']

    read_config = open('./results/results_docker_scout.json')
    config = json.load(read_config)
    docker_scout = config['unique_cves']

    read_config = open('./results/results_grype.json')
    config = json.load(read_config)
    grype = config['unique_cves']

    cves = list(set(trivy + docker_scout + grype))

    return cves 

def write_file(json_file):
    with open(f'./results/cvss_severity_levels.json','w') as file:
        json.dump(json_file ,file)

cves = get_cves()
cve_list = get_cvss_level(cves)
write_file(cve_list)

import os
import json

def get_cwes(cves):
    cve_cwe = []
    for cve in cves:
        cve_detail = { 'id': '', 'cwe': [] }
        score = 0
        file = os.popen(f'grep -rnw "./nvd" -e {cve}').read().split(':')[0]
        if file == '':
            continue
        test = open(file,'r')
        test2 = json.load(test)
        for index in range(len(test2["CVE_Items"])):
            if test2["CVE_Items"][index]["cve"]["CVE_data_meta"]["ID"] == cve:
                try:
                    for index in range(len(test2["CVE_Items"][index]["cve"]["problemtype"]["problemtype_data"][0]["description"])):
                        cve_detail['cwe'].append(test2["CVE_Items"][index]["cve"]["problemtype"]["problemtype_data"][0]["description"][index]["value"])
                except:
                    os.system(f'echo "{cve}" >> cves_without_cwe')
                    continue

        cve_detail['id'] = cve
        cve_cwe.extend([cve_detail])
        write_file(cve_cwe)

    return cve_cwe

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
    with open(f'./results/cve_cwe_mappings.json','w') as file:
        json.dump(json_file ,file)

cves = get_cves()
cve_list = get_cwes(cves)
write_file(cve_list)


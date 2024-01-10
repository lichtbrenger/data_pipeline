"""
Automates scanning for images
"""
import os
import json

def setup_report_directory():
    path = './scanned_images/'
    if not os.path.exists(path):
        os.mkdir(path)
        for scanner in scanners:
            os.mkdir(path+'/'+scanner)
    else:
        if not os.path.exists(path+'/'+scanner):
            for scanner in scanners:
                os.mkdir(path+'/'+scanner)

def choose_scanner():
    scanners = ['trivy', 'grype', 'docker_scout', 'depscan']
    batch_numbers = []
    for scanner in scanners:
        batch_number = get_batch(scanner) 
        batch_numbers.append(batch_number)
    lowest_number = min(batch_numbers)
    if lowest_number <= 26:
        index = batch_numbers.index(lowest_number)
        return scanners[index]

def get_batch(scanner):
    read_config = open('./scan_config.json')
    config = json.load(read_config)
    batch_number = config["scanners"][scanner]
    read_config.close()

    return batch_number

def update_batch(original_batch_number, scanner):
    read_config = open('./scan_config.json')
    config = json.load(read_config)
    read_config.close()

    write_config = open('./scan_config.json','w')
    batch_number = original_batch_number + 1
    config["scanners"][scanner] = batch_number
    json.dump(config,write_config)
    write_config.close()


os.system('sudo systemctl start docker')
os.system('docker login')
scanner = choose_scanner()
batch_number = get_batch(scanner)
update_batch(batch_number, scanner)
os.system(f'python3 scan.py docker_scout 5')
# trivy 5
# grype 5
# docker_scout 5


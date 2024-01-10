"""
uses all the images scraped and scans them.
scanners used: Trivy, Grype, Docker Scout, DepScan
docker scout: https://docs.docker.com/engine/reference/commandline/scout_cves/
docker scout cves --output haskell.json haskell:buster
depscan --no-error --cache --src alpine:14.10 -o depscan-scan.json -t docker
https://github.com/deepfence/ThreatMapper
"""
import os
import json
import argparse

def get_images():
    with open(f'../image_database/images_{args.batch_number}', encoding="utf-8") as image_list:
        images = image_list.read().splitlines()
        return images

def get_image_name(image):
    return image.split(',')[0]
    
def get_image_version(image):
    image_versions = image.split(',')[1:]
    if image_versions[0] == 'latest' and (len(image_versions) > 1):
        return image_versions[1]
    else:
        return image_versions[0]

def get_report_name(image):
    report_name = image.split(',')[0]
    if '/' in report_name:
        report_name = report_name.split('/')[1]
    return report_name

def scan_images(images):
    for image in images:
        image_name = get_image_name(image)
        image_version = get_image_version(image)
        report_name = get_report_name(image)
        match args.scanner_name:
            case 'trivy':
                os.system(f'trivy image -f json -o ../reports/trivy/{report_name}_trivy.json {image_name}:{image_version}')
            case 'grype':
                os.system(f'grype {image_name}:{image_version} -o json > ../reports/grype/{report_name}-grype.json')
            case 'docker_scout':
                os.system(f'docker scout cves --output ../reports/docker_scout/{report_name}_docker_scout.json {image_name}:{image_version}')
            case 'depscan':
                os.system(f'depscan --no-error --src {image_name}:{image_version} -o ../reports/depscan/scanned_images/{report_name}_depscan.json -t docker')

def start_scan():
    images = get_images()
    scan_images(images)

parser = argparse.ArgumentParser(description='Optional app description')
parser.add_argument('scanner_name', type=str,
                    help='A required integer positional argument')
parser.add_argument('batch_number', type=int,
                    help='A required integer positional argument')
args = parser.parse_args()
start_scan()

# Base Libraries 
import os
import time
import re
import requests

# Selenium 4 for loading the Browser Driver 
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service

# Web Driver Manager
from webdriver_manager.chrome import ChromeDriverManager

# BeautifulSoup Library used for Parsing the HTML 
from bs4 import BeautifulSoup

# Change the base_dir with your path.
base_dir = '/Users/lichtbrenger/Downloads' + os.sep

# Opening the CSV File Handle
image_file = open('images', 'w')

# Initialising the Chrome Driver
options = Options()
options.add_argument("start-maximized")
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

# Images Type which have to filitered from the DockerHub 
images = ["official","store","open_source"]
verifiedImages = list()
officialImages = list()

for i in images:
    counter = 1
    while True:
    
        # Load the Docker Hub HTML page
        driver.get(
            "https://hub.docker.com/search?q=&type=image&image_filter=" + i + "&operating_system=linux&page=" + str(counter))
        
        # Delay to load the contents of the HTML FIle
        time.sleep(2)
        
        # Parse processed webpage with BeautifulSoup
        soup = BeautifulSoup(driver.page_source, features="html.parser")
        
        nextCheck = soup.find('p', attrs={'class': 'styles__limitedText___HDSWL'})
        
        
        if not isinstance(nextCheck, type(None)):
            break
            
        results = soup.find(id="searchResults")
        
        if isinstance(results, type(None)):
            print("Error: results is NoneType")
            break

        imagesList = results.find_all('a',attrs={'data-testid': 'imageSearchResult'})

        if len(imagesList) == 0:
            break   # Stopping the parsing when no images are found

        for image in imagesList:

            # Getting the Name of the Image
            image_name = image.find('span',{"class":re.compile('.*MuiTypography-root.*')}).text

            # Writing the Image Name, Download Count and Stars Count to File
            image_file.write(image_name)
            
            namespace = ''
            if i == 'official':
                namespace = '_'
            else:
                namespace = 'r'
            driver.get(f'https://hub.docker.com/{namespace}/{image_name}/tags')
            soup = BeautifulSoup(driver.page_source, features="html.parser")
            tags = soup.find_all('a',attrs={'data-testid': 'navToImage'})

            for tag in tags:
                image_file.write(','+tag.text)
            image_file.write('\n')

        if len(imagesList) == 0:
            break

        counter += 1

# Closing of the CSV File Handle           
image_file.close()

# Closing of the Chrome Driver 
driver.quit()

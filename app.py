import json
import logging
import platform
import sys
import time
import os
from pprint import pprint

## Logging stuff
datum = time.strftime("%d-%m-%Y")
logging.basicConfig(filename='%s-log.log'%(datum) ,format='%(asctime)s - %(name)s - %(levelname)s | %(message)s |', stream=sys.stdout, level=logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s | %(message)s |')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

def tools():
    x = os.listdir("./json")
    for jsons in x:
        with open('json/%s'%jsons) as data_file:
            data = json.load(data_file)

        for exploit in data:
            for d in exploit:
                logging.info(data[d]['id'])
                logging.info(data[d]['Description'])

def main():
    logging.info("Welcome to Hardening")
    logging.info("Running on %s version %s" %(platform.system(),platform.release()))
    if platform.system() != "Ubuntu":
        logging.critical("Operating system not Supported!")
        #exit()
    logging.info("Testing..!")
    tools()


if __name__ == "__main__":
    # execute only if run as a script
    user = os.getenv("SUDO_USER")
    #if user is None:
    #    print("This program need 'sudo'")
    #    exit()
    main()
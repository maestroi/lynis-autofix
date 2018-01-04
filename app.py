import json
import logging
import platform
import sys
import shlex
import time
import os
import subprocess
from StringIO import StringIO
from pprint import pprint

## Logging stuff
datum = time.strftime("%d-%m-%Y")
logging.basicConfig(filename='%s-log.log'%(datum) ,format='%(asctime)s - %(name)s - %(levelname)s | %(message)s |', stream=sys.stdout, level=logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s | %(message)s |')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)


def run_shell_command(command_line):
    command_line_args = shlex.split(command_line)

    logging.info('Subprocess: "' + command_line + '"')

    try:
        command_line_process = subprocess.Popen(
            command_line_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True,
        )

        process_output, _ =  command_line_process.communicate()

    except (OSError) as exception:
        logging.info('Exception occured: ' + str(exception))
        logging.info('Subprocess failed')
        return False
    else:
        # no exception was raised
        logging.info('Subprocess finished')
    return True

def tools():
    x = os.listdir("./json")
    for jsons in x:
        with open('json/%s'%jsons) as data_file:
            data = json.load(data_file)

        for exploit in data:
            for d in exploit:
                logging.info(data[d]['id'])
                run_shell_command(data[d]['command'])

def apache():
    #print os.system('dpkg -l | grep apache2')
    pass

def lynisupdate():
    if os.path.exists("/usr/local/lynis") == True:
        os.system("cd /usr/local/lynis && git pull > /dev/null 2>&1")
        logging.info('Lynis updated')
    elif os.path.exists("/usr/local/lynis") == False:
        os.system("sudo git clone https://github.com/CISOfy/lynis.git /usr/local/lynis > /dev/null 2>&1")
        logging.info('Lynis Installed')
    else:
        logging.critical('Could not update/download lynis')

def runlynis():
    try:
        logging.info('Generate Lynis Report bare with us :-)')
        os.system("cd /usr/local/lynis && sudo ./lynis audit system -q --auditor 'Lynis-autofix' --report-file /usr/local/lynis/%s-report.dat > /dev/null 2>&1"%datum)
        logging.info('Report Generated! find it at /usr/local/lynis/%s-report.dat'%datum)
    except:
        logging.critical('Could not update/download lynis')

def main():
    logging.info("Welcome to Hardening")
    if platform.system() == "Linux":
        logging.info("Running on %s version %s" % (platform.system(), platform.release()))
    elif platform.system() != "Linux":
        logging.info("Running on %s version %s" % (platform.system(), platform.release()))
        logging.critical("%s %s not Supported!" % (platform.system(), platform.release()))
        exit()
    else:
        exit()
    logging.info(40 * "-")
    lynisupdate()
    logging.info(40 * "-")
    runlynis()
    logging.info(40 * "-")
    tools()
    logging.info(40 * "-")
    apache()


if __name__ == "__main__":
    # execute only if run as a script
    user = os.getenv("SUDO_USER")
    #if user is None:
    #    print("This program need 'sudo'")
    #    exit()
    main()
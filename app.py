import json
import logging
import platform
import sys
import shlex
import time
import os
import re
import subprocess
from StringIO import StringIO
from pprint import pprint

## Logging stuff
datum = time.strftime("%d-%m-%Y-%H-%M-%S")
logging.basicConfig(filename='%s-log.log'%(datum) ,format='%(asctime)s - %(name)s - %(levelname)s | %(message)s |', stream=sys.stdout, level=logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s | %(message)s |')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)
listtodo = []

def fix_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

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

def fixes():
    for todo in listtodo:
        try:
            with open('json/%s.json' % todo[0]) as data_file:
                data = json.load(data_file)
            for fix in data:
                for d in fix:
                     if fix_yes_no('Do you want to install %s - %s?'%(data[d]['id'], data[d]['Description']), default="yes") == True:
                        logging.info('%s - %s' % (data[d]['id'], data[d]['command']))
                     else:
                         logging.warning('%s - %s is not installed' % (data[d]['id'], data[d]['command']))
        except:
            logging.critical('%s.json does not excist in the json directory' % todo[0])

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
        os.system("cd /usr/local/lynis && sudo ./lynis audit system -q --auditor 'Lynis-autofix' --report-file /usr/local/lynis/%s-report.dat > /dev/null 2>&1 && cat /usr/local/lynis/%s-report.dat | grep suggestion > /usr/local/lynis/%s-suggestion.txt "%(datum,datum,datum))
        file = open('/usr/local/lynis/%s-suggestion.txt'%datum, "r")
        for row in file:
            logging.info("%s"%row)
        file.close()
    except:
        logging.critical('Could not create report from lynis')

def todolist():
    file = open("/usr/local/lynis/%s-suggestion.txt"%datum, "r")
    regex = r"suggestion\[\]=([A-z-0-9]+)\|"
    for row in file:
        matches = re.findall(regex, row)
        listtodo.append(matches)
    file.close()


def main():
    logging.info("Welcome to Lynis Autofix!")
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
    todolist()
    logging.info(40 * "-")
    fixes()


if __name__ == "__main__":
    user = os.getenv("SUDO_USER")
    if user is None:
        print("This program need 'sudo'")
        exit()
    main()
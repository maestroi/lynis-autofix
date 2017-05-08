import os
import sys
import logging

## Logging stuff
logging.basicConfig(filename='hardening.log' ,format='%(asctime)s - %(name)s - %(levelname)s | %(message)s |', stream=sys.stdout, level=logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s | %(message)s |')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

def hardenssh():
    with open("/etc/ssh/sshd_config", "a") as myfile:
        myfile.write("ClientAliveCountMax 2 \n Compression no\n MaxAuthTries 2 \nMaxSessions 2 \n TCPKeepAlive no \nUsePrivilegeSeparation SANDBOX \n AllowAgentForwarding no \n Banner /etc/issue.net")
        os.system(command='sudo service ssh restart')
    logging.info('SSHD |Added SSH config hardening')

def banner():
    with open("/etc/issue.net", "a") as issue:
        issue.write("""###############################################################
    #                                                      Welcome to Meastro's server                                                           # 
    #                                   All connections are monitored and recorded                                         #
    #                          Disconnect IMMEDIATELY if you are not an authorized user!                    #
    ###############################################################""")
    logging.info('issue.net | Add legal banner to /etc/issue.net, to warn unauthorized users [BANN-7130]')
    with open("/etc/motd", "a") as motd:
            motd.write("""###############################################################
    #                                                      Welcome to Meastro's server                                                           # 
    #                                   All connections are monitored and recorded                                         #
    #                          Disconnect IMMEDIATELY if you are not an authorized user!                    #
    ###############################################################""")
    logging.info('MOTD | Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126]')

def tools():
    try:
        os.system(command='sudo apt-get update && sudo apt-get upgrade && sudo apt-get dist-upgrade')
        logging.info('System updated')
    except:
        logging.critical('Could not update!')
    try:
        os.system(command='sudo apt-get install gi')
        logging.info('Git installed')
    except:
        logging.critical('Could not install git!')
    try:
        os.system(command='sudo apt-get install AIDE -y')
        logging.info('AIDE |Aide is installed! integrety')
    except:
        logging.critical('AIDE | could not install AIDE already installed?')
    try:
        os.system(command='sudo apt-get install acct -y')
        logging.info('[FINT-4350] |ACCT is installed! integrety')
    except:
        logging.critical('[FINT-4350] | could not install ACCT already installed?')
    try:
        os.system(command='sudo apt-get install auditd -y')
        logging.info('[ACCT-9628] | Enable auditd to collect audit information ')
    except:
        logging.critical('[ACCT-9628] | Could not install auditd!')
    try:
        os.system(command='sudo apt-get install rkhunter chkrootkit -y')
        logging.info('[ACCT-9628] | Anti maleware ')
    except:
        logging.critical('[ACCT-9628] | Could not install  Anti maleware!')

def cleanlog():
    logging.info('Remove temp files')
    try:
        logging.info('Remove temp files')
        os.system(command='sudo rm -r /tmp')
        os.system(command='sudo rm -r /var/tmp')
    except:
        logging.critical('Could not remove temp files')

def lynisupdate():
    os.system("cd /usr/local")
    os.system("git clone https://github.com/CISOfy/lynis")
    os.system("cd lynis")

def main():
    lynisupdate()
    tools()
    banner()
    hardenssh()
    cleanlog()

if __name__ == "__main__":
    # execute only if run as a script
    main()
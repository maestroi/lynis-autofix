import os
import sys
import logging
import platform
import time

## Logging stuff
logging.basicConfig(filename='hardening.log' ,format='%(asctime)s - %(name)s - %(levelname)s | %(message)s |', stream=sys.stdout, level=logging.INFO)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s | %(message)s |')
console.setFormatter(formatter)
logging.getLogger('').addHandler(console)

def hardenssh():
    with open("/etc/ssh/sshd_config", "a") as myfile:
        myfile.write("ClientAliveCountMax 2" + "\n" +
                     "Compression no" + "\n" +
                     "MaxAuthTries 2" + "\n" +
                     "MaxSessions 2" + "\n" +
                     "TCPKeepAlive no" + "\n" +
                     "UsePrivilegeSeparation SANDBOX" + "\n" +
                     "AllowAgentForwarding no" + "\n" +
                     "Banner /etc/issue.net")
    os.system('sudo service ssh restart')
    logging.info('SSHD |Added SSH config hardening')

def hardenkernel():
    with open("/etc/sysctl", "a") as myfile:
        myfile.write("fs.suid_dumpable  0" + "\n" +
                     "kernel.core_uses_pid 1" + "\n" +
                     "kernel.kptr_restrict 2" + "\n" +
                     "kernel.sysrq 0" + "\n" +
                     "net.ipv4.conf.all.forwarding 0" + "\n" +
                     "net.ipv4.conf.all.log_martians 1" + "\n" +
                     "net.ipv4.conf.all.send_redirects 0" + "\n" +
                     "net.ipv4.conf.default.log_martians 1" + "\n" +
                     "net.ipv4.tcp_syncookies 1" + "\n" +
                     "net.ipv4.tcp_timestamps")
    logging.info('Kernel |Kernel hardening added')

def banner():
    with open("/etc/issue.net", "a") as issue:
        issue.write("""###############################################################
    #                                                      Welcome to Meastro's server                                                           # 
    #                                   All connections are monitored and recorded                                         #
    #                          Disconnect IMMEDIATELY if you are not an authorized user!                    #
    ###############################################################""")
    logging.info('issue.net | Add legal banner to /etc/issue.net, to warn unauthorized users [BANN-7130]')
    with open("/etc/issue", "a") as issue:
        issue.write("""###############################################################
    #                                                      Welcome to Meastro's server                                                           # 
    #                                   All connections are monitored and recorded                                         #
    #                          Disconnect IMMEDIATELY if you are not an authorized user!                    #
    ###############################################################""")
    logging.info('issue | Add legal banner to /etc/issue, to warn unauthorized users [BANN-7130]')
    with open("/etc/motd", "a") as motd:
            motd.write("""###############################################################
    #                                                      Welcome to Meastro's server                                                           # 
    #                                   All connections are monitored and recorded                                         #
    #                          Disconnect IMMEDIATELY if you are not an authorized user!                    #
    ###############################################################""")
    logging.info('MOTD | Add a legal banner to /etc/issue, to warn unauthorized users [BANN-7126]')

def tools():
    try:
        logging.info('starting: system updated')
        os.system('sudo apt-get update -y > /dev/null 2>&1 && sudo apt-get upgrade -y > /dev/null 2>&1 && sudo apt-get dist-upgrade -y > /dev/null 2>&1')
        logging.info('System updated')
    except:
        logging.critical('Could not update!')
    time.sleep(2)
    try:
        os.system('sudo apt-get install git')
        logging.info('Git installed')
    except:
        logging.critical('Could not install git!')
    time.sleep(2)
    try:
        os.system('sudo apt-get install aide -y > /dev/null 2>&1')
        logging.info('aide |Aide is installed! integrety')
    except:
        logging.critical('aide | could not install aide already installed?')
    time.sleep(2)
    try:
        os.system('sudo apt-get install acct -y > /dev/null 2>&1')
        logging.info('[FINT-4350] |ACCT is installed! integrety')
    except:
        logging.critical('[FINT-4350] | could not install ACCT already installed?')
    time.sleep(2)
    try:
        os.system('sudo apt-get install auditd -y > /dev/null 2>&1')
        logging.info('[ACCT-9628] | Enable auditd to collect audit information ')
    except:
        logging.critical('[ACCT-9628] | Could not install auditd!')
    time.sleep(2)
    try:
        os.system('sudo apt-get install rkhunter chkrootkit -y > /dev/null 2>&1')
        logging.info('[ACCT-9628] | Anti maleware ')
    except:
        logging.critical('[ACCT-9628] | Could not install  Anti maleware!')
    time.sleep(2)
    try:
        os.system('sudo apt-get install libpam-cracklib -y > /dev/null 2>&1')
        logging.info('[AUTH-9262] | Cracklib ')
    except:
        logging.critical('[AUTH-9262] | Could not install Crackliv!')
    time.sleep(2)
    try:
        os.system('sudo apt-get install sysstat -y > /dev/null 2>&1')
        logging.info('[ACCT-9626] | Sysstat accounting data')
    except:
        logging.critical('[ACCT-9626] | Sysstat accounting data not installed!')
    time.sleep(2)
    try:
        os.system('sudo apt-get install arpwatch -y > /dev/null 2>&1')
        logging.info('NETW-3032 |ARP is installed! integrety')
    except:
        logging.critical('NETW-3032 | could not install ARP already installed?')
    time.sleep(2)
    try:
        os.system('sudo apt-get install debsums -y > /dev/null 2>&1')
        logging.info('NETW-3032 |ARP is installed! integrety')
    except:
        logging.critical('NETW-3032 | could not install debsums already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install debsecan -y > /dev/null 2>&1')
        logging.info('NETW-3032 |ARP is installed! integrety')
    except:
        logging.critical('NETW-3032 | could not install debsecan already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install ntpdate -y > /dev/null 2>&1')
        logging.info('NETW-3032 |ntpdate is installed!')
    except:
        logging.critical('NETW-3032 | could not install ntpdate already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install libpam-tmpdir -y > /dev/null 2>&1')
        logging.info('NETW-3032 |libpam-tmpdir is installed!')
    except:
        logging.critical('NETW-3032 | could not install libpam already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install sysstat -y > /dev/null 2>&1')
        logging.info('NETW-3032 |sysstat is installed!')
    except:
        logging.critical('NETW-3032 | could not install sysstat already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install apt-show-versions -y > /dev/null 2>&1')
        logging.info('NETW-3032 |Apt-show versions is installed!')
    except:
        logging.critical('NETW-3032 | could not install Apt-show versions already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install apt-listchanges -y > /dev/null 2>&1')
        logging.info('NETW-3032 |apt-listchanges versions is installed!')
    except:
        logging.critical('NETW-3032 | could not install Apt-show versions already installed')
    time.sleep(2)
    try:
        os.system('sudo apt-get install debian-goodies -y > /dev/null 2>&1')
        logging.info('NETW-3032 |debian-goodies is installed!')
    except:
        logging.critical('NETW-3032 | could not install debian-goodies versions already installed')





def apache():
    logging.info('Apache Hardening')
    try:
        logging.info('Apache Hardening: mod security')
        os.system('sudo apt-get install libapache2-mod-security2 -y > /dev/null 2>&1')
    except:
        logging.critical('Could not install mod security')
    time.sleep(2)
    try:
        logging.info('Apache Hardening: libapache2-mod-evasive')
        os.system('apt-get install libapache2-mod-evasive -y > /dev/null 2>&1')
    except:
        logging.critical('Could not install rule')
    time.sleep(2)
    try:
        logging.info('install rule')
        os.system('sudo sed -i "s/SecRuleEngine DetectionOnly/SecRuleEngine On/" /etc/modsecurity/modsecurity.conf')
    except:
        logging.critical('Could not install rule')






def cleanlog():
    logging.info('Remove temp files')
    try:
        logging.info('Remove temp files')
        os.system(command='sudo rm -r /tmp')
        os.system(command='sudo rm -r /var/tmp')
    except:
        logging.critical('Could not remove temp files')

def lynisupdate():
    if os.path.exists("/usr/local/lynis"):
        os.system("cd /usr/local")
        os.system("sudo git clone https://github.com/CISOfy/lynis.git")
    else:
        logging.critical('Could not download lynis')

def firewall():
    try:
        os.system("sudo apt-get install ufw")
        logging.info("installed UFW!")
    except:
        logging.info("Ufw already installed!")
    try:
        os.system("sudo ufw allow ssh")
        logging.info("Allowed SSH!")
    except:
        logging.info("SSH already allowed")
    try:
        os.system("sudo ufw enable")
        logging.info("UFW Enabled")
    except:
        logging.info("UFW Already enabled!")

def main():
    logging.info("Welcome to Hardening")
    logging.info("Running on %s version %s" %(platform.system(),platform.release()))
    logging.info("Testing..")
    lynisupdate()
    tools()
    banner()
    hardenssh()
    cleanlog()

if __name__ == "__main__":
    # execute only if run as a script
    user = os.getenv("SUDO_USER")
    if user is None:
        print("This program need 'sudo'")
        exit()
    main()
#!/bin/bash
clear
echo ------------------------
echo Setup script by meastro
echo ------------------------
echo
clean=clean.sh
ssh=ssh.sh
firewall=firewallsetup.sh
rootkit=rootkit.sh
echo ------------------------
echo Checking for clean script!
echo ------------------------
if [ -f $clean ]; then
    echo "$clean found!"
    echo "$clean updating.."
    rm $clean
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/clean.sh
    chmod 755 $clean
    echo "$clean newest version downloaded!"
else 
    echo "$clean does not exist"
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/clean.sh
    chmod 755 $clean
    echo "$clean new version downloaded!"
fi
echo ------------------------
echo Done checking clean script!
echo ------------------------
sleep 10
clear
echo ------------------------
echo Update and upgrade OS
echo ------------------------
update=1
if [ $update -eq 1 ]; then
    sudo apt-get update && sudo apt-get upgrade -y
    sudo apt-get autoremove && sudo apt-get autoclean -y
    update=2
fi
echo ------------------------
echo Update and upgrade Finished!
echo ------------------------
sleep 10
clear
echo ------------------------
echo ssh config
echo ------------------------
if [ -f $ssh ]; then
    echo "$ssh found!"
    rm $ssh
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/ssh.sh
    chmod 755 $ssh
    echo "$ssh newest version downloaded!"
else 
    echo "$ssh does not exist"
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/ssh.sh
    chmod 755 $ssh
    echo "$ssh new version downloaded!"
fi
echo ------------------------
echo ssh config done!
echo ------------------------
sleep 10
clear
echo ------------------------
echo Install and setup firewall
echo ------------------------
if [ -f $firewall ]; then
    echo "$firewall found!"
    rm $firewall
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/firewallsetup.sh
    chmod 755 $firewall
    echo "$firewall newest version downloaded!"
    ./$firewall
else 
    echo "$firewall does not exist"
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/firewallsetup.sh
    chmod 755 $firewall
    echo "$firewall new version downloaded!"
    ./$firewall
fi
echo ------------------------
echo Firewall installation and setup done!
echo ------------------------
sleep 10
clear
echo ------------------------
echo install anti rootkit
echo ------------------------
if [ -f $rootkit ]; then
    echo "$rootkit found!"
    rm $rootkit
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/rootkit.sh
    chmod 755 $rootkit
    echo "$rootkit newest version downloaded!"
else 
    echo "$rootkit does not exist"
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/rootkit.sh
    chmod 755 $rootkit
    echo "$rootkit new version downloaded!"
fi
echo ------------------------
echo anti rootkit script done!
echo ------------------------
sleep 10
clear
echo ------------------------
echo Setup script by meastro done! thank you for using!
echo ------------------------

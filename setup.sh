#!/bin/bash
echo ------------------------
echo Setup script by meastro
echo ------------------------
echo
echo ------------------------
echo checking for clean script!
echo ------------------------
clean=clean.sh
if [ -f $clean ]; then
    echo "$clean found!"
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
echo done checking clean script!
echo ------------------------
sleep 2
clear
echo ------------------------
echo update ubuntu
echo ------------------------

update=1
if [ $update -eq 1 ]; then
    sudo apt-get update && sudo apt-get upgrade -y
    update=2
fi

echo ------------------------
echo update finished
echo ------------------------
sleep 2
clear
echo ------------------------
echo install anti rootkit
echo ------------------------

if which rkhunter >/dev/null; then
    echo exists
else
    sudo apt-get install rkhunter chkrootkit -y
    echo installed!
fi

echo ------------------------
echo anti rootkit script done!
echo ------------------------

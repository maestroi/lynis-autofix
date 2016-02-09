echo ------------------------
echo setup rootkit
echo ------------------------
if which rkhunter >/dev/null; then
    echo already installed!
else
    sudo apt-get install rkhunter chkrootkit -y
    echo installed!
fi
echo ------------------------
echo setup rootkit done!
echo ------------------------
sleep 2
clear

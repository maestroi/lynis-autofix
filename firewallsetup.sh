echo ------------------------
echo setup firewall
echo ------------------------
sudo ufw allow ssh
echo port 22 SSH added
sudo ufw allow 1025
echo port 1025 new SSH added
sudo ufw allow 80/tcp
echo port 80 web added
sudo ufw allow 443/tcp
echo port 443 SSL added
echo Please, enter extra port
read port
ufw allow $port
echo $port added!
sudo ufw enable
echo ------------------------
echo setup firewall done!
echo ------------------------
sleep 2
clear

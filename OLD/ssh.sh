echo ------------------------
echo setup SSH
echo ------------------------
echo -n "do you need to setup ssh? [ENTER] y/n: "
read name
if  [ $name == 'y' ]; then
	wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/sshd_config
	sudo mv  sshd_config /etc/ssh/sshd_config
else
	echo "You are already setup ssh."
echo ------------------------
echo setup SSH done! please restart SSHdeamon service ssh restart 
echo ------------------------
sleep 2
clear

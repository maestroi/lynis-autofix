#!/bin/bash
echo ------------------------
echo clean script by meastro
echo ------------------------
setup=setup.sh
if [ -f $setup ]; then
	echo "$setup found!"
    rm $setup
    wget https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/setup.sh
    chmod 755 setup.sh
else 
    echo "$setup does not exist"
fi
echo ------------------------
echo clean script done
echo ------------------------

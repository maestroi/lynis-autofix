#!/bin/bash
@echo off
echo ------------------------
echo clean script by meastro
echo ------------------------
setup=setup.sh
if [ -f $setup ]; then
    echo "$setup found!"
    rm $setup
    wget –quiet https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/setup.sh
    chmod 755 setup.sh
    echo "$setup new version downloaded!"
else 
    echo "$setup does not exist"
fi
echo ------------------------
echo clean script done
echo ------------------------

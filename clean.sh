#!/bin/bash
@echo off
echo ------------------------
echo clean script by meastro
echo ------------------------
setup=setup.sh
if [ -f $setup ]; then
    echo "$setup found!"
    rm $setup
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/setup.sh
    chmod 755 $setup
    echo "$setup new version downloaded!"
else 
    echo "$setup does not exist"
    wget -q https://raw.githubusercontent.com/maestroi/Hardeningdebian/master/setup.sh
    chmod 755 $setup
    echo "$setup new version downloaded!"
fi
echo ------------------------
echo clean script done
echo ------------------------

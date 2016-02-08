#!/bin/bash
echo ------------------------
echo Setup script by meastro
echo ------------------------
setup = setup.sh
if [ ! -f /$setup ]; then
    echo "File not found!"
fi
echo sudo apt-get update && sudo apt-get upgrade -y
echo ------------------------
echo update finished
echo ------------------------

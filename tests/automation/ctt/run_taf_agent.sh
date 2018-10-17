#!/bin/bash
sudo apt-get update
sudo apt-get update --fix-missing 
sudo apt-get install libuv1.dev
sudo apt-get install libxml2-dev
sudo apt-get install xdotool

cp ../../../port/linux/discover_device .
cp ../../../port/linux/CertificationApp .

export LD_LIBRARY_PATH=/usr/local/lib


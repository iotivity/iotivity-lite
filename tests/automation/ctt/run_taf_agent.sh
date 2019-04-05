#!/bin/bash
sudo apt-get update
sudo apt-get update --fix-missing
sudo apt-get install libuv1.dev
sudo apt-get install libxml2-dev

killall -9 tafagent 
killall -9 CertificationApp
cd ../../../port/linux
make cleanall
make TCP=1 CLOUD=1
cd -
cp ../../../port/linux/discover_device .
cp ../../../port/linux/CertificationApp .

rm -rf CertificationApp_creds
mkdir CertificationApp_creds
#include system configured UV lib path
export LD_LIBRARY_PATH=/usr/local/lib
make
./tafagent client_config.txt 1 6 13 2.0.2 192.168.4.123 2 10 1 6 client

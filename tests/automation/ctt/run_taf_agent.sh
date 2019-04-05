#!/bin/bash
sudo apt-get update
sudo apt-get update --fix-missing
sudo apt-get install libuv1.dev
sudo apt-get install libxml2-dev

fuser -k 5000/tcp
fuser -k 5001/tcp
killall -9 tafagent
killall -9 CertificationApp

cd ../../../port/linux
make cleanall
make TCP=1 CLOUD=1 IDD=1 CREATE=1
cd -
cp ../../../port/linux/discover_device .
cp ../../../port/linux/CertificationApp .

rm -rf pki_certs
mkdir pki_certs
cd pki_certs
cp ../../../../port/linux/pki_certs/* .
cd -

rm -rf CertificationApp_creds
mkdir CertificationApp_creds
#include system configured UV lib path
export LD_LIBRARY_PATH=/usr/local/lib
make
./tafagent server_config.txt 1 6 13 2.0.5 192.168.3.227 2 7 server 1 6

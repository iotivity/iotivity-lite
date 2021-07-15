#!/bin/bash
echo `pwd`
cd ../port/linux
#make clean
#make clean
make CLOUD=1 CLIENT=1 PKI=1 SECURE=1 libiotivity-lite-client-python.so
cd  ../../python
#mkdir pki_certs
cp -r ../apps/pki_certs/. ./pki_certs
#!/bin/bash
echo `pwd`
cd ../port/linux
#make clean
make clean
#make OC_SO=1 SO_DPP=1 CLOUD=1 CLIENT=1 PKI=1 SECURE=1 libiotivity-lite-client-python.so
make DEBUG=1 CLIENT=1 PKI=1 SECURE=1 libiotivity-lite-client-python.so
cd  ../../web-obt
#mkdir pki_certs
cp -r ../apps/pki_certs/. ./pki_certs
#create web certs
cd obt_web
KEY="key.pem"
if [ ! -f "$KEY" ]; then
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
    -subj "/C=US/ST=RFOTM/L=Springfield/O=Dis/CN=www.example.com" \
    -keyout key.pem  -out cert.pem
fi
#Check for virtual environement
VENV="ocf"
if [ ! -d "$VENV" ]; then
	#create virtual environement
	echo "Create virtual environment"
	python3 -m venv ocf
fi
#check version of python, VENV check differs on 2.7 vs 3.X
version=$(python -V 2>&1 | grep -Po '(?<=Python )(.+)')
if [[ -z "$version" ]]
then
    echo "No Python!" 
    exit
fi
MAJOR_VERSION="${version:0:1}"
if [ $MAJOR_VERSION -lt 3 ];then
INVENV=$(python -c 'import sys; print ("1" if hasattr(sys, "real_prefix") else "0")')
else
INVENV=$(python -c 'import sys; print ("0" if sys.prefix == sys.base_prefix else "1")')
fi

#If building within venv
if [ 1 -eq $INVENV  ]; then
	#don't check for depnedancies every time.  
	REQUIREMENTS="requirements_met"
	if [ ! -f "$REQUIREMENTS" ]; then
		echo "Installing required packages"
		pip install -r requirements.txt
	fi
else
	REQUIREMENTS="requirements_met"
	if [ ! -f "$REQUIREMENTS" ]; then
		source ocf/bin/activate
		pip install -r requirements.txt
	fi
fi 
cd ..
SOF="libiotivity-lite-client-python.so"
if [ ! -f "$SOF" ]; then
	echo "Make sure to run the Web-OBT in a virtual environment"
	echo "Example: source obt_web/ocf/bin/activate"
fi



# Create python virtual environement

python3 -m venv ~/ocf

# Activate virtual environment

cd ~/ocf

source bin/activate


# Install pre-requisites

pip install -r requirements.txt

**_NOTE:_** for running the web page in secure mode
apt-get install openssl

# Build Shared Library

cd ~/iotivity/python

./build\_so.sh

# Runnning the OBT
 openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

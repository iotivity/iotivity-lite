

# Create python virtual environement

python3 -m venv ~/ocf

# Activate virtual environment

cd ~/ocf

source bin/activate


# Install pre-requisites

pip install -r requirements.txt

**_NOTE_** for running the web page in secure mode

apt-get install openssl

# Build Shared Library

cd ~/iotivity/python

./build\_so.sh

# Runnning the OBT
cd ~/iotivity-lite/python/obt_web/

openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365

python gen_app_secret.py

python obt_web.py

# View OBT Web
Open browser and got to the IP (localhost if you are running this locally)
port is 5000

https://IP:5000


# TODO

1. Check for OBT creds and do not start a new OBT every time
2. Clean up Javascript
3. Seperate Javascript into seperate file
4. Make all javascript local
5. OTM selection
6. ~~Resources dictionary is currently using the unowned uuid.  Needs to be the ownned UUID~~
7. Finish simple client
8. Finish ACL editing
9. ~~Implement threading events for resourcelist (need to wait until resources are populated)~~
10. ~~Fix duplicates in Device array~~



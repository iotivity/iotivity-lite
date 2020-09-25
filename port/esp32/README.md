This repository contains ESP32 simulator for linux.

# How does it work?

ESP-IDF contains small amount of hardware specific code, FreeRTOS and few
multi-platform libraries.

# Running

## Using ubuntu

```
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools cmake ninja-build ccache libffi-dev libssl-dev libusb-1.0-0
mkdir esp
cd esp
git clone -b release/v4.1 --recursive https://github.com/espressif/esp-idf.git
./esp-idf/install.sh
. ./esp-idf/export.sh
idf.py build
```

## Inside docker

```
docker build -t esp32-simulator .
docker run --cap-add=NET_ADMIN --device /dev/net/tun:/dev/net/tun --name esp32-simulator -v `pwd`:/root/simulator -d esp32-simulator

docker exec -i -t esp32-simulator bash
cd ~/simulator/example
idf.build
./build/example
```

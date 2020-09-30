ESP32

# Build

## ubuntu
```
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools cmake ninja-build ccache libffi-dev libssl-dev libusb-1.0-0
git clone --recursive https://github.com/espressif/esp-idf.git
./esp-idf/install.sh
. ./esp-idf/export.sh
idf.py set-target esp32
idf.py menuconfig // set wifi
idf.py build
idf.py -p (PORT) flash monitor
```

## windows
 - [install] (https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/windows-setup.html)
 - Please select master repository
 - Install CMake
 - Set PATH env to cmake, python
 - Run esp-idf commandline
 - cd iotivity-lite/port/esp32
 - ```
    idf.py set-target esp32
    idf.py menuconfig // set wifi
    idf.py build
    idf.py -p (PORT) flash monitor
   ```




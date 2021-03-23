# ESP32

## Get IoTivity-Lite

First, clone recursively IoTivity-Lite which includes a port for the ESP32.
```bash
git clone --recursive https://gitlab.iotivity.org/iotivity/iotivity-lite.git
```

## Build

### Ubuntu
```bash
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-setuptools \
 python3-serial python3-click python3-cryptography python3-future python3-pyparsing \
 python3-pyelftools cmake ninja-build ccache libffi-dev libssl-dev libusb-1.0-0

cd ./iotivity-lite/port/esp32
git clone https://github.com/espressif/esp-idf.git
(cd esp-idf && git checkout 457ce080aec9811faee26a1ea5293fff17049fee && git submodule init && git submodule update)
./esp-idf/install.sh
. ./esp-idf/export.sh
```

Jump to the [common steps](#common-steps) below.

### MacOS
```bash
cd ./iotivity-lite/port/esp32
git clone https://github.com/espressif/esp-idf.git
(cd esp-idf && git checkout 457ce080aec9811faee26a1ea5293fff17049fee && git submodule init && git submodule update)
./esp-idf/install.sh
. ./esp-idf/export.sh
```
> Note: `./esp-idf/export.sh` script exports invalid `IDF_PATH` value. Please modify it after export manually.

Jump to the [common steps](#common-steps) below.

### Windows

- [install] (https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/windows-setup.html)
- Please select master repository and install it to iotivity-lite/port/esp32/esp-idf
- Install CMake, Bash for find
- Set PATH env to cmake, python
- Run esp-idf commandline
- [CommonSteps](#common-steps)

### Common steps

```bash
idf.py set-target esp32
idf.py menuconfig // this will bring up a GUI where you need to set up wifi
( cd esp-idf/components/mbedtls/mbedtls && git am ../../../../patches/mbedtls/*.patch )
( cd esp-idf && find ../patches/esp-idf/ -type f -name '*.patch' -exec patch -p1 -i {} \; )
( cd esp-idf/components/lwip/lwip && find ../../../../patches/lwip/ -type f -name '*.patch' -exec patch -p1 -i {} \; )
idf.py build
idf.py -p (PORT) flash monitor
```
- Note: to erase the flash call `idf.py erase_flash`
- Note: When in monitor mode, you can use Ctrl + ] to break out (like Ctrl + C).

## Known issues
- after OCF ownership transfer and cloud onboard, only 50KB of heap is available; rebooting gives 130KB
- partition nvs must be resized (extended) because the storage store the data to the nvs
- when built with CLOUD=1, OC_DYNAMIC_ALLOCATION must be set as as well as OC_COLLECTIONS requires it
- max_app_data_size must be set to 6+KB otherwise credentials are not stored to the storage
- max_app_data_Size must be less then 8KB otherwise heap is exhausted during own and onboard
- compiler performance optimalization(-O2) must be set otherwise heap is exhausted during own and onboard
- to avoid exhausted heap, set CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN to same same size as max_app_data_size

## Performance over heap memory

| Setup | free heap size |
| --------- | ----------- |
| SECURE, TCP, IPV4, fresh | 166KB |
| SECURE, TCP, IPV4, just owned | 117KB |
| SECURE, TCP, IPV4, owned, rebooted | 159KB |
| SECURE, TCP, IPV4, just owned, onboarded to the cloud | 83KB |
| SECURE, TCP, IPV4, owned, onboarded to the cloud, rebooted | 141KB |

# ESP32

## Get IoTivity-Lite

First, clone recursively IoTivity-Lite which includes a port for the ESP32.

```bash
git clone --recursive https://github.com/iotivity/iotivity-lite.git
```

## Build

### Ubuntu

```bash
sudo apt install -y git wget flex bison gperf python3 python3-pip python3-setuptools \
 python3-serial python3-click python3-cryptography python3-future python3-pyparsing \
 python3-pyelftools cmake ninja-build ccache libffi-dev libssl-dev libusb-1.0-0
```

Jump to the [common steps](#common-steps) below.

### macOS

Jump to the [common steps](#common-steps) below.

### Windows

Install ubuntu via wsl2 and then run the Ubuntu bash in terminal:

```sh
wsl
```

And then create the file with /etc/wsl.conf in ubuntu bash with body:

```conf
[automount]
enabled = true
options = "metadata"
```

After that restart ubuntu from windows cmd line:

```sh
wsl --terminate Ubuntu-20.04
wsl
```

and install dependecies in ubuntu bash terminal:

```bash
sudo apt update
sudo apt-get -y install python3-pip cmake python3-venv
```

The last is to jump to the [common steps](#common-steps) below in the ubuntu bash.

### Common steps

For ESP32 v5.4 with mbedTLS v3.6.2:

```bash
cd ./iotivity-lite/port/esp32
git clone --recursive -b release/v5.4 https://github.com/espressif/esp-idf.git
# checkout latest commit with mbedTLS v3.6.2
( cd esp-idf && git checkout c8bb53292d08d6449a09823cf554e62ac839cd8c )
( cd esp-idf && git submodule update --init --recursive )
./esp-idf/install.sh
. ./esp-idf/export.sh
cp sdkconfig.3_6_2.defaults sdkconfig.defaults
idf.py set-target esp32
idf.py menuconfig # this will bring up a GUI where you need to set up wifi
( cd esp-idf/components/mbedtls/mbedtls && patch -p1 < ../../../../../../patches/mbedtls/3.6/01-ocf-anon-psk.patch )
( cd esp-idf/components/mbedtls/mbedtls && patch -p1 < ../../../../patches/mbedtls/3.6/02-ocf-mbedtls-config.patch )
( cd esp-idf/components/lwip/lwip && find ../../../../patches/lwip/ -type f -name '*.patch' -exec patch -p1 -i {} \; )
idf.py build
ESPBAUD=115200 idf.py flash monitor
```

For ESP32 v5.1 with mbedTLS v3.5.0:

```bash
cd ./iotivity-lite/port/esp32
git clone --recursive -b release/v5.1 https://github.com/espressif/esp-idf.git
# checkout latest commit with mbedTLS v3.5.0
( cd esp-idf && git checkout 7380f96017424c7be5d8e3229bf81ceb0869cc54 )
( cd esp-idf && git submodule update --init --recursive )
./esp-idf/install.sh
. ./esp-idf/export.sh
cp sdkconfig.3_5_0.defaults sdkconfig.defaults
idf.py set-target esp32
idf.py menuconfig # this will bring up a GUI where you need to set up wifi
( cd esp-idf/components/mbedtls/mbedtls && patch -p1 < ../../../../../../patches/mbedtls/3.5/01-ocf-anon-psk.patch )
( cd esp-idf/components/mbedtls/mbedtls && patch -p1 < ../../../../patches/mbedtls/3.5/02-ocf-mbedtls-config.patch )
( cd esp-idf/components/lwip/lwip && find ../../../../patches/lwip/ -type f -name '*.patch' -exec patch -p1 -i {} \; )
idf.py build
ESPBAUD=115200 idf.py flash monitor
```

- Note: to erase the flash call `ESPBAUD=115200 idf.py erase-flash`
- Note: When in monitor mode, you can use Ctrl + ] to break out (like Ctrl + C).

## Known issues

- after OCF ownership transfer and cloud onboard, only 50KB of heap is available; rebooting gives 130KB
- partition nvs must be resized (extended) because the storage store the data to the nvs
- when built with CLOUD=1, OC_DYNAMIC_ALLOCATION must be set as well as OC_COLLECTIONS requires it
- max_app_data_size must be set to 7+KB otherwise credentials are not stored to the storage
- compiler performance optimalization(-O2) must be set otherwise heap is exhausted during own and onboard
- to avoid exhausted heap, set CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN to the same size as max_app_data_size

## Performance over heap memory

| Setup | free heap size |
| --------- | ----------- |
| SECURE, TCP, IPV4, fresh | 164KB |
| SECURE, TCP, IPV4, just owned | 117KB |
| SECURE, TCP, IPV4, owned, rebooted | 159KB |
| SECURE, TCP, IPV4, just owned, onboarded to the cloud via TCP | 122KB |
| SECURE, TCP, IPV4, owned, onboarded to the cloud via TCP, rebooted | 135KB |
| SECURE, TCP, IPV4, just owned, onboarded to the cloud via DTLS | 123KB |
| SECURE, TCP, IPV4, owned, onboarded to the cloud via DTLS | 138KB |
| SECURE, IPV4, just owned, onboarded to the cloud via DTLS | 128KB |
| SECURE, IPV4, owned, onboarded to the cloud via DTLS | 144KB |

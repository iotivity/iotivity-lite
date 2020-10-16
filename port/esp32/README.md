ESP32

# Build

## Ubuntu
- sudo apt install -y git wget flex bison gperf python3 python3-pip python3-setuptools python3-serial python3-click python3-cryptography python3-future python3-pyparsing python3-pyelftools cmake ninja-build ccache libffi-dev libssl-dev libusb-1.0-0
 - cd port/esp32
 - git clone --recursive https://github.com/espressif/esp-idf.git 
 - ./esp-idf/install.sh
 - . ./esp-idf/export.sh
 - [CommonSteps](#common-steps)

## Windows
 - [install] (https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/windows-setup.html)
 - Please select master repository and install it to iotivity-lite/port/esp32/esp-idf
 - Install CMake
 - Set PATH env to cmake, python
 - Run esp-idf commandline
 - [CommonSteps](#common-steps)


## Common steps
- idf.py set-target esp32
- idf.py menuconfig // set wifi
- ( cd esp-idf/components/mbedtls/mbedtls && git am ../../../../patches/mbedtls/*.patch )
- ( cd esp-idf && find ../patches/esp-idf/ -type f -name '*.patch' -exec patch -p1 -i {} \; )
- ( cd esp-idf/components/lwip/lwip && find ../../../../patches/lwip/ -type f -name '*.patch' -exec patch -p1 -i {} \; )
- idf.py build
- idf.py -p (PORT) flash monitor

# Known issues
 - after own and onboard lot's of the heap is consumed (just 50KB are free). When the device was rebooted 130KB are free.
 - partition nvs must be resize (extended) because storage store data to nvs
 - when cloud is enabled OC_DYNAMIC_ALLOCATION must be set because OC_COLLECTIONS is not supported without OC_DYNAMIC_ALLOCATION
 - max_app_data_size must be set to 6+KB(otherwise credentials are not stored to the storage) and less then 8KB(otherwise esp aborts - heap is exhausted during own and onboard)
 - compiler performance optimalization(-O2) must be set otherwise heap is exhausted during own and onboard
 - set CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN to same same size as max_app_data_size because we want to avoid exhaust heap and more is not used.

# Performance over heap memory
| Setup | free heap size |
| --------- | ----------- | 
| SECURE, TCP, IPV4, fresh | 166KB |
| SECURE, TCP, IPV4, just owned | 117KB |
| SECURE, TCP, IPV4, owned, rebooted | 159KB |
| SECURE, TCP, IPV4, just owned, onboarded to the cloud | 83KB |
| SECURE, TCP, IPV4, owned, onboarded to the cloud, rebooted | 141KB |


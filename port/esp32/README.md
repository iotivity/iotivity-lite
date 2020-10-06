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
- idf.py menuconfig // set wifi, mbedtls
- ( cd esp-idf/components/mbedtls/mbedtls && git am ../../../../patches/mbedtls/*.patch )
- ( cd esp-idf && git am ../patches/esp-idf/*.patch )
- idf.py build
- idf.py -p (PORT) flash monitor

# Known issues
 - after own and onboard lot's of the heap is consumed (just 50KB are free). When the device was rebooted 130KB are free.
 - partition nvs must be resize (extended) because storage store data to nvs
 - when cloud is enabled OC_DYNAMIC_ALLOCATION must be set because OC_COLLECTIONS is not supported without OC_DYNAMIC_ALLOCATION
 - max_app_data_size must be set to 6+KB(otherwise credentials are not stored to the storage) and less then 8KB(otherwise esp aborts(heap is exhausted) during own and onboard)
 - compiler performance optimalization(-O2) must be set otherwise heap is exhausted during own and onboard

# Performance over heap memory
| Setup | free heap size |
| --------- | ----------- | 
| SECURE, TCP, IPV4, fresh | 170KB |
| SECURE, TCP, IPV4, just owned | 89KB |
| SECURE, TCP, IPV4, owned, rebooted | 162KB |
| SECURE, TCP, IPV4, just owned, onboarded to the cloud | 53KB / crash for exhausted heap |
| SECURE, TCP, IPV4, owned, rebooted, onboarded to the cloud | 134KB |


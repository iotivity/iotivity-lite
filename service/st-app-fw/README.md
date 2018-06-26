# Discription
...

# How to build

To build st-app-fw module, you need to locate right json file in 'json' folder. (only one json file can be accepted)
If json file is located in json folder properly, on build time it will converted CBOR formatted header file.
You can see that header file which name is 'st_device_def.h' in 'include' folder.
Also, raw data for CBOR converted value is st_device_def which is located in 'json' folder.
If you want to see that file is convert successfully, you can use below command to print that
value to hex. And you can convert to cbor formatted file to json in 'cbor.me'

    $ xxd -p st_device_def

# How to test
...
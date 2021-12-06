# Python bindings 

The python bindings are based on ctypes.
The python code is using the shared library containing an OCF device that can act as an OBT and client.
The python code uses the device to interact with other OCF devices on the network.

## limitations

Only tested on Linux based systems.

## Build Shared Library

run the following command from this folder:

```
./build\_so.sh
```

This command builds the shared library and copies the library to this folder.
Hence the python code can be used directly from this folder.

## Sending HTTP Requests to PLGD Server

When retrieving cloud configurations from the PLGD cloud server for the first time, the request headers inside plgd_headers.config needs to be modified, namely the "auth0" part of the cookie: 

    1. Go to the cloud webpage (e.g. https://cloud.cascoda.com/things), and log in if required; 
    2. Enable Network Monitor, by pressing F12 and click "Network"; 
    3. Click "+Device" -> Enter a random UUID -> Click "Get the Code"; 
    4. Inside Network Monitor, click on the first GET request (sent to auth.plgd.cloud);
    5. Inside Response Headers, find the set-cookie header that contains the "auth0" cookie;
    6. Copy the "auth0" cookie and replace the outdated one inside plgd_headers.config. 

Note that these steps only need to be done once - the python script can then automate the whole process. 
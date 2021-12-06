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

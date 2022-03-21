# Python bindings 

The python bindings are based on ctypes.
The python code is using the shared library containing an OCF device that can act as an OBT and client.
The python code uses the device to interact with other OCF devices on the network.

## limitations



## Build Shared Library on Linux

run the following command from this folder:

```
./build\_so.sh
```

This command builds the shared library and copies the library to this folder.
Hence the python code can be used directly from this folder.



## Build Shared Library on Windows for debugging

run the following command from the build directory in a git bash shell:

```bash
cmake .
```

Assuming the build directory has been configured correctly, this command ensures that the latest
version of the scripts are copied into the build dir. Since the scripts are copied at configure time,
you need to use this command whenever you want to test a change to the scripts, or you will see the
old behaviour instead.

```bash
start_shell.bat
```

This command opens a windows developer shell that knows all paths of visual studio.
in this shell issue the commands to build in this folder.

```bash
cmake -G"NMake Makefiles" .. 
nmake
```

This command builds the windows shared library.
Therefore the python code can be used directly from this folder.

```bash
python iotivity.py
```
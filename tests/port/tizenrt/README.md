##### clone TizenRT code from open source below mentioned link

git clone https://github.com/Samsung/TizenRT

Create folder "iotivity-constrained" in this path (TizenRT/external/) (EX:mkdir iotivity-constrained)

Clone iotivity-constrained code in this path TizenRT/external/iotivity-constrained/

switch to samsung branch (EX: git checkout samsung)

Copy iotivity-constrained/port/tizenrt/iotlite_apps folder to TizenRT/apps/

Copy iotivity-constrained/tests/port/tizenrt/configs/artik055/iotlite folder to TizenRT/build/configs/artik055/

Copy iotivity-constrained/tizenrt/scripts/Makefile and tizenrt/scripts/Make.defs to TizenRT/external/iotivity-constrained/

#### How to Build the TizenRT with constrained IOT  ####################


#### Configure the build from *$TIZENRT_BASEDIR/os/tools* directory

cd os/tools

 
#### To check the different board configurations combinations supported, type below:

./configure.sh --help

#### To configure the specific board.

./configure.sh <board>/<configuration_set>   (Example: ./configure.sh artik053/iotliteconfig )


#### After configuring above, configuration can be modified through *make menuconfig* from *$TIZENRT_BASEDIR/os*.

cd ..

make


#### Built binaries are in *$TIZENRT_BASEDIR/build/output/bin*.


#### How  to dumping the code to board. ########################

### connect the device to linux pc.
#### change the path to  *$TIZENRT_BASEDIR/os*.
#### example : make download ALL
#### make download [ALL | BOOTLOADER | RESOURCE | KERNEL | APP]

sudo make download ALL


##### How to run a sample apps ##################################

sudo cutecom

open the device.

#### press restart button.

wifi startsta
wifi join <ssid_name> ------  for wifi open mode 
ifconfig wl1 dhcp

###### run sample app ##########################

iotlite

###### run easysetup sample app ##########################

easysetup










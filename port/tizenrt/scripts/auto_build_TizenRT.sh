#!/bin/bash
#Iotivity-constrained build procedure on TizenRT

scripts_dir="$(pwd)"

echo $scripts_dir

os_dir=../../../../../../os/

echo $os_dir

constrained_dir=../../../

echo $constrained_dir

external=$os_dir../external

echo $external

apps=$os_dir../apps

echo $apps

echo "$os_dir"

cp -r ../iotlite_apps/ $apps

cp -r $constrained_dir/apps/st_app $apps/iotlite_apps/

cp -r $constrained_dir/apps/st_app/tizenrt/Make* $apps/iotlite_apps/st_app/

cp ./Makefile ../$constrained_dir

cp ./Make.defs ../$constrained_dir

cp -r $constrained_dir/apps/tizenrt/configs/artik053/iotlite/ $os_dir/../build/configs/artik053/

cd $os_dir; cd tools

./configure.sh a

echo "Please select the board: \n===================================== \n artik053 \n artik055s \n qemu"

read device

echo $device

echo "Please select the configuration: \n===================================== \n artik053 \n artik055s"

read config

echo $config

./configure.sh $device/$config;cd ..





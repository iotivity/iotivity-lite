#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile client java files
javac  -cp ../../iotivity-lite-java/libs/iotivity-lite.jar  -sourcepath ./src  -d ./bin  ./src/java_multi_device_server/*.java

# create jar file
jar -cfv multi-device-server.jar -C ./bin  .

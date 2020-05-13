#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile server java files
javac  -cp ../../iotivity-lite-java/libs/iotivity-lite.jar  -sourcepath ./src  -d ./bin  ./src/java_smart_home_server/*.java

# create jar file
jar -cfv smart-home-server.jar -C ./bin .  -C ./assets .

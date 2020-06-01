#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile server java files
javac  -cp ../../iotivity-lite-java/libs/iotivity-lite.jar  -sourcepath ./src  -d ./bin  ./src/java_dummy_bridge/*.java

# create jar file
jar -cfv dummy_bridge.jar -C ./bin  .

#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile client java files
javac  -cp ../../java_lang/iotivity-lite.jar  -sourcepath ./src  -d ./bin  ./src/java_lite_simple_client/*.java

# create jar file
jar -cfv simple-client-lite.jar -C ./bin  .

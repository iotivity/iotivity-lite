#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile server java files
javac  -cp ../../../java_lang/iotivity-lite.jar  -sourcepath ./src  -d ./bin  ./src/java_oc_onboarding_tool/*.java

# create jar file
jar -cfv onboarding-tool-lite.jar -C ./bin  .

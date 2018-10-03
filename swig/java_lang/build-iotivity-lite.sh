#!/bin/bash

# remove existing .class files
rm -rf ../iotivity-lite-eclipse-project/bin

# create .class files directory
mkdir ../iotivity-lite-eclipse-project/bin

# compile swig generated java files and custom java files
javac  -sourcepath ../iotivity-lite-eclipse-project/src  -d ../iotivity-lite-eclipse-project/bin  ../iotivity-lite-eclipse-project/src/org/iotivity/*.java

# create jar file
jar -cfv iotivity-lite.jar -C ../iotivity-lite-eclipse-project/bin  .

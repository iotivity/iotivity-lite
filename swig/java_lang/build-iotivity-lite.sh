#!/bin/bash

# remove existing .class files
rm -rf ../iotivity-lite-eclipse-project/bin

# create .class files directory
mkdir ../iotivity-lite-eclipse-project/bin

# compile swig generated java files
javac  -sourcepath ../iotivity-lite-eclipse-project/src  -d ../iotivity-lite-eclipse-project/bin  ../iotivity-lite-eclipse-project/src/org/iotivity/*.java

# compile custom java files and place them with the swig compiled files
javac  -cp ../iotivity-lite-eclipse-project/bin/  -sourcepath ../oc_java  -d ../iotivity-lite-eclipse-project/bin  ../oc_java/*.java

# create jar file
jar -cfv iotivity-lite.jar -C ../iotivity-lite-eclipse-project/bin  .

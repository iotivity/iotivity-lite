#!/bin/bash

# remove existing .class files
rm -rf ../iotivity-lite-eclipse-project/bin

# create .class files directory
mkdir ../iotivity-lite-eclipse-project/bin

# compile swig generated java files and custom java files
javac -source 1.7 -target 1.7 -sourcepath ../iotivity-lite-eclipse-project/src  -d ../iotivity-lite-eclipse-project/bin  ../iotivity-lite-eclipse-project/src/org/iotivity/*.java

# create jar file
jar -cfv iotivity-lite.jar -C ../iotivity-lite-eclipse-project/bin  .

# if building for Android, copy jar to Android libs directory
#cp -v iotivity-lite.jar ../apps/android_simple_server/SimpleServer/app/libs/iotivity-lite.jar
#cp -v iotivity-lite.jar ../apps/android_simple_client/SimpleClient/app/libs/iotivity-lite.jar


#!/bin/bash

# remove existing .class files
rm -rf ../iotivity-lite-java/bin

# create .class files directory
mkdir ../iotivity-lite-java/bin

# compile swig generated java files and custom java files
javac -source 1.7 -target 1.7 -sourcepath ../iotivity-lite-java/src  -d ../iotivity-lite-java/bin  ../iotivity-lite-java/src/org/iotivity/*.java ../iotivity-lite-java/src/org/iotivity/oc/*.java

# create jar file
jar -cfv ../iotivity-lite-java/libs/iotivity-lite.jar -C ../iotivity-lite-java/bin  .

# if building for Android, copy jar to Android libs directory
if [ "$#" -ge 1 ] && [ "$1" = "android" ]
then
  cp -v ../iotivity-lite-java/libs/iotivity-lite.jar ../apps/android_simple_server/SimpleServer/app/libs/iotivity-lite.jar
  cp -v ../iotivity-lite-java/libs/iotivity-lite.jar ../apps/android_simple_client/SimpleClient/app/libs/iotivity-lite.jar
  cp -v ../iotivity-lite-java/libs/iotivity-lite.jar ../apps/android_on_boarding_tool/OnBoardingTool/app/libs/iotivity-lite.jar

  cp -v ../iotivity-lite-java/libs/iotivity-lite.jar ../apps/oc/android_simple_server/SimpleServer/app/libs/iotivity-lite.jar
  cp -v ../iotivity-lite-java/libs/iotivity-lite.jar ../apps/oc/android_simple_client/SimpleClient/app/libs/iotivity-lite.jar
  cp -v ../iotivity-lite-java/libs/iotivity-lite.jar ../apps/oc/android_on_boarding_tool/OnBoardingTool/app/libs/iotivity-lite.jar
fi

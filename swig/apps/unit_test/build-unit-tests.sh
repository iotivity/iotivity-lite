#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile server java files
javac  -cp ../../iotivity-lite-java/libs/iotivity-lite.jar:$JUNIT4 -sourcepath ../../iotivity-lite-java/junit -d ./bin ../../iotivity-lite-java/junit/org/iotivity/*.java

# create jar file
jar -cfv iotivity-junit.jar -C ./bin .
#$HOME/junit/junit-4.13.jar
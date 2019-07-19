#!/bin/bash

# remove existing .class files
rm -rf ./bin

# create .class files directory
mkdir ./bin

# compile server java files
javac  -cp ../../iotivity-lite-java/libs/iotivity-lite.jar  -sourcepath ./src  -d ./bin  ./src/java_cloud_certification_tests/*.java

# create jar file
jar -cfv cloud-certification-tests.jar -C ./bin  .

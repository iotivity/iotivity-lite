#!/bin/bash

java -Djava.library.path=../../iotivity-lite-java/libs -cp iotivity-junit.jar:../../iotivity-lite-java/libs/iotivity-lite.jar:$JUNIT4:$HAMCREST_CORE org.iotivity.TestRunner

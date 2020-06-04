#!/bin/bash

java -Djava.library.path=../../../iotivity-lite-java/libs -cp oc_dummy_bridge.jar:../../../iotivity-lite-java/libs/iotivity-lite.jar java_oc_dummy_bridge.DummyBridge

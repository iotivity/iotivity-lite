#!/bin/bash

java -Djava.library.path=../../iotivity-lite-java/libs -cp dummy_bridge.jar:../../iotivity-lite-java/libs/iotivity-lite.jar java_dummy_bridge.DummyBridgeMain

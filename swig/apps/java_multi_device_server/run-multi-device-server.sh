#!/bin/bash

java -Djava.library.path=../../iotivity-lite-java/libs -cp multi-device-server.jar:../../iotivity-lite-java/libs/iotivity-lite.jar java_multi_device_server.Server

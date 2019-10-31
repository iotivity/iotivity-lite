#!/bin/bash

java -Djava.library.path=../../../iotivity-lite-java/libs -cp simple-media-server.jar:../../../iotivity-lite-java/libs/iotivity-lite.jar java_oc_simple_media_server.Server

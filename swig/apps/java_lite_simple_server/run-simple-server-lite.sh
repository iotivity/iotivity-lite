#!/bin/bash

java -Djava.library.path=../../java_lang -cp simple-server-lite.jar:../../java_lang/iotivity-lite.jar java_lite_simple_server.Server

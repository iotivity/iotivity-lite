#!/bin/bash

java -Djava.library.path=../../../iotivity-lite-java/libs -cp channel-change-client.jar:../../../iotivity-lite-java/libs/iotivity-lite.jar java_oc_channel_change_client.Client

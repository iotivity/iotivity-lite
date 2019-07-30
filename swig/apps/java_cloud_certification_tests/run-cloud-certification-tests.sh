#!/bin/bash

java -Djava.library.path=../../iotivity-lite-java/libs -cp cloud-certification-tests.jar:../../iotivity-lite-java/libs/iotivity-lite.jar java_cloud_certification_tests.CloudCertTestsMain

#!/bin/sh

echo "This script assumes that Java source has already been built from SWIG interface files."
rm -fr ../iotivity-lite-java/docs
javadoc -sourcepath ../iotivity-lite-java/src -d ../iotivity-lite-java/docs -subpackages org.iotivity org.iotivity.oc
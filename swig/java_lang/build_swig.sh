#!/bin/sh

rm *.c
rm *.cxx
rm ../iotivity-lite-eclipse-project/src/org/iotivity/*.java

swig -c++ -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../include/ ../swig_interfaces/oc_api.i
swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../port/ ../swig_interfaces/oc_clock.i
#swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ ../swig_interfaces/oc_ri.i
swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../port/ ../swig_interfaces/oc_storage.i

cp ../oc_java/*.java ../iotivity-lite-eclipse-project/src/org/iotivity/
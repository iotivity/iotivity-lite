#!/bin/sh

swig -c++ -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_api.i
#swig -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_base64.i
swig -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_clock.i
#swig -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_collection.i
#swig -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_rep.i
#swig -c++ -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_resource.i
#swig -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_ri.i
swig -java -package org.iotivity -outcurrentdir ../swig_interfaces/oc_storage.i

cp ../oc_java/*.java .

rm ../iotivity-lite-eclipse-project/src/org/iotivity/*.java
cp *.java ../iotivity-lite-eclipse-project/src/org/iotivity
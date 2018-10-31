#!/bin/sh

rm *.c
rm *.cxx
rm ../iotivity-lite-eclipse-project/src/org/iotivity/*.java

swig -c++ -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../include/ ../swig_interfaces/oc_api.i

if [ "$#" -ge 1 ] && [ "$1" = "linux" ]
then
  echo Building wrapper for linux clock
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../port/ -o oc_clock_wrap.c ../swig_interfaces/oc_clock_linux.i
elif [ "$#" -ge 1 ] && [ "$1" = "android" ]
then
  echo Building wrapper for android clock
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../port/ -o oc_clock_wrap.c ../swig_interfaces/oc_clock_android.i
else
  echo Building wrapper for windows clock
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../port/ ../swig_interfaces/oc_clock.i
fi

#swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ ../swig_interfaces/oc_ri.i
swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-eclipse-project/src/org/iotivity/ -I../../port/ ../swig_interfaces/oc_storage.i

cp ../oc_java/*.java ../iotivity-lite-eclipse-project/src/org/iotivity/
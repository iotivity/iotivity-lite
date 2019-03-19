#!/bin/sh

rm *.c
#rm *.cxx
rm ../iotivity-lite-java/src/org/iotivity/*.java
rm ../iotivity-lite-java/src/org/iotivity/oc/*.java

swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ ../swig_interfaces/oc_obt.i

swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ ../swig_interfaces/oc_uuid.i

swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ ../swig_interfaces/oc_collection.i

if [ "$#" -ge 1 ] && [ "$1" = "linux" ]
then
  echo Building wrapper for linux clock
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/linux ../swig_interfaces/oc_api.i
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -D__linux__ -I../.. -I../../port/linux -o oc_clock_wrap.c ../swig_interfaces/oc_clock.i
elif [ "$#" -ge 1 ] && [ "$1" = "android" ]
then
  echo Building wrapper for android clock
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/android ../swig_interfaces/oc_api.i
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -D__linux__ -I../.. -I../../port/android -o oc_clock_wrap.c ../swig_interfaces/oc_clock.i
else
  echo Building wrapper for windows clock
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/windows ../swig_interfaces/oc_api.i
  swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../port/windows ../swig_interfaces/oc_clock.i
fi

#swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ ../swig_interfaces/oc_ri.i
swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../port/ ../swig_interfaces/oc_storage.i

#swig -java -package org.iotivity -outcurrentdir -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../security/ ../swig_interfaces/oc_acl.i

cp ../oc_java/*.java ../iotivity-lite-java/src/org/iotivity/
mkdir -p ../iotivity-lite-java/src/org/iotivity/oc/
cp ../oc_java/oc/*.java ../iotivity-lite-java/src/org/iotivity/oc/

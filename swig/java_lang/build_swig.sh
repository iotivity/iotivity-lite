#!/bin/sh

#rm *.c
#rm *.cxx
rm ../iotivity-lite-java/jni/*.h
rm ../iotivity-lite-java/jni/*.c
rm ../iotivity-lite-java/src/org/iotivity/*.java
rm ../iotivity-lite-java/src/org/iotivity/oc/*.java

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_uuid_wrap.c ../swig_interfaces/oc_uuid.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_collection_wrap.c ../swig_interfaces/oc_collection.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -o ../iotivity-lite-java/jni/oc_connectivity_wrap.c ../swig_interfaces/oc_connectivity.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_endpoint_wrap.c ../swig_interfaces/oc_endpoint.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_pki_wrap.c ../swig_interfaces/oc_pki.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_rep_wrap.c ../swig_interfaces/oc_rep.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_buffer_settings_wrap.c ../swig_interfaces/oc_buffer_settings.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_core_res_wrap.c ../swig_interfaces/oc_core_res.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_cloud_wrap.c ../swig_interfaces/oc_cloud.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_session_events_wrap.c ../swig_interfaces/oc_session_events.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../include/ -o ../iotivity-lite-java/jni/oc_introspection_wrap.c ../swig_interfaces/oc_introspection.i

swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -DOC_PKI -I../../include/ -o ../iotivity-lite-java/jni/oc_cred_wrap.c ../swig_interfaces/oc_cred.i

if [ "$#" -ge 1 ] && [ "$1" = "linux" ]
then
  echo Building wrapper for linux clock
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/linux -o ../iotivity-lite-java/jni/oc_obt_wrap.c ../swig_interfaces/oc_obt.i
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/linux -o ../iotivity-lite-java/jni/oc_api_wrap.c ../swig_interfaces/oc_api.i
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -D__linux__ -I../.. -I../../port/linux -o ../iotivity-lite-java/jni/oc_clock_wrap.c ../swig_interfaces/oc_clock.i
elif [ "$#" -ge 1 ] && [ "$1" = "android" ]
then
  echo Building wrapper for android clock
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/android -o ../iotivity-lite-java/jni/oc_obt_wrap.c ../swig_interfaces/oc_obt.i
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/android -o ../iotivity-lite-java/jni/oc_api_wrap.c ../swig_interfaces/oc_api.i
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -D__linux__ -I../.. -I../../port/android -o ../iotivity-lite-java/jni/oc_clock_wrap.c ../swig_interfaces/oc_clock.i
else
  echo Building wrapper for windows clock
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/windows -o ../iotivity-lite-java/jni/oc_obt_wrap.c ../swig_interfaces/oc_obt.i
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../.. -I../../include/ -I../../port/windows -o ../iotivity-lite-java/jni/oc_api_wrap.c ../swig_interfaces/oc_api.i
  swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -D_WIN32 -I../.. -I../../port/windows -o ../iotivity-lite-java/jni/oc_clock_wrap.c ../swig_interfaces/oc_clock.i
fi

#swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -o ../iotivity-lite-java/jni/oc_ri_wrap.c ../swig_interfaces/oc_ri.i
swig -java -package org.iotivity -outdir ../iotivity-lite-java/src/org/iotivity/ -I../../port/ -o ../iotivity-lite-java/jni/oc_storage_wrap.c  ../swig_interfaces/oc_storage.i

cp *.h ../iotivity-lite-java/jni/
cp *.c ../iotivity-lite-java/jni/
cp ../oc_java/*.java ../iotivity-lite-java/src/org/iotivity/
mkdir -p ../iotivity-lite-java/src/org/iotivity/oc/
cp ../oc_java/oc/*.java ../iotivity-lite-java/src/org/iotivity/oc/

/* File oc_obt.i */
%module OCUuid
%include "typemaps.i"
%include "iotivity.swg"

%pragma(java) jniclasscode=%{
  static {
    try {
        System.loadLibrary("iotivity-lite-jni");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}

%{
#include "oc_uuid.h"

%}

%rename(OCUuidType) oc_uuid_t;
%rename(stringToUuid) oc_str_to_uuid;
%rename(uuidToString) oc_uuid_to_str;
%rename(generateUuid) oc_gen_uuid;
%include oc_uuid.h
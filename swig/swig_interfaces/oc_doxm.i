/* File oc_doxm.i */
%module OCDoxm

%include "iotivity.swg"
%import "oc_uuid.i"

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
#include "oc_iotivity_lite_jni.h"

#include "security/oc_doxm.h"
%}

%rename(OCOxmType) oc_sec_oxmtype_t;
%rename(OCSecurityDoxm) oc_sec_doxm_t;

%ignore oc_sec_doxm_init;
%ignore oc_sec_doxm_free;
%ignore oc_sec_decode_doxm;
%ignore oc_sec_encode_doxm;
%rename(getOwnDoxm) oc_sec_get_doxm;
%ignore oc_sec_doxm_default;
%ignore get_doxm;
%ignore post_doxm;

%include "oc_doxm.h"
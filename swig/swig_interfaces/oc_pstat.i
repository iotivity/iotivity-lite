/* File oc_pstat.i */
%module OCPstat

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

#include "security/oc_pstat.h"
%}

%rename(OCDosType) oc_dostype_t;
%rename(OCSecurityPstat) oc_sec_pstat_t;

%ignore oc_sec_pstat_init;
%ignore oc_sec_pstat_free;
%ignore oc_sec_is_operational;
%ignore oc_sec_decode_pstat;
%ignore oc_sec_encode_pstat;
%rename(getOwnPstat) oc_sec_get_pstat;
%ignore oc_sec_pstat_default;
%ignore get_pstat;
%ignore post_pstat;
%rename(reset) oc_sec_reset;

%include "oc_pstat.h"
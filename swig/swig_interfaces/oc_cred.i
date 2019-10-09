/* File oc_cred.i */
%module OCCredUtil
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
#include "oc_iotivity_lite_jni.h"

#include "oc_cred.h"
%}

%rename(OCCredType) oc_sec_credtype_t;
%rename(OCCredUsage) oc_sec_credusage_t;
%rename(OCEncoding) oc_sec_encoding_t;
%rename(OCCredData) oc_cred_data_t;
%rename(OCCred) oc_sec_cred_t;
%rename(OCCredRole) oc_sec_cred_t_role;

%rename(OCCreds) oc_sec_creds_t;

%rename(readCredusage) oc_cred_read_credusage;
%rename(readEncoding) oc_cred_read_encoding;
%apply oc_string_t *INPUT { oc_string_t *credusage_string };
%rename(parseCredusage) oc_cred_parse_credusage;
%apply oc_string_t *INPUT { oc_string_t *encoding_string };
%rename(parseEncoding) oc_cred_parse_encoding;
%rename(credTypeString) oc_cred_credtype_string;

%include "oc_cred.h"
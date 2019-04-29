/* File oc_cred.i */
%module OCCred

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

#include "security/oc_cred.h"
%}

%rename(OCCredType) oc_sec_credtype_t;
%rename(OCCredUsage) oc_sec_credusage_t;
%rename(OCEncoding) oc_sec_encoding_t;
%rename(OCCredData) oc_cred_data_t;
%rename(OCCredRole) oc_sec_cred_t_role;
%rename(OCSecurityCred) oc_sec_cred_t;
%ignore oc_sec_creds_t;
%ignore oc_tls_peer_t;


%ignore oc_sec_add_new_cred;
%ignore oc_sec_cred_init;
%ignore oc_sec_cred_free;
%ignore oc_sec_cred_default;
%ignore oc_sec_encode_cred;
%ignore oc_sec_decode_cred;
%rename(removeSubject) oc_cred_remove_subject;
%rename(removeCred) oc_sec_remove_cred;
%rename(findCredsForSubject) oc_sec_find_creds_for_subject;
%rename(findCred) oc_sec_find_cred;
%rename(findRoleCred) oc_sec_find_role_cred;
%ignore oc_sec_get_creds;
%rename(getCredById) oc_sec_get_cred_by_credid;
%ignore oc_sec_allocate_cred;
%ignore put_cred;
%ignore post_cred;
%ignore get_cred;
%ignore delete_cred;

%include "oc_cred.h"

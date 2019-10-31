/* File oc_cred.i */
%module OCCredUtil
%include "typemaps.i"
%include "iotivity.swg"
%include "enums.swg"
%javaconst(1);

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

#include "oc_cred.h"
%}

%rename(OCCredType) oc_sec_credtype_t;
%rename(OCCredUsage) oc_sec_credusage_t;
%rename(OCEncoding) oc_sec_encoding_t;
%rename(OCCredData) oc_cred_data_t;
%rename(OCCred) oc_sec_cred_t;
%ignore role;
%ignore oc_sec_cred_t_role;
%inline %{
typedef struct role role;
%}
%rename(privateData) oc_sec_cred_t::privatedata;
// OC_PKI only data
%ignore oc_sec_cred_t::publicdata;
%ignore oc_sec_cred_t::credusage;
%ignore oc_sec_cred_t::chain;
%ignore oc_sec_cred_t::child;
%ignore oc_sec_cred_t::ctx;
// end OC_PKI only data
%rename(credId) credid;
%rename(credType) oc_sec_cred_t::credtype;
%rename(subjectUuid) subjectuuid;
%rename(ownerCred) oc_sec_cred_t::owner_cred;
%extend oc_sec_cred_t {
  oc_string_t getRole() {
    return self->role.role;
  }

  oc_string_t getAuthority() {
    return self->role.authority;
  }

  oc_cred_data_t *getPublicData() {
#ifdef OC_PKI
    return &(self->publicdata);
#else
    return NULL;
#endif /* OC_PKI */
  }

  oc_sec_credusage_t getCredUsage() {
#ifdef OC_PKI
    return self->credusage;
#else
    return OC_CREDUSAGE_NULL;
#endif /* OC_PKI */
  }

  struct oc_sec_cred_t *getChain() {
#ifdef OC_PKI
    return self->chain;
#else
    return NULL;
#endif /* OC_PKI */
  }

  struct oc_sec_cred_t *getChild() {
#ifdef OC_PKI
  return self->child;
#else
  return NULL;
#endif /* OC_PKI */
  }
}

%rename(OCCreds) oc_sec_creds_t;
%ignore oc_sec_creds_t::OC_LIST_STRUCT(creds);
%extend oc_sec_creds_t {
  oc_sec_cred_t *getCredsListHead() {
    return oc_list_head(self->creds);
  }
}

%rename(readCredusage) oc_cred_read_credusage;
%rename(readEncoding) oc_cred_read_encoding;
%apply oc_string_t *INPUT { oc_string_t *credusage_string };
%rename(parseCredusage) oc_cred_parse_credusage;
%apply oc_string_t *INPUT { oc_string_t *encoding_string };
%rename(parseEncoding) oc_cred_parse_encoding;
%rename(credTypeString) oc_cred_credtype_string;

%include "oc_cred.h"
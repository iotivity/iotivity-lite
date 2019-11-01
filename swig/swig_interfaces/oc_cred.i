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

%ignore oc_cred_read_credusage;
%rename(readCredUsage) jni_cred_read_credusage;
%inline %{
const char * jni_cred_read_credusage(oc_sec_credusage_t credusage)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  const char *return_value = oc_cred_read_credusage(credusage);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning \"None\" as default.", __func__);
  const char *return_value = "None";
#endif /* OC_SECURITY and OC_PKI */
  return return_value;
}
%}

%ignore oc_cred_read_encoding;
%rename(readEncoding) jni_cred_read_encoding;
%inline %{
const char *jni_cred_read_encoding(oc_sec_encoding_t encoding)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  const char *return_value = oc_cred_read_encoding(encoding);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning \"Unknown\" as default.", __func__);
  const char *return_value = "Unknown";
#endif /* OC_SECURITY */
  return return_value;
}
%}

%apply oc_string_t *INPUT { oc_string_t *credusageString };
%ignore oc_cred_parse_credusage;
%rename(parseCredUsage) jni_cred_parse_credusage;
%inline %{
oc_sec_credusage_t jni_cred_parse_credusage(oc_string_t *credusageString)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_sec_credusage_t return_value = oc_cred_parse_credusage(credusageString);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning OC_CREDUSAGE_NULL(0) as default.", __func__);
  oc_sec_credusage_t return_value = OC_CREDUSAGE_NULL;
#endif /* OC_SECURITY and OC_PKI */
  return return_value;
}
%}

%apply oc_string_t *INPUT { oc_string_t *encodingString };
%ignore oc_cred_parse_encoding;
%rename(parseEncoding) jni_cred_parse_encoding;
%inline %{
oc_sec_encoding_t jni_cred_parse_encoding(oc_string_t *encodingString)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_sec_encoding_t return_value = oc_cred_parse_encoding(encodingString);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning OC_ENCODING_UNSUPPORTED(0) as default.", __func__);
  oc_sec_encoding_t return_value = OC_ENCODING_UNSUPPORTED;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_cred_credtype_string;
%rename(credTypeString) jni_cred_credtype_string;
%inline %{
const char *jni_cred_credtype_string(oc_sec_credtype_t credType)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  const char *return_value = oc_cred_credtype_string(credType);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning \"Unknown\" as default.", __func__);
  const char *return_value = "Unknown";
#endif /* OC_SECURITY */
  return return_value;
}
%}

%include "oc_cred.h"
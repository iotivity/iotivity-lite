/* File oc_pki.i */
%module OCPki

%include "stdint.i"

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
#include "oc_pki.h"
%}

%ignore oc_sp_types_t;

%apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *cert, size_t cert_size) };
%apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *key, size_t key_size) };

%ignore oc_pki_add_mfg_cert;
%rename (addMfgCert) jni_pki_add_mfg_cert;
%inline %{
int jni_pki_add_mfg_cert(size_t device, const unsigned char *cert,
                        size_t cert_size, const unsigned char *key,
                        size_t key_size)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  return oc_pki_add_mfg_cert(device, cert, cert_size, key, key_size);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  return -1;
#endif /* OC_SECURITY && OC_PKI */
}
%}
%ignore oc_pki_add_mfg_intermediate_cert;
%rename (addMfgIntermediateCert) jni_pki_add_mfg_intermediate_cert;
%inline %{
int jni_pki_add_mfg_intermediate_cert(size_t device, int credid,
                                     const unsigned char *cert,
                                     size_t cert_size)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  return oc_pki_add_mfg_intermediate_cert(device, credid, cert, cert_size);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  return -1;
#endif /* OC_SECURITY && OC_PKI */
}
%}
%ignore oc_pki_add_mfg_trust_anchor;
%rename (addMfgTrustAnchor) jni_pki_add_mfg_trust_anchor;
%inline %{
int jni_pki_add_mfg_trust_anchor(size_t device, const unsigned char *cert,
                                size_t cert_size)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  return oc_pki_add_mfg_trust_anchor(device, cert, cert_size);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  return -1;
#endif /* OC_SECURITY && OC_PKI */
}
%}
%ignore oc_pki_add_trust_anchor;
%rename (addTrustAnchor) jni_pki_add_trust_anchor;
%inline %{
int jni_pki_add_trust_anchor(size_t device, const unsigned char *cert,
                             size_t cert_size)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  return oc_pki_add_trust_anchor(device, cert, cert_size);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  return -1;
#endif /* OC_SECURITY && OC_PKI */
}
%}
%ignore oc_pki_set_security_profile;
%rename (setSecurityProfile) jni_pki_set_security_profile;
%inline %{
void jni_pki_set_security_profile(size_t device,
                                  oc_sp_types_t supported_profiles,
                                  oc_sp_types_t current_profile, int mfg_credid)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_pki_set_security_profile(device, supported_profiles, current_profile, mfg_credid);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI.", __func__);
#endif /* OC_SECURITY && OC_PKI */
}
%}

%include "oc_pki.h"
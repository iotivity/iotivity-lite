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

%rename (OCSpTypesMask) oc_sp_types_t;

%apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *cert, size_t cert_size) };
%apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *key, size_t key_size) };

%rename (addMfgCert) oc_pki_add_mfg_cert;
%rename (addMfgIntermediateCert) oc_pki_add_mfg_intermediate_cert;
%rename (addMfgTrustAnchor) oc_pki_add_mfg_trust_anchor;
%rename (addTrustAnchor) oc_pki_add_trust_anchor;
%rename (setSecurityProfile) oc_pki_set_security_profile;


%include "oc_pki.h"
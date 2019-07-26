/* File oc_storage.i */
%module OCStorage
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
#include "port/oc_storage.h"
#include "port/oc_log.h"
#include <assert.h>

%}

#if defined(SWIGJAVA) 

%typemap(in)     (uint8_t *BYTE, size_t LENGTH) {  
$1 = (uint8_t*) JCALL2(GetByteArrayElements, jenv, $input, 0); 
$2 = (size_t)    JCALL1(GetArrayLength,       jenv, $input); 
} 
%typemap(jni)    (uint8_t *BYTE, size_t LENGTH) "jbyteArray" 
%typemap(jtype)  (uint8_t *BYTE, size_t LENGTH) "byte[]" 
%typemap(jstype) (uint8_t *BYTE, size_t LENGTH) "byte[]" 
%typemap(javain) (uint8_t *BYTE, size_t LENGTH) "$javainput" 

/* Specify signature of method to handle */ 
%apply (uint8_t *BYTE, size_t LENGTH)   { (uint8_t *buf, size_t size) }; 

#else 
%apply (uint8_t *BYTE, size_t LENGTH) { (uint8_t *buf, size_t size) }; 
#endif 

%rename (storageConfig) jni_storage_config;
%inline %{
int jni_storage_config(const char *store) {
#ifdef OC_SECURITY
    OC_DBG("JNI: %s with path %s\n", __func__, store);
    return oc_storage_config(store);
#else
    OC_DBG("JNI: OC_SECURITY disabled ignoring %s with path %s\n", __func__, store);
    return 0;
#endif /* OC_SECURITY */
}
%}
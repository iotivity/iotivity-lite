/* File oc_introspection.i */
%module OCIntrospection

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
#include "oc_introspection.h"
#include "oc_log.h"
%}

/* C build flag OC_IDD_API has to be included when building */
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
%apply (uint8_t *BYTE, size_t LENGTH)   { (uint8_t *IDD, size_t IDD_size) }; 

#else 
%apply (uint8_t *BYTE, size_t LENGTH) { (uint8_t *IDD, size_t IDD_size) }; 
#endif 
 
 %ignore oc_set_introspection_data;
 %rename (setIntrospectionData) jni_set_introspection_data;
 %inline %{
void jni_set_introspection_data(size_t device, uint8_t *IDD, size_t IDD_size){
// due to the Introspection code using oc_storage both OC_SECURITY and OC_IDD_API
// must be defined to use oc_set_introspection_file function.
#if defined(OC_SECURITY) && defined(OC_IDD_API)
    oc_set_introspection_data(device, IDD, IDD_size);
#else
    OC_DBG("JNI: OC_SECURITY or OC_IDD_API disabled setIntrospectionFile ignored");
#endif
 }
 %}

%include "oc_introspection.h"
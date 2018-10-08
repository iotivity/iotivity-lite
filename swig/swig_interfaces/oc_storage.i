/* File oc_storage.i */
%module OCStorage
%include "typemaps.i"
%{
#include "oc_storage.h"

int swig_oc_storage_config(const char *store) {
#ifdef OC_SECURITY
    return oc_storage_config(store);
#else
    return 0;
#endif /* OC_SECURITY */
}

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

%rename (storage_config) swig_oc_storage_config;
int swig_oc_storage_config(const char *store);
/*
%rename (storage_read) oc_storage_read;
long oc_storage_read(const char *store, uint8_t *buf, size_t size);

%rename (storage_write) oc_storage_write;
long oc_storage_write(const char *store, uint8_t *buf, size_t size);
*/
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
%}

/* C build flag OC_IDD_FILE has to be included when building */
%ignore oc_set_introspection_file;
%rename(setIntrospectionFile) jni_set_introspection_file;
%inline %{
void jni_set_introspection_file(size_t device, const char *filename) {
// due to the Introspection code using oc_storage both OC_SECURITY and OC_IDD_FILE
// must be defined to use oc_set_introspection_file function.
#ifdef OC_SECURITY && OC_IDD_FILE
    oc_set_introspection_file(device, filename);
#else
    OC_DBG("JNI: OC_SECURITY or OC_IDD_FILE disabled setIntrospectionFile ignored");
#endif
}
%}
%ignore oc_create_introspection_resource;

%include "oc_introspection.h"
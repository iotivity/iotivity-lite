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
%rename(setIntrospectionFile) oc_set_introspection_file;
%ignore oc_create_introspection_resource;

%include "oc_introspection.h"
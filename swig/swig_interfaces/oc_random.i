/* file oc_random.i */
%module OCRandom

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
#include "port/oc_random.h"
%}

%rename (init) oc_random_init;
%rename (randomValue) oc_random_value;
%rename (destroy) oc_random_destroy;

%include "port/oc_random.h"
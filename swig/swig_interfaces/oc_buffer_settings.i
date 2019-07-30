/* File oc_buffer_settings.i */
%module OCBufferSettings

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
#include "oc_buffer_settings.h"
%}

%rename (setMtuSize) oc_set_mtu_size;
%rename (getMtuSize) oc_get_mtu_size;
%rename (setMaxAppDataSize) oc_set_max_app_data_size;
%rename (getMaxAppDataSize) oc_get_max_app_data_size;
%rename (getBlockSize) oc_get_block_size;

%include "oc_buffer_settings.h"
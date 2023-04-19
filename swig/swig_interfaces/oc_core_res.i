/* file oc_core_res.i */
%module OCCoreRes

%include "iotivity.swg"

%import "oc_uuid.i"
%import "oc_rep.i"
%import "oc_ri.i"

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

#include "oc_core_res.h"
%}

%rename (OCPlatformInfo) oc_platform_info_t;
%ignore oc_platform_info_t::init_platform_cb;
%ignore oc_platform_info_t::data;

%rename (OCDeviceInfo) oc_device_info_t;
%ignore oc_device_info_t::add_device_cb;
%ignore oc_device_info_t::data;

%rename (init) oc_core_init;
%rename (shutdown) oc_core_shutdown;
%rename (getNumDevices) oc_core_get_num_devices;
%rename (getDeviceId) oc_core_get_device_id;
%rename (getDeviceInfo) oc_core_get_device_info;
%rename (getPlatformInfo) oc_core_get_platform_info;
%rename (encodeInterfacesMask) oc_core_encode_interfaces_mask;
%rename (getResourceByIndex) oc_core_get_resource_by_index;
%rename (getResourceByUri) oc_core_get_resource_by_uri;
/* TODO get oc_store_uri working */
%ignore oc_store_uri;
//%rename (storeUri) oc_store_uri;
/* TODO get oc_core_populate_resource working */
%ignore oc_core_populate_resource;
//%rename (populateResource) oc_core_populate_resource;
%rename (filterResourceByRt) oc_filter_resource_by_rt;
%rename (isDCR) oc_core_is_DCR;

#define OC_NONNULL(...)
%include "oc_core_res.h"

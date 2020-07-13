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

/* Code and typemaps for mapping the oc_core_init_platform to the java OCCoreInitPlatformHandler */
%{
void jni_oc_core_init_platform_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  assert(cls_OCCoreInitPlatformHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCCoreInitPlatformHandler,
                                       "handler",
                                       "()V");
  assert(mid_handler);
  JCALL2(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler);

if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }
}
%}
%typemap(jni)    oc_core_init_platform_cb_t init_cb "jobject";
%typemap(jtype)  oc_core_init_platform_cb_t init_cb "OCCoreInitPlatformHandler";
%typemap(jstype) oc_core_init_platform_cb_t init_cb "OCCoreInitPlatformHandler";
%typemap(javain) oc_core_init_platform_cb_t init_cb "$javainput";

%typemap(in,numinputs=1) (oc_core_init_platform_cb_t init_cb, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_TILL_SHUTDOWN;
  jni_list_add(user_data);
  $1 = jni_oc_core_init_platform_callback;
  $2 = user_data;
}
%ignore oc_core_init_platform;
/* the oc_init_platform without the callback or data pointer */
%rename(initPlatform) jni_core_init_platform;
%inline %{
oc_platform_info_t * jni_core_init_platform(const char *mfg_name) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_core_init_platform(mfg_name, NULL, NULL);
}
%}
%rename(initPlatform) jni_core_init_platform1;
%inline %{
oc_platform_info_t * jni_core_init_platform1(const char *mfg_name, oc_core_init_platform_cb_t init_cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_core_init_platform(mfg_name, init_cb, jcb);
}
%}

/* Code and typemaps for mapping the oc_add_device to the java OCCoreAddDeviceHandler */
%{
void jni_oc_core_add_device_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  assert(cls_OCCoreAddDeviceHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCCoreAddDeviceHandler,
                                       "handler",
                                       "()V");
  assert(mid_handler);
  JCALL2(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }
}
%}
%typemap(jni)    oc_core_add_device_cb_t add_device_cb "jobject";
%typemap(jtype)  oc_core_add_device_cb_t add_device_cb "OCCoreAddDeviceHandler";
%typemap(jstype) oc_core_add_device_cb_t add_device_cb "OCCoreAddDeviceHandler";
%typemap(javain) oc_core_add_device_cb_t add_device_cb "$javainput";
%typemap(in,numinputs=1) (oc_core_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_TILL_SHUTDOWN;
  jni_list_add(user_data);
  $1 = jni_oc_core_add_device_callback;
  $2 = user_data;
}
%ignore oc_core_add_new_device;
%rename(OCCoreAddNewDevice) jni_oc_core_add_new_device0;
%inline %{
oc_device_info_t * jni_oc_core_add_new_device0(const char *uri, const char *rt,
                               const char *name,
                               const char *spec_version,
                               const char *data_model_version) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_core_add_new_device(uri, rt, name, spec_version, data_model_version, NULL, NULL);
}
%}
%rename(OCCoreAddNewDevice) jni_oc_core_add_new_device1;
%inline %{
oc_device_info_t * jni_oc_core_add_new_device1(const char *uri, const char *rt,
                               const char *name,
                               const char *spec_version,
                               const char *data_model_version,
                               oc_core_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_core_add_new_device(uri, rt, name, spec_version, data_model_version, add_device_cb, jcb);
}
%}

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

%include "oc_core_res.h"

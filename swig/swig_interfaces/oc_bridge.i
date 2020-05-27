/* File oc_bridge.i */
%module OCBridge

%include "iotivity.swg"

%import "oc_api.i"

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

#include "oc_bridge.h"
%}

%rename (OCVirtualDevice) oc_virtual_device_t;


%ignore oc_bridge_add_bridge_device;
%rename(addBridgeDevice) jni_bridge_add_bridge_device;
%inline %{
int jni_bridge_add_bridge_device(const char *name, const char *spec_version,
                                const char *data_model_version) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_bridge_add_bridge_device(name, spec_version, data_model_version, NULL, NULL);
}
%}

%rename(addBridgeDevice) jni_bridge_add_bridge_device1;
%inline %{
int jni_bridge_add_bridge_device1(const char *name, const char *spec_version,
                                const char *data_model_version,
                                oc_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_bridge_add_bridge_device(name, spec_version, data_model_version, add_device_cb, jcb);
}
%}


%typemap(in)     (uint8_t *BYTE, size_t LENGTH) {
$1 = (uint8_t*) JCALL2(GetByteArrayElements, jenv, $input, 0);
$2 = (size_t)    JCALL1(GetArrayLength,       jenv, $input);
}
%typemap(jni)    (uint8_t *BYTE, size_t LENGTH) "jbyteArray"
%typemap(jtype)  (uint8_t *BYTE, size_t LENGTH) "byte[]"
%typemap(jstype) (uint8_t *BYTE, size_t LENGTH) "byte[]"
%typemap(javain) (uint8_t *BYTE, size_t LENGTH) "$javainput"

/* Specify signature of method to handle */ 
%apply (uint8_t *BYTE, size_t LENGTH)   { (const uint8_t *virtual_device_id, size_t virtual_device_id_size) };

%ignore oc_bridge_add_virtual_device;

%rename (addVirtualDevice) jni_bridge_add_virtual_device;
%inline %{
size_t jni_bridge_add_virtual_device(
  const uint8_t *virtual_device_id, size_t virtual_device_id_size,
  const char *econame, const char *uri, const char *rt, const char *name,
  const char *spec_version, const char *data_model_version){
  return oc_bridge_add_virtual_device1(virtual_device_id, virtual_device_id_size,
                                       econame, uri, rt, name, spec_version,
                                       data_model_version, NULL, NULL);

}
%}

%rename (addVirtualDevice) jni_bridge_add_virtual_device1;
%inline %{
size_t jni_bridge_add_virtual_device1(
  const uint8_t *virtual_device_id, size_t virtual_device_id_size,
  const char *econame, const char *uri, const char *rt, const char *name,
  const char *spec_version, const char *data_model_version,
  oc_add_device_cb_t add_device_cb,  jni_callback_data *jcb){
  return oc_bridge_add_virtual_device1(virtual_device_id, virtual_device_id_size,
                                       econame, uri, rt, name, spec_version,
                                       data_model_version, add_device_cb, jcb);

}
%}
%rename (removeVirtualDevice) oc_bridge_remove_virtual_device;

%rename (deleteVirtualDevice) oc_bridge_delete_virtual_device;

%rename (getVirtualDeviceIndex) oc_bridge_get_virtual_device_index;

%rename (getVirtualDeviceInfo)  oc_bridge_get_virtual_device_info;

%include "oc_bridge.h"
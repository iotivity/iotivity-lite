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


%typemap(jstype) uint8_t *v_id "byte[]"
%typemap(jtype) uint8_t *v_id "byte[]"
%typemap(jni) uint8_t *v_id "jbyteArray"
%typemap(javaout) uint8_t *v_id {
  return $jnicall;
}
%typemap(out) uint8_t *v_id {
  if($1 != NULL) {
    $result = JCALL1(NewByteArray, jenv, (jsize)arg1->v_id_size);
    JCALL4(SetByteArrayRegion, jenv, $result, 0, (jsize)arg1->v_id_size, (const jbyte *)$1);
  } else {
    $result = NULL;
  }
}
%typemap(javain) int8_t *v_id "$javainput"
%typemap(in) int8_t *v_id (int8_t *v_id, size_t v_id_size) {
  jbyte *jid = JCALL2(GetByteArrayElements, jenv, $input, 0);
  //jsize jid_size = JCALL1(GetArrayLength, jenv, $input);
  // TODO if jid_size != v_id_size throw exception
  memcpy(temp, jid, arg1->v_id_size);
  $1 = temp;
  JCALL3(ReleaseByteArrayElements, jenv, $input, jid, 0);
}

%nodefaultctor oc_virtual_device_t;
%nodefaultdtor oc_virtual_device_t;
%rename (OCVirtualDevice) oc_virtual_device_t;
%ignore oc_virtual_device_t::v_id_size;
%immutable oc_virtual_device_t::v_id;
%rename (id) oc_virtual_device_t::v_id;
%immutable oc_virtual_device_t::econame;
%immutable oc_virtual_device_t::index;

// DOCUMENTATION workaround
%javamethodmodifiers jni_bridge_add_bridge_device "/**
   * Add an 'oic.d.bridge' device.
   * <p>
   * The 'oic.r.vodlist' resource will be registered to the bridge device.
   * <p>
   * @param name the user readable name of the device
   * @param spec_version The version of the OCF Server.
   *                       This is the 'icv' device property
   * @param data_model_version Spec version of the resource and device
   *                               specifications to which this device data model
   *                               is implemented. This is the 'dmv' device
   *                               property
   * @return 0 on success, -1 on failure
   */
  public";
%ignore oc_bridge_add_bridge_device;
%rename(addBridgeDevice) jni_bridge_add_bridge_device;
%inline %{
int jni_bridge_add_bridge_device(const char *name, const char *spec_version,
                                const char *data_model_version) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_bridge_add_bridge_device(name, spec_version, data_model_version, NULL, NULL);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_bridge_add_bridge_device1 "/**
   * Add an 'oic.d.bridge' device.
   * <p>
   * The 'oic.r.vodlist' resource will be registered to the bridge device.
   * <p>
   * @param name the user readable name of the device
   * @param spec_version The version of the OCF Server.
   *                       This is the 'icv' device property
   * @param data_model_version Spec version of the resource and device
   *                               specifications to which this device data model
   *                               is implemented. This is the 'dmv' device
   *                               property
   * @param add_device_cb callback function invoked during oc_add_device().
   *                          The purpose is to add additional device properties
   *                          that are not supplied to
   *                          oc_bridge_add_bridge_device() function call.
   *
   * @return 
   *   - `0` on success<br>
   *   - `-1` on failure
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_bridge_add_virtual_device "/**
   * Add a virtual ocf device to the the stack.
   * <p>
   * This function is called to add a newly discovered non-ocf device to a bridge
   * device. This will typically be called in response to the non-ocf devices
   * discovery mechanism.
   * <p>
   * The <tt>OCBridge.addVirtualDevice()</tt> function may be called as many
   * times as needed.  Each call will add a new device to the stack with its
   * own port address. Each device is automatically assigned a device index
   * number. Unlike the <tt>OCBridge.addDevice()</tt> function this number is not
   * incremented by one but assigned an index number based on avalibility.  The
   * index assigned to the virtual device will be returned from the function
   * call. The function <tt>OCBridge.getVirtualDeviceIndex()</tt> can also
   * be used to get the logical device index number after this function call.
   *
   * The function `OCBridge.addBridgeDevice()` must be called before this
   * function.
   *
   * @param virtual_device_id a unique identifier that identifies the virtual
   *                          device this could be a UUID, serial number or other
   *                          means of uniquely identifying the device
   * @param econame ecosystem name of the bridged device which is exposed by this
   *                virtual device
   * @param uri the The device URI.  The wellknown default URI '/oic/d' is hosted
   *            by every server. Used to device specific information.
   * @param rt the resource type
   * @param name the user readable name of the device
   * @param spec_version The version of the OCF Server.  This is the 'icv' device
   *                     property
   * @param data_model_version Spec version of the resource and device
   *                           specifications to which this device data model is
   *                           implemented. This is the 'dmv' device property
   *
   * @return
   *   - the logical index of the virtual device on success<br>
   *   - `0` on failure since a bridge device is required to add virtual devices
   *         a zero index cannot be assigned to a virtual device.
   */
  public";
%ignore oc_bridge_add_virtual_device;
%rename (addVirtualDevice) jni_bridge_add_virtual_device;
%inline %{
size_t jni_bridge_add_virtual_device(
  const uint8_t *virtual_device_id, size_t virtual_device_id_size,
  const char *econame, const char *uri, const char *rt, const char *name,
  const char *spec_version, const char *data_model_version){
  return oc_bridge_add_virtual_device(virtual_device_id, virtual_device_id_size,
                                       econame, uri, rt, name, spec_version,
                                       data_model_version, NULL, NULL);

}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_bridge_add_virtual_device1 "/**
   * Add a virtual ocf device to the the stack.
   * <p>
   * This function is called to add a newly discovered non-ocf device to a bridge
   * device. This will typically be called in response to the non-ocf devices
   * discovery mechanism.
   * <p>
   * The <tt>OCBridge.addVirtualDevice()</tt> function may be called as many
   * times as needed.  Each call will add a new device to the stack with its
   * own port address. Each device is automatically assigned a device index
   * number. Unlike the <tt>OCBridge.addDevice()</tt> function this number is not
   * incremented by one but assigned an index number based on avalibility.  The
   * index assigned to the virtual device will be returned from the function
   * call. The function <tt>OCBridge.getVirtualDeviceIndex()</tt> can also
   * be used to get the logical device index number after this function call.
   *
   * The function `OCBridge.addBridgeDevice()` must be called before this
   * function.
   *
   * @param virtual_device_id a unique identifier that identifies the virtual
   *                          device this could be a UUID, serial number or other
   *                          means of uniquely identifying the device
   * @param econame ecosystem name of the bridged device which is exposed by this
   *                virtual device
   * @param uri the The device URI.  The wellknown default URI '/oic/d' is hosted
   *            by every server. Used to device specific information.
   * @param rt the resource type
   * @param name the user readable name of the device
   * @param spec_version The version of the OCF Server.  This is the 'icv' device
   *                     property
   * @param data_model_version Spec version of the resource and device
   *                           specifications to which this device data model is
   *                           implemtned. This is the 'dmv' device property
   * @param add_device_cb callback function invoked during oc_add_device(). The
   *                      purpose is to add additional device properties that are
   *                      not supplied to oc_add_device() function call.
   *
   * @return
   *   - the logical index of the virtual device on success<br>
   *   - `0` on failure since a bridge device is required to add virtual devices
   *         a zero index cannot be assigned to a virtual device.
   */
  public";
%rename (addVirtualDevice) jni_bridge_add_virtual_device1;
%inline %{
size_t jni_bridge_add_virtual_device1(
  const uint8_t *virtual_device_id, size_t virtual_device_id_size,
  const char *econame, const char *uri, const char *rt, const char *name,
  const char *spec_version, const char *data_model_version,
  oc_add_device_cb_t add_device_cb,  jni_callback_data *jcb){
  return oc_bridge_add_virtual_device(virtual_device_id, virtual_device_id_size,
                                       econame, uri, rt, name, spec_version,
                                       data_model_version, add_device_cb, jcb);

}
%}

// DOCUMENTATION workaround
%javamethodmodifiers oc_bridge_remove_virtual_device "/**
   * If the non-ocf device is no longer reachable this can be used to remove
   * the virtual device from the bridge device.
   * <p>
   * This will shutdown network connectivity for the device and will update
   * the vodslist resource found on the bridge.
   * <p>
   * Any persistant settings will remain unchanged.  If the virtual device
   * has already been onboarded and permission settings have been modified when
   * the device is added again using <tt>OCBridge.addVirtualDevice</tt> those
   * persistant settings will still be in place.
   *
   * @param device_index the index of the virtual device
   *
   * @return
   *   - `0` on success<br>
   *   - `-1` on failure
   */
  public";
%rename (removeVirtualDevice) oc_bridge_remove_virtual_device;

// DOCUMENTATION workaround
%javamethodmodifiers oc_bridge_delete_virtual_device "/**
   * This will remove the virtual device and free memory associated with that
   * device.
   * <p>
   * Delete virtual device will remove all persistant settings. If the virtual
   * device is added again the onboarding and device permissions will need to be
   * setup as if the device were a new device.
   *
   * @param device_index index of the virtual device
   *
   * @return
   *   - `0` on success<br>
   *   - `-1` on failure
   */
  public";
%rename (deleteVirtualDevice) oc_bridge_delete_virtual_device;

// DOCUMENTATION workaround
%javamethodmodifiers oc_bridge_get_virtual_device_index "/**
   * Get the logical device index for the virtual device
   * <p>
   * @param virtual_device_id a unique identifier that identifies the virtual
   *                          device this could be a UUID, serial number or other
   *                          means of uniquely identifying the device
   * @param econame ecosystem name of the bridged virtual device
   *
   * @return
   *   - the logical index of the virtual device on success<br>
   *   - `0` on failure since a bridge device is required to add virtual devices
   *         a zero index cannot be assigned to a virtual device.
   */
  public";
%rename (getVirtualDeviceIndex) oc_bridge_get_virtual_device_index;

// DOCUMENTATION workaround
%javamethodmodifiers oc_bridge_get_virtual_device_info "/**
   * Use the device index of the virtual device to look up the virtual device
   * info.
   * <p>
   * @param virtual_device_index the logical index of the virtual device
   *
   * @return
   *    - an OCVirtualDevice upon success<br>
   *    - NULL if no virtual device was found using the provided index
   */
  public";
%rename (getVirtualDeviceInfo)  oc_bridge_get_virtual_device_info;

%include "oc_bridge.h"
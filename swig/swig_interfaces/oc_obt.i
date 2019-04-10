/* File oc_obt.i */
%module OCObt
%include "typemaps.i"
%include "iotivity.swg"

%import "oc_uuid.i"
// include not importe oc_acl.i it only exposes structs and enums so no need to build it separate.
%include "oc_acl.i"

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

#include "oc_obt.h"
%}


/* a little remapping trick to force saving a pointer to the JavaVM */
%typemap(in, numinputs=0) void* dummy {
  JCALL1(GetJavaVM, jenv, &jvm);
}

%rename(init) oc_obt_init;
%rename(shutdown) oc_obt_shutdown;

/* code and typemaps for mapping the oc_obt_discover_cb to the java OCObtDiscoveryHandler */
%{
extern jclass cls_OCObtDiscoveryHandler;
extern jclass cls_OCObtDeviceStatusHandler;
extern jclass cls_OCObtStatusHandler;
extern jclass cls_OCEndpoint;
extern jclass cls_OCUuid;

static void jni_obt_discovery_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  assert(user_data);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCObtDiscoveryHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCObtDiscoveryHandler,
        "handler",
        "(Lorg/iotivity/OCUuid;Lorg/iotivity/OCEndpoint;)V");
  assert(mid_handler);

  assert(cls_OCUuid);
  const jmethodID mid_OCUuid_init = JCALL3(GetMethodID, (data->jenv), cls_OCUuid, "<init>", "(JZ)V");
  assert(mid_OCUuid_init);

  assert(cls_OCEndpoint);
  const jmethodID mid_OCEndpoint_init = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCEndpoint,
        "<init>",
        "(JZ)V");
  assert(mid_OCEndpoint_init);

  /* make copy of uuid that will be owned by Java code */
  oc_uuid_t *juuid = malloc(sizeof(oc_uuid_t));
  memcpy(juuid->id, uuid->id, 16);

  JCALL4(CallVoidMethod,
        (data->jenv),
        data->jcb_obj,
        mid_handler,
        JCALL4(NewObject, (data->jenv), cls_OCUuid, mid_OCUuid_init, (jlong)juuid, true),
        JCALL4(NewObject, (data->jenv), cls_OCEndpoint, mid_OCEndpoint_init, (jlong)eps, false));

  ReleaseJNIEnv(getEnvResult);
}
%}

%ignore oc_obt_discovery_cb_t;
%typemap(jni)    oc_obt_discovery_cb_t callback "jobject";
%typemap(jtype)  oc_obt_discovery_cb_t callback "OCObtDiscoveryHandler";
%typemap(jstype) oc_obt_discovery_cb_t callback "OCObtDiscoveryHandler";
%typemap(javain) oc_obt_discovery_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
  $1 = jni_obt_discovery_cb;
  $2 = user_data;
}

%ignore oc_obt_discover_unowned_devices;
%rename(discoverUnownedDevices) jni_oc_obt_discover_unowned_devices;
%inline %{
int jni_oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_unowned_devices(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_obt_discover_owned_devices;
%rename(discoverOwnedDevices) jni_oc_obt_discover_owned_devices;
%inline %{
int jni_oc_obt_discover_owned_devices(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_owned_devices(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

/* code and typemaps for mapping the oc_obt_device_status_cb_t to the java OCObtDeviceStatusHandler */
%{
static void jni_obt_device_status_cb(oc_uuid_t *uuid, int status, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCObtDeviceStatusHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCObtDeviceStatusHandler,
        "handler",
        "(Lorg/iotivity/OCUuid;I)V");
  assert(mid_handler);

  assert(cls_OCUuid);
  const jmethodID mid_OCUuid_init = JCALL3(GetMethodID, (data->jenv), cls_OCUuid, "<init>", "(JZ)V");
  assert(mid_OCUuid_init);

  /* make copy of uuid that will be owned by Java code */
  oc_uuid_t *juuid = malloc(sizeof(oc_uuid_t));
  memcpy(juuid->id, uuid->id, 16);

  JCALL4(CallVoidMethod,
        (data->jenv),
        data->jcb_obj,
        mid_handler,
        JCALL4(NewObject, (data->jenv), cls_OCUuid, mid_OCUuid_init, (jlong)juuid, true),
        (jint) status);

  ReleaseJNIEnv(getEnvResult);
}
%}

%ignore oc_obt_device_status_cb_t;
%typemap(jni)    oc_obt_device_status_cb_t callback "jobject";
%typemap(jtype)  oc_obt_device_status_cb_t callback "OCObtDeviceStatusHandler";
%typemap(jstype) oc_obt_device_status_cb_t callback "OCObtDeviceStatusHandler";
%typemap(javain) oc_obt_device_status_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
  $1 = jni_obt_device_status_cb;
  $2 = user_data;
}

%ignore oc_obt_perform_just_works_otm;
%rename(performJustWorksOtm) jni_obt_perform_just_works_otm;
%inline %{
int jni_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_perform_just_works_otm(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_obt_request_random_pin;
%rename(requestRandomPin) jni_obt_request_random_pin;
%inline %{
int jni_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_request_random_pin(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}


/* For oc_obt_perform_random_pin_otm use Java String as the pin input.
   Use the Java String length to input the pin_len */
%typemap(in,numinputs=1) (const char *pin, size_t pin_len)
{
  $1 = ($1_type)JCALL2(GetStringUTFChars, jenv, $input, 0);
  $2 = ($2_type)JCALL1(GetStringUTFLength, jenv, $input);
}
%typemap(freearg,numinputs=1) (const char *pin, size_t pin_len)
{
  JCALL2(ReleaseStringUTFChars, jenv, $input, $1);
}


%ignore oc_obt_perform_random_pin_otm;
%rename(performRandomPinOtm) jni_obt_perform_random_pin_otm;
%inline %{
int jni_obt_perform_random_pin_otm(oc_uuid_t *uuid, const char *pin, size_t pin_len,
                                   oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_perform_random_pin_otm(uuid, (const unsigned char*)pin, pin_len, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_obt_device_hard_reset;
%rename(deviceHardReset) jni_obt_device_hard_reset;
%inline %{
int jni_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_device_hard_reset(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

/* code and typemaps for mapping the oc_obt_device_status_cb_t to the java OCObtDeviceStatusHandler */
%{
static void jni_obt_status_cb(int status, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCObtStatusHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCObtStatusHandler,
        "handler",
        "(I)V");
  assert(mid_handler);

  JCALL3(CallVoidMethod,
        (data->jenv),
        data->jcb_obj,
        mid_handler,
        (jint) status);

  ReleaseJNIEnv(getEnvResult);
}
%}

%ignore oc_obt_status_cb_t;
%typemap(jni)    oc_obt_status_cb_t callback "jobject";
%typemap(jtype)  oc_obt_status_cb_t callback "OCObtStatusHandler";
%typemap(jstype) oc_obt_status_cb_t callback "OCObtStatusHandler";
%typemap(javain) oc_obt_status_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
  $1 = jni_obt_status_cb;
  $2 = user_data;
}

%ignore oc_obt_provision_pairwise_credentials;
%rename(provisionPairwiseCredentials) jni_obt_provision_pairwise_credentials;
%inline %{
int jni_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2, oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_pairwise_credentials(uuid1, uuid2, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%rename(newAceForSubject) oc_obt_new_ace_for_subject;
%rename(newAceForConnection) oc_obt_new_ace_for_connection;
%rename(aceNewResource) oc_obt_ace_new_resource;
%rename(aceResourceSetHref) oc_obt_ace_resource_set_href;
%rename(aceResourceSetNumRt) oc_obt_ace_resource_set_num_rt;
%rename(aceResourceBindRt) oc_obt_ace_resource_bind_rt;
%rename(aceResourceBindIf) oc_obt_ace_resource_bind_if;
%rename(aceResourceSetWc) oc_obt_ace_resource_set_wc;
%rename(aceAddPermission) oc_obt_ace_add_permission;
%ignore oc_obt_provision_ace;
%rename(provisionAce) jni_obt_provision_ace;
%inline %{
int jni_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_ace(subject, ace, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}
%rename(freeAce) oc_obt_free_ace;

%include "oc_obt.h";
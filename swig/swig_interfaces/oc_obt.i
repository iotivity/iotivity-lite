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
#include "oc_obt.h"
%}


/* a little remapping trick to force saving a pointer to the JavaVM */
%typemap(in, numinputs=0) void* dummy {
  JCALL1(GetJavaVM, jenv, &jvm);
}

%ignore oc_obt_init;
%rename(init) jni_obt_init;
%inline %{
void jni_obt_init(void* dummy) {
    oc_obt_init();
}
%}

/* code and typemaps for mapping the oc_obt_discover_cb to the java OCObtDiscoveryHandler */
%{
static void jni_obt_discovery_cb(oc_uuid_t *uuid, oc_endpoint_t *eps, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  assert(user_data);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  const jclass callbackInterfaceClass = JCALL1(FindClass,
        (data->jenv),
        "org/iotivity/OCObtDiscoveryHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        callbackInterfaceClass,
        "handler",
        "(Lorg/iotivity/OCUuid;Lorg/iotivity/OCEndpoint;Ljava/lang/Object;)V");
  assert(mid_handler);

  const jclass cls_OCUuid = JCALL1(FindClass, (data->jenv), "org/iotivity/OCUuid");
  assert(cls_OCUuid);
  const jmethodID mid_OCUuid_init = JCALL3(GetMethodID, (data->jenv), cls_OCUuid, "<init>", "(JZ)V");
  assert(mid_OCUuid_init);
  const jclass cls_OCEndpoint = JCALL1(FindClass, (data->jenv), "org/iotivity/OCEndpoint");
  assert(cls_OCEndpoint);
  const jmethodID mid_OCEndpoint_init = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCEndpoint,
        "<init>",
        "(JZ)V");
  assert(mid_OCEndpoint_init);
  JCALL5(CallVoidMethod,
        (data->jenv),
        data->jcb_obj,
        mid_handler,
        JCALL4(NewObject, (data->jenv), cls_OCUuid, mid_OCUuid_init, (jlong)uuid, false),
        JCALL4(NewObject, (data->jenv), cls_OCEndpoint, mid_OCEndpoint_init, (jlong)eps, false),
        data->juser_data);

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
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_obt_discovery_cb;
  $2 = user_data;
}

%ignore oc_obt_discover_unowned_devices;
%rename(discoverUnownedDevices) jni_oc_obt_discover_unowned_devices0;
%inline %{
int jni_oc_obt_discover_unowned_devices0(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = NULL;
  return oc_obt_discover_unowned_devices(callback, jcb);
}
%}

%rename(discoverUnownedDevices) jni_oc_obt_discover_unowned_devices1;
%inline %{
int jni_oc_obt_discover_unowned_devices1(oc_obt_discovery_cb_t callback, jni_callback_data *jcb,
                                          void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_obt_discover_unowned_devices(callback, jcb);
}
%}

%ignore oc_obt_discover_owned_devices;
%rename(discoverOwnedDevices) jni_oc_obt_discover_owned_devices0;
%inline %{
int jni_oc_obt_discover_owned_devices0(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = NULL;
  return oc_obt_discover_owned_devices(callback, jcb);
}
%}

%rename(discoverOwnedDevices) jni_oc_obt_discover_owned_devices1;
%inline %{
int jni_oc_obt_discover_owned_devices1(oc_obt_discovery_cb_t callback, jni_callback_data *jcb,
                                          void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_obt_discover_owned_devices(callback, jcb);
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

  const jclass callbackInterfaceClass = JCALL1(FindClass,
        (data->jenv),
        "org/iotivity/OCObtDeviceStatusHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        callbackInterfaceClass,
        "handler",
        "(Lorg/iotivity/OCUuid;ILjava/lang/Object;)V");
  assert(mid_handler);

  const jclass cls_OCUuid = JCALL1(FindClass, (data->jenv), "org/iotivity/OCUuid");
  assert(cls_OCUuid);
  const jmethodID mid_OCUuid_init = JCALL3(GetMethodID, (data->jenv), cls_OCUuid, "<init>", "(JZ)V");
  assert(mid_OCUuid_init);
  JCALL5(CallVoidMethod,
        (data->jenv),
        data->jcb_obj,
        mid_handler,
        JCALL4(NewObject, (data->jenv), cls_OCUuid, mid_OCUuid_init, (jlong)uuid, false),
        (jint) status,
        data->juser_data);

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
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_obt_device_status_cb;
  $2 = user_data;
}

%ignore oc_obt_perform_just_works_otm;
%rename(performJustWorksOtm) jni_obt_perform_just_works_otm0;
%inline %{
int jni_obt_perform_just_works_otm0(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = NULL;
  return oc_obt_perform_just_works_otm(uuid, callback, jcb);
}
%}

%rename(performJustWorksOtm) jni_obt_perform_just_works_otm1;
%inline %{
int jni_obt_perform_just_works_otm1(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_obt_perform_just_works_otm(uuid, callback, jcb);
}
%}

%ignore oc_obt_device_hard_reset;
%rename(deviceHardReset) jni_obt_device_hard_reset0;
%inline %{
int jni_obt_device_hard_reset0(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = NULL;
  return oc_obt_device_hard_reset(uuid, callback, jcb);
}
%}

%rename(deviceHardReset) jni_obt_device_hard_reset1;
%inline %{
int jni_obt_device_hard_reset1(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_obt_device_hard_reset(uuid, callback, jcb);
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

  const jclass callbackInterfaceClass = JCALL1(FindClass,
        (data->jenv),
        "org/iotivity/OCObtStatusHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        callbackInterfaceClass,
        "handler",
        "(ILjava/lang/Object;)V");
  assert(mid_handler);

  JCALL4(CallVoidMethod,
        (data->jenv),
        data->jcb_obj,
        mid_handler,
        (jint) status,
        data->juser_data);

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
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_obt_status_cb;
  $2 = user_data;
}

%ignore oc_obt_provision_pairwise_credentials;
%rename(provisionPairwiseCredentials) jni_obt_provision_pairwise_credentials0;
%inline %{
int jni_obt_provision_pairwise_credentials0(oc_uuid_t *uuid1, oc_uuid_t *uuid2, oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = NULL;
  return oc_obt_provision_pairwise_credentials(uuid1, uuid2, callback, jcb);
}
%}

%rename(provisionPairwiseCredentials) jni_obt_provision_pairwise_credentials1;
%inline %{
int jni_obt_provision_pairwise_credentials1(oc_uuid_t *uuid1, oc_uuid_t *uuid2, oc_obt_status_cb_t callback, jni_callback_data *jcb, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_obt_provision_pairwise_credentials(uuid1, uuid2, callback, jcb);
}
%}

%rename(newAceForSubject) oc_obt_new_ace_for_subject;
%rename(newAceForConnection) oc_obt_new_ace_for_connection;
%rename(aceNewResource) oc_obt_ace_new_resource;
%rename(aceResourceSetHref) oc_obt_ace_resource_set_href;
%rename(aceResoruceSetNumRt) oc_obt_ace_resource_set_num_rt;
%rename(aceResoruceBindRt) oc_obt_ace_resource_bind_rt;
%rename(aceResourceBindIf) oc_obt_ace_resource_bind_if;
%rename(aceResourceSetWc) oc_obt_ace_resource_set_wc;
%rename(aceAddPermission) oc_obt_ace_add_permission;
%ignore oc_obt_provision_ace;
%rename(provisionAce) jni_obt_provision_ace0;
%inline %{
int jni_obt_provision_ace0(oc_uuid_t *subject, oc_sec_ace_t *ace, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = NULL;
  return oc_obt_provision_ace(subject, ace, callback, jcb);
}
%}

%rename(provisionAce) jni_obt_provision_ace1;
%inline %{
int jni_obt_provision_ace1(oc_uuid_t *subject, oc_sec_ace_t *ace, oc_obt_device_status_cb_t callback, jni_callback_data *jcb, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_obt_provision_ace(subject, ace, callback, jcb);
}
%}
%rename(freeAce) oc_obt_free_ace;

%include "oc_obt.h";
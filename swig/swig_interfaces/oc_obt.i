/* File oc_obt.i */
%module OCObt
%include "typemaps.i"
%include "iotivity.swg"

%import "oc_api.i"
%import "oc_uuid.i"

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

%rename(OCSecurityAce) oc_sec_ace_s;
/* We are relying on the iotivity-lite library to create and destry instances of oc_sec_ace_s */
%nodefaultctor oc_sec_ace_s;
%nodefaultdtor oc_sec_ace_s;
/* This will cause SWIG to wrap oc_sec_ace_s, even though oc_obt does not know anything about what is inside it */
struct oc_sec_ace_s{ };

%rename(OCAceResource) oc_ace_res_s;
/* We are relying on the iotivity-lite library to create and destry instances of oc_ace_res_s */
%nodefaultctor oc_ace_res_s;
%nodefaultdtor oc_ace_res_s;
/* This will cause SWIG to wrap oc_ace_res_s, even though oc_obt does not know anything about what is inside it */
struct oc_ace_res_s{ };

%rename(OCAceConnectionType) oc_ace_connection_type_t;
%rename(OCAceWildcard) oc_ace_wildcard_t;
%ignore oc_ace_permissions_t;

%ignore oc_obt_init;
%rename(init) jni_obt_init;
%inline %{
int jni_obt_init(void)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_init();
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  return -1;
#endif /* OC_SECURITY */
}
%}

%ignore oc_obt_shutdown;
%rename(shutdown) jni_obt_shutdown;
%inline %{
void jni_obt_shutdown(void)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_shutdown();
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
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
  data->jenv = get_jni_env(&getEnvResult);
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
        JCALL4(NewObject, (data->jenv), cls_OCEndpoint, mid_OCEndpoint_init, (jlong)eps, true));

  release_jni_env(getEnvResult);
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
  // TODO figure out the lifetime of the oc_obt_discovery_cb_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_obt_discovery_cb;
  $2 = user_data;
}

%ignore oc_obt_discover_unowned_devices;
%rename(discoverUnownedDevices) jni_oc_obt_discover_unowned_devices;
%inline %{
int jni_oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_unowned_devices(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_discover_unowned_devices_realm_local_ipv6;
%rename(discoverUnownedDevicesRealmLocalIPv6) jni_obt_discover_unowned_devices_realm_local_ipv6;
%inline %{
int jni_obt_discover_unowned_devices_realm_local_ipv6(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_unowned_devices_realm_local_ipv6(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_discover_unowned_devices_site_local_ipv6;
%rename(discoverUnownedDevicesSiteLocalIPv6) jni_obt_discover_unowned_devices_site_local_ipv6;
%inline %{
int jni_obt_discover_unowned_devices_site_local_ipv6(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_unowned_devices_site_local_ipv6(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_discover_owned_devices;
%rename(discoverOwnedDevices) jni_oc_obt_discover_owned_devices;
%inline %{
int jni_oc_obt_discover_owned_devices(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_owned_devices(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_discover_owned_devices_realm_local_ipv6;
%rename(discoverOwnedDevicesRealmLocalIPv6) jni_obt_discover_owned_devices_realm_local_ipv6;
%inline %{
int jni_obt_discover_owned_devices_realm_local_ipv6(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_owned_devices_realm_local_ipv6(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_discover_owned_devices_site_local_ipv6;
%rename(discoverOwnedDevicesSiteLocalIPv6) jni_obt_discover_owned_devices_site_local_ipv6;
%inline %{
int jni_obt_discover_owned_devices_site_local_ipv6(oc_obt_discovery_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_owned_devices_site_local_ipv6(callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
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
  data->jenv = get_jni_env(&getEnvResult);
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

  release_jni_env(getEnvResult);
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
  // TODO figure out the lifetime of the oc_obt_device_status_cb_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_obt_device_status_cb;
  $2 = user_data;
}

%ignore oc_obt_perform_just_works_otm;
%rename(performJustWorksOtm) jni_obt_perform_just_works_otm;
%inline %{
int jni_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_perform_just_works_otm(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_request_random_pin;
%rename(requestRandomPin) jni_obt_request_random_pin;
%inline %{
int jni_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_request_random_pin(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
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
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_perform_random_pin_otm(uuid, (const unsigned char*)pin, pin_len, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_perform_cert_otm;
%rename(performCertOtm) jni_obt_perform_cert_otm;
%inline %{
int jni_obt_perform_cert_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_perform_cert_otm(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY && OC_PKI */
  return return_value;
}
%}

%ignore oc_obt_add_roleid;
%rename(addRoleId) jni_obt_add_roleid;
%inline %{
oc_role_t *jni_obt_add_roleid(oc_role_t *roles, const char *role, const char *authority)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  return oc_obt_add_roleid(roles, role, authority);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning NULL.", __func__);
  return NULL;
#endif /* OC_SECURITY && OC_PKI */
}
%}
%ignore oc_obt_free_roleid;
%rename(freeRoleId) jni_obt_free_roleid;
%inline %{
void jni_obt_free_roleid(oc_role_t *roles)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_obt_free_roleid(roles);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI.", __func__);
#endif /* OC_SECURITY && OC_PKI */
}
%}

%ignore oc_obt_device_hard_reset;
%rename(deviceHardReset) jni_obt_device_hard_reset;
%inline %{
int jni_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_device_hard_reset(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
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
  data->jenv = get_jni_env(&getEnvResult);
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

  release_jni_env(getEnvResult);
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
    // TODO figure out the lifetime of the oc_obt_status_cb_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_obt_status_cb;
  $2 = user_data;
}

%ignore oc_obt_provision_pairwise_credentials;
%rename(provisionPairwiseCredentials) jni_obt_provision_pairwise_credentials;
%inline %{
int jni_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2, oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_pairwise_credentials(uuid1, uuid2, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_provision_identity_certificate;
%rename(provisionIdentityCertificate) jni_obt_provision_identity_certificate;
%inline %{
int jni_obt_provision_identity_certificate(oc_uuid_t *uuid, oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_identity_certificate(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY && OC_PKI */
  return return_value;
}
%}

%ignore oc_obt_provision_role_certificate;
%rename(provisionRoleCertificate) jni_obt_provision_role_certificate;
%inline %{
int jni_obt_provision_role_certificate(oc_role_t *roles, oc_uuid_t *uuid, oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_role_certificate(roles, uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY and OC_PKI returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY && OC_PKI */
  return return_value;
}
%}

%ignore oc_obt_new_ace_for_subject;
%rename(newAceForSubject) jni_obt_new_ace_for_subject;
%inline %{
oc_sec_ace_t *jni_obt_new_ace_for_subject(oc_uuid_t *uuid)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_new_ace_for_subject(uuid);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning NULL.", __func__);
  return NULL;
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_new_ace_for_connection;
%rename(newAceForConnection) jni_obt_new_ace_for_connection;
%inline %{
oc_sec_ace_t *jni_obt_new_ace_for_connection(oc_ace_connection_type_t conn)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_new_ace_for_connection(conn);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning NULL.", __func__);
  return NULL;
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_new_ace_for_role;
%rename(newAceForRole) jni_obt_new_ace_for_role;
%inline %{
oc_sec_ace_t *jni_obt_new_ace_for_role(const char *role, const char *authority)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_new_ace_for_role(role, authority);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning NULL.", __func__);
  return NULL;
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_new_resource;
%rename(aceNewResource) jni_obt_ace_new_resource;
%inline %{
oc_ace_res_t *jni_obt_ace_new_resource(oc_sec_ace_t *ace)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_ace_new_resource(ace);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning NULL.", __func__);
  return NULL;
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_resource_set_href;
%rename(aceResourceSetHref) jni_obt_ace_resource_set_href;
%inline %{
void jni_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_ace_resource_set_href(resource, href);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_resource_set_num_rt;
%rename(aceResourceSetNumRt) jni_obt_ace_resource_set_num_rt;
%inline %{
void jni_obt_ace_resource_set_num_rt(oc_ace_res_t *resource, int num_resources)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_ace_resource_set_num_rt(resource, num_resources);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_resource_bind_rt;
%rename(aceResourceBindRt) jni_obt_ace_resource_bind_rt;
%inline %{
void jni_obt_ace_resource_bind_rt(oc_ace_res_t *resource, const char *rt)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_ace_resource_bind_rt(resource, rt);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_resource_bind_if;
%rename(aceResourceBindIf) jni_obt_ace_resource_bind_if;
%inline %{
void jni_obt_ace_resource_bind_if(oc_ace_res_t *resource,
                                  oc_interface_mask_t iface_mask)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_ace_resource_bind_if(resource, iface_mask);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_resource_set_wc;
%rename(aceResourceSetWc) jni_obt_ace_resource_set_wc;
%inline %{
void jni_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_ace_resource_set_wc(resource, wc);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_ace_add_permission;
%rename(aceAddPermission) jni_obt_ace_add_permission;
%inline %{
void jni_obt_ace_add_permission(oc_sec_ace_t *ace,
                                oc_ace_permissions_t permission)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_ace_add_permission(ace, permission);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_provision_ace;
%rename(provisionAce) jni_obt_provision_ace;
%inline %{
int jni_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_ace(subject, ace, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}
%ignore oc_obt_free_ace;
%rename(freeAce) jni_obt_free_ace;
%inline %{
void jni_obt_free_ace(oc_sec_ace_t *ace)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_free_ace(ace);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}
%ignore oc_obt_provision_role_wildcard_ace;
%rename(provisionRoleWildcardAce) jni_obt_provision_role_wildcard_ace;
%inline %{
int jni_obt_provision_role_wildcard_ace(oc_uuid_t *subject, const char *role, const char *authority,
                                        oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_role_wildcard_ace(subject, role, authority, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_provision_auth_wildcard_ace;
%rename(provisionAuthWildcardAce) jni_obt_provision_auth_wildcard_ace;
%inline %{
int jni_obt_provision_auth_wildcard_ace(oc_uuid_t *subject, oc_obt_device_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_auth_wildcard_ace(subject, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning error.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%include "oc_obt.h";
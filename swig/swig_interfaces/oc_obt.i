/* File oc_obt.i */
%module OCObt
%include "typemaps.i"
%include "iotivity.swg"
%include "enums.swg"
%javaconst(1);

%import "oc_api.i"
%import "oc_uuid.i"
%import "oc_cred.i"

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

/*******************Begin oc_acl.h*****************/
/*
 * NOTE: currently We only expose enums and structs from oc_acl.h
 * This is why we are not currently using an independent swig interface file. It
 * would just create an empty Java class. If any functions are exposed this should
 * be moved to its own interface file.
 */
%rename(OCSecurityAcl) oc_sec_acl_s;
%ignore oc_sec_acl_s::OC_LIST_STRUCT(subjects);
%extend oc_sec_acl_s {
  oc_sec_ace_t *getSubjectsListHead() {
    return (oc_sec_ace_t *)oc_list_head(self->subjects);
  }
}
%rename(OCAceConnectionType) oc_ace_connection_type_t;
%rename(OCAceWildcard) oc_ace_wildcard_t;
%ignore oc_ace_permissions_t;
%rename(OCAceResource) oc_ace_res_t;
/* We are relying on the iotivity-lite library to create and destroy instances of oc_ace_res_t */
%nodefaultctor oc_ace_res_t;
%nodefaultdtor oc_ace_res_t;
/* We are relying on the iotivity-lite library to create and destroy instances of oc_ace_subject_type_t */
%rename(OCAceSubjectType) oc_ace_subject_type_t;
%nodefaultctor oc_ace_subject_type_t;
%nodefaultdtor oc_ace_subject_type_t;
%rename(OCAceSubject) oc_ace_subject_t;
%nodefaultctor oc_ace_subject_t;
%nodefaultdtor oc_ace_subject_t;
//%rename(OCAceSubjectRole) oc_ace_subject_t_role;
%ignore oc_ace_subject_t_role;
%extend oc_ace_subject_t {
  oc_string_t getRole() {
    return self->role.role;
  }

  oc_string_t getAuthority() {
    return self->role.authority;
  }
}
%rename(OCSecurityAce) oc_sec_ace_t;
%ignore oc_sec_ace_t::OC_LIST_STRUCT(resources);
%extend oc_sec_ace_t {
  oc_ace_res_t *getResourcesListHead() {
    return oc_list_head(self->resources);
  }
}
%rename(subjectType) oc_sec_ace_t::subject_type;
%rename(OCSecurityAcl) oc_sec_acl_s;
/* We are relying on the iotivity-lite library to create and destroy instances of oc_sec_ace_t */
%nodefaultctor oc_sec_ace_t;
%nodefaultdtor oc_sec_ace_t;
/*******************End oc_acl.h*****************/

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

  jobject juuid = NULL;
  if (uuid) {
    assert(cls_OCUuid);
    const jmethodID mid_OCUuid_init = JCALL3(GetMethodID, (data->jenv), cls_OCUuid, "<init>", "(JZ)V");
    assert(mid_OCUuid_init);

    /* make copy of uuid that will be owned by Java code */
    oc_uuid_t *new_uuid = malloc(sizeof(oc_uuid_t));
    memcpy(new_uuid->id, uuid->id, 16);

    juuid = JCALL4(NewObject, (data->jenv), cls_OCUuid, mid_OCUuid_init, (jlong)new_uuid, true);
  }

  jobject jeps = NULL;
  if (eps) {
    assert(cls_OCEndpoint);
    const jmethodID mid_OCEndpoint_init = JCALL3(GetMethodID,
                                                 (data->jenv),
                                                 cls_OCEndpoint,
                                                 "<init>",
                                                 "(JZ)V");
  assert(mid_OCEndpoint_init);

  jeps = JCALL4(NewObject, (data->jenv), cls_OCEndpoint, mid_OCEndpoint_init, (jlong)eps, false);
  }
  JCALL4(CallVoidMethod, (data->jenv),
         data->jcb_obj,
         mid_handler,
         juuid,
         jeps);

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

%ignore oc_obt_discover_all_resources;
%rename (discoverAllResources) jni_obt_discover_all_resources;
%inline %{
int jni_obt_discover_all_resources(oc_uuid_t *uuid, oc_discovery_all_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_discover_all_resources(uuid, handler, jcb);
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

  jobject juuid = NULL;
  if (uuid) {
    assert(cls_OCUuid);
    const jmethodID mid_OCUuid_init = JCALL3(GetMethodID, (data->jenv), cls_OCUuid, "<init>", "(JZ)V");
    assert(mid_OCUuid_init);

    /* make copy of uuid that will be owned by Java code */
    oc_uuid_t *new_uuid = malloc(sizeof(oc_uuid_t));
    memcpy(new_uuid->id, uuid->id, 16);

    juuid = JCALL4(NewObject, (data->jenv), cls_OCUuid, mid_OCUuid_init, (jlong)new_uuid, true);
  }

  JCALL4(CallVoidMethod, (data->jenv),
         data->jcb_obj,
         mid_handler,
         juuid,
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
%typemap(in,numinputs=1) (char *pin, size_t pin_len)
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
int jni_obt_perform_random_pin_otm(oc_uuid_t *uuid, char *pin, size_t pin_len,
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



%ignore oc_obt_provision_trust_anchor;
%rename(provisionTrustAnchor) jni_obt_provision_trust_anchor;
%inline %{
int jni_oc_obt_provision_trust_anchor(char* certificate, size_t certificate_size, char* subject, oc_uuid_t *uuid, oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_provision_trust_anchor(certificate, certificate_size, subject, uuid, callback, jcb);
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

%ignore oc_obt_retrieve_own_creds;
%rename (retrieveOwnCreds) jni_obt_retrieve_own_creds;
%inline %{
oc_sec_creds_t *jni_obt_retrieve_own_creds(void)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_retrieve_own_creds();
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning NULL.", __func__);
  return NULL;
#endif /* OC_SECURITY */
}
%}

%ignore oc_obt_delete_own_cred_by_credid;
%rename(deleteOwnCredByCredId) jni_obt_delete_own_cred_by_credid;
%inline %{
int jni_obt_delete_own_cred_by_credid(int credid)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  return oc_obt_delete_own_cred_by_credid(credid);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning -1.", __func__);
  return -1;
#endif /* OC_SECURITY */
}
%}

/* code and typemaps for mapping the oc_obt_creds_cb_t to the java OCObtCredsHandler */
%{
void jni_obt_creds_cb(struct oc_sec_creds_t *creds, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCObtCredsHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCObtCredsHandler,
        "handler",
        "(Lorg/iotivity/OCCreds;)V");
  assert(mid_handler);

  jobject jcreds = NULL;
  if (creds) {
    assert(cls_OCCreds);
    const jmethodID mid_OCCreds_init = JCALL3(GetMethodID, (data->jenv), cls_OCCreds, "<init>", "(JZ)V");
    assert(mid_OCCreds_init);

    jcreds = JCALL4(NewObject, (data->jenv), cls_OCCreds, mid_OCCreds_init, (jlong)creds, false);
  }
  JCALL3(CallVoidMethod, (data->jenv),
         data->jcb_obj,
         mid_handler,
         jcreds);

  release_jni_env(getEnvResult);
}
%}

%ignore oc_obt_creds_cb_t;
%typemap(jni)    oc_obt_creds_cb_t callback "jobject";
%typemap(jtype)  oc_obt_creds_cb_t callback "OCObtCredsHandler";
%typemap(jstype) oc_obt_creds_cb_t callback "OCObtCredsHandler";
%typemap(javain) oc_obt_creds_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_obt_creds_cb_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
    // TODO figure out the lifetime of the oc_obt_creds_cb_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_obt_creds_cb;
  $2 = user_data;
}

%ignore oc_obt_retrieve_creds;
%rename(retrieveCreds) jni_obt_retrieve_creds;
%inline %{
int jni_obt_retrieve_creds(oc_uuid_t *subject, oc_obt_creds_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_retrieve_creds(subject, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning -1.", __func__);
  return -1;
#endif /* OC_SECURITY */
}
%}

%ignore oc_obt_free_creds;
%rename(freeCreds) jni_obt_free_creds;
%inline %{
void jni_obt_free_creds(oc_sec_creds_t *creds)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_free_creds(creds);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}

%ignore oc_obt_delete_cred_by_credid;
%rename(deleteCredByCredId) jni_obt_delete_cred_by_credid;
%inline %{
int jni_obt_delete_cred_by_credid(oc_uuid_t *uuid, int credid,
                                 oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_delete_cred_by_credid(uuid, credid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning -1.", __func__);
  return -1;
#endif /* OC_SECURITY */
}
%}

/* code and typemaps for mapping the oc_obt_acl_cb_t to the java OCObtAclHandler */
%{
void jni_obt_acl_cb(oc_sec_acl_t *acl, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCObtAclHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCObtAclHandler,
        "handler",
        "(Lorg/iotivity/OCSecurityAcl;)V");
  assert(mid_handler);

  jobject jacl = NULL;
  if (acl) {
    assert(cls_OCSecurityAcl);
    const jmethodID mid_OCSecurityAcl_init = JCALL3(GetMethodID, (data->jenv), cls_OCSecurityAcl, "<init>", "(JZ)V");
    assert(mid_OCSecurityAcl_init);

    jacl = JCALL4(NewObject, (data->jenv), cls_OCSecurityAcl, mid_OCSecurityAcl_init, (jlong)acl, false);
  }

  JCALL3(CallVoidMethod, (data->jenv),
         data->jcb_obj,
         mid_handler,
         jacl);

  release_jni_env(getEnvResult);
}
%}

%ignore oc_obt_creds_cb_t;
%typemap(jni)    oc_obt_acl_cb_t callback "jobject";
%typemap(jtype)  oc_obt_acl_cb_t callback "OCObtAclHandler";
%typemap(jstype) oc_obt_acl_cb_t callback "OCObtAclHandler";
%typemap(javain) oc_obt_acl_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_obt_acl_cb_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
    // TODO figure out the lifetime of the oc_obt_creds_cb_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_obt_acl_cb;
  $2 = user_data;
}

%ignore oc_obt_retrieve_acl;
%rename(retrieveAcl) jni_obt_retrieve_acl;
%inline %{
int jni_obt_retrieve_acl(oc_uuid_t *uuid, oc_obt_acl_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_retrieve_acl(uuid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning -1.", __func__);
  int return_value = -1;
#endif /* OC_SECURITY */
  return return_value;
}
%}

%ignore oc_obt_free_acl;
%rename(freeAcl) jni_obt_free_acl;
%inline %{
void jni_obt_free_acl(oc_sec_acl_t *acl)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  oc_obt_free_acl(acl);
#else
  OC_DBG("JNI: %s requires OC_SECURITY.", __func__);
#endif /* OC_SECURITY */
}
%}

%ignore oc_obt_delete_ace_by_aceid;
%rename(deleteAceByAceId) jni_obt_delete_ace_by_aceid;
%inline %{
int jni_obt_delete_ace_by_aceid(oc_uuid_t *uuid, int aceid,
                               oc_obt_status_cb_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_obt_delete_ace_by_aceid(uuid, aceid, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else
  OC_DBG("JNI: %s requires OC_SECURITY returning -1.", __func__);
  return -1;
#endif /* OC_SECURITY */
}
%}
%include "oc_acl.h"
%include "oc_obt.h";
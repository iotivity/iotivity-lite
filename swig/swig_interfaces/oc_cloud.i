/* file oc_cloud.i */
%module OCCloud

%include "enums.swg"
%javaconst(1);
%include "iotivity.swg"
%include "stdint.i"

%import "oc_collection.i"
%import "oc_endpoint.i"
%import "oc_ri.i"
%import "oc_session_events.i"

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
#include "api/cloud/oc_cloud_context_internal.h"
#include "api/cloud/oc_cloud_store_internal.h"
#include "oc_cloud.h"
#include "port/oc_log_internal.h"

#include <assert.h>
%}

/* code and typemaps for mapping the oc_cloud_cb_t to the java OCCloudHandler */
%{
static void jni_cloud_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCCloudHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
        (data->jenv),
        cls_OCCloudHandler,
        "handler",
        "(Lorg/iotivity/OCCloudContext;I)V");
  assert(mid_handler);

  // convert oc_cloud_context_t to java org.iotivity.OCCloudContext so it can
  // be passed upto the handler method.
  jobject jctx = NULL;
  if (ctx) {
    assert(cls_OCCloudContext);
    const jmethodID mid_OCOCCloudContext_init = JCALL3(GetMethodID, (data->jenv),
                                                       cls_OCCloudContext,
                                                       "<init>",
                                                       "(JZ)V");
    assert(mid_OCOCCloudContext_init);
    jctx = JCALL4(NewObject, (data->jenv),
                  cls_OCCloudContext,
                  mid_OCOCCloudContext_init,
                  (jlong)ctx,
                  false);
  }

  JCALL4(CallVoidMethod, (data->jenv),
         data->jcb_obj,
         mid_handler,
         jctx,
         (jint) status);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }
  release_jni_env(getEnvResult);
}

%}

%ignore oc_cloud_cb_t;
%typemap(jni)    oc_cloud_cb_t callback "jobject";
%typemap(jtype)  oc_cloud_cb_t callback "OCCloudHandler";
%typemap(jstype) oc_cloud_cb_t callback "OCCloudHandler";
%typemap(javain) oc_cloud_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_cloud_cb_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(user_data);
  $1 = jni_cloud_cb;
  $2 = user_data;
}

// TODO: implement
%ignore oc_cloud_on_keepalive_response_cb_t;
%ignore oc_cloud_keepalive_t;
%ignore oc_cloud_set_keepalive;

// TODO: implement
%ignore cloud_context_iterator_cb_t;
%ignore cloud_context_iterate;

// TODO: implement
%ignore oc_cloud_set_schedule_action;
%ignore oc_cloud_schedule_action_cb_t;
%ignore oc_cloud_schedule_action_t;
%ignore oc_cloud_action_to_str;
%ignore oc_cloud_action_t;

// oc_cloud_status is a bitmask exposed through OCCloudStatusMask.java as ints
%ignore oc_cloud_status_t;
%rename (OCCloudPrivisoningStatus) oc_cps_t;
%rename (UNINITIALIZED) OC_CPS_UNINITIALIZED;
%rename (READYTOREGISTER) OC_CPS_READYTOREGISTER;
%rename (REGISTERING) OC_CPS_REGISTERING;
%rename (REGISTERED) OC_CPS_REGISTERED;
%rename (FAILED) OC_CPS_FAILED;

%rename (OCCloudError) oc_cloud_error_t;
%ignore oc_cloud_on_status_change_cb_t;

%rename (OCCloudContext) oc_cloud_context_t;
%ignore oc_cloud_context_t::next;
%ignore oc_cloud_context_t::device;
%ignore oc_cloud_context_t::on_status_change;
%ignore oc_cloud_context_t::store;
%ignore oc_cloud_context_t::keepalive;
%ignore oc_cloud_context_t::schedule_action;
%ignore oc_cloud_context_t::cloud_ep_state;
%ignore oc_cloud_context_t::cloud_ep;
%ignore oc_cloud_context_t::rd_publish_resources;
%ignore oc_cloud_context_t::rd_published_resources;
%ignore oc_cloud_context_t::rd_delete_resources;
%ignore oc_cloud_context_t::selected_identity_cred_id;
%ignore oc_cloud_context_t::last_error;
%ignore oc_cloud_context_t::time_to_live;
%ignore oc_cloud_context_t::retry_count;
%ignore oc_cloud_context_t::cloud_manager;
%ignore oc_cloud_context_t::retry_refresh_token_count;

%ignore oc_cloud_get_context;
%rename (getContext) jni_cloud_get_context;
%inline %{
oc_cloud_context_t *jni_cloud_get_context(size_t device)
{
#ifdef OC_CLOUD
  return oc_cloud_get_context(device);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)device;
  return NULL;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_device;
%rename (getDevice) jni_cloud_get_device;
%inline %{
size_t jni_cloud_get_device(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_device(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return 0;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_apn;
%rename (getAuthorizationProviderName) jni_cloud_get_apn;
%inline %{
const char *jni_cloud_get_apn(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_apn(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return NULL;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_at;
%rename (getAccessToken) jni_cloud_get_at;
%inline %{
const char *jni_cloud_get_at(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_at(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return NULL;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_cis;
%rename (getAddress) jni_cloud_get_cis;
%inline %{
const char *jni_cloud_get_cis(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_cis(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return NULL;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_sid;
%rename (getId) jni_cloud_get_sid;
%inline %{
const char *jni_cloud_get_sid(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_sid(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return NULL;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_uid;
%rename (getUserId) jni_cloud_get_uid;
%inline %{
const char *jni_cloud_get_uid(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_uid(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return NULL;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_manager_start;
%rename (managerStart) jni_cloud_manager_start;
%inline %{
int jni_cloud_manager_start(oc_cloud_context_t *ctx, oc_cloud_cb_t callback, jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  jcb->cb_valid = OC_CALLBACK_VALID_TILL_CLOUD_MANAGER_STOP;
  int return_value = oc_cloud_manager_start(ctx, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)callback;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_manager_stop;
%rename (managerStop) jni_cloud_manager_stop;
%inline %{
int jni_cloud_manager_stop(oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  int ret = oc_cloud_manager_stop(ctx);
  jni_callback_data *item = jni_list_get_item_by_callback_valid(OC_CALLBACK_VALID_TILL_CLOUD_MANAGER_STOP);
  jni_list_remove(item);
  return ret;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_manager_restart;
%rename (managerRestart) jni_cloud_manager_restart;
%inline %{
void jni_cloud_manager_restart(oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  oc_cloud_manager_restart(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_register;
%rename (registerCloud) jni_cloud_register;
%inline %{
int jni_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t callback, jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  jcb->cb_valid = OC_CALLBACK_VALID_FOR_A_SINGLE_CALL;
  int return_value = oc_cloud_register(ctx, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)callback;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_login;
%rename (login) jni_cloud_login;
%inline %{
int jni_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t callback, jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  jcb->cb_valid = OC_CALLBACK_VALID_FOR_A_SINGLE_CALL;
  int return_value = oc_cloud_login(ctx, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)callback;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_logout;
%rename (logout) jni_cloud_logout;
%inline %{
int jni_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t callback, jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  jcb->cb_valid = OC_CALLBACK_VALID_FOR_A_SINGLE_CALL;
  int return_value = oc_cloud_logout(ctx, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)callback;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_deregister;
%rename (deregisterCloud) jni_cloud_deregister;
%inline %{
int jni_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t callback, jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  jcb->cb_valid = OC_CALLBACK_VALID_FOR_A_SINGLE_CALL;
  int return_value = oc_cloud_deregister(ctx, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)callback;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_refresh_token;
%rename (refreshToken) jni_cloud_refresh_token;
%inline %{
int jni_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t callback, jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  jcb->cb_valid = OC_CALLBACK_VALID_FOR_A_SINGLE_CALL;
  int return_value = oc_cloud_refresh_token(ctx, callback, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)callback;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_set_published_resources_ttl;
%rename (setPublishedResourcesTtl) jni_cloud_set_published_resources_ttl;
%inline %{
void jni_cloud_set_published_resources_ttl(oc_cloud_context_t *ctx,
                                           uint32_t ttl)
{
#ifdef OC_CLOUD
  oc_cloud_set_published_resources_ttl(ctx, ttl);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)ttl;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_token_expiry;
%rename (getTokenExpiry) jni_cloud_get_token_expiry;
%inline %{
int jni_cloud_get_token_expiry(oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_token_expiry(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_add_resource;
%rename (addResource) jni_cloud_add_resource;
%inline %{
int jni_cloud_add_resource(oc_resource_t *resource)
{
#ifdef OC_CLOUD
  return oc_cloud_add_resource(resource);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)resource;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_delete_resource;
%rename (deleteResource) jni_cloud_delete_resource;
%inline %{
void jni_cloud_delete_resource(oc_resource_t *resource)
{
#ifdef OC_CLOUD
  oc_cloud_delete_resource(resource);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)resource;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_publish_resources;
%rename (publishResources) jni_cloud_publish_resources;
%inline %{
int jni_cloud_publish_resources(size_t device)
{
#ifdef OC_CLOUD
  return oc_cloud_publish_resources(device);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)device;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_discover_resources;
%rename (discoverResources) jni_cloud_discover_resources;

%inline %{
int jni_cloud_discover_resources(oc_cloud_context_t *ctx,
                                oc_discovery_all_handler_t handler,
                                jni_callback_data *jcb)
{
#ifdef OC_CLOUD
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_cloud_discover_resources(ctx, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)handler;
  (void)jcb;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_provision_conf_resource;
%rename(provisionConfResource) jni_cloud_provision_conf_resource;
%inline %{
int jni_cloud_provision_conf_resource(oc_cloud_context_t *ctx,
                                      const char *server,
                                      const char *accessToken,
                                      const char *serverId,
                                      const char *authProvider)
{
#ifdef OC_CLOUD
  return oc_cloud_provision_conf_resource(ctx, server, accessToken, serverId, authProvider);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)server;
  (void)accessToken;
  (void)serverId;
  (void)authProvider;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_provision_conf_resource_v1;
%rename(provisionConfResourceV1) jni_cloud_provision_conf_resource_v1;
%inline %{
int jni_cloud_provision_conf_resource_v1(oc_cloud_context_t *ctx,
                                         const char *server,
                                         size_t server_len,
                                         const char *accessToken,
                                         size_t accessToken_len,
                                         const char *serverId,
                                         size_t serverId_len,
                                         const char *authProvider,
                                         size_t authProvider_len)
{
#ifdef OC_CLOUD
  return oc_cloud_provision_conf_resource_v1(ctx, server, server_len, accessToken, accessToken_len,
    serverId, serverId_len, authProvider, authProvider_len);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)server;
  (void)server_len;
  (void)accessToken;
  (void)accessToken_len;
  (void)serverId;
  (void)serverId_len;
  (void)authProvider;
  (void)authProvider_len;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_set_identity_cert_chain;
%rename(setIdentityCertChain) jni_cloud_set_identity_cert_chain;
%inline %{
void jni_cloud_set_identity_cert_chain(oc_cloud_context_t *ctx,
                                       int selected_identity_cred_id)
{
#ifdef OC_CLOUD
  oc_cloud_set_identity_cert_chain(ctx, selected_identity_cred_id);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)selected_identity_cred_id;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_get_identity_cert_chain;
%rename(getIdentityCertChain) jni_cloud_get_identity_cert_chain;
%inline %{
int jni_cloud_get_identity_cert_chain(const oc_cloud_context_t *ctx)
{
#ifdef OC_CLOUD
  return oc_cloud_get_identity_cert_chain(ctx);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_context_clear;
%rename(clearContext) jni_cloud_context_clear;
%inline %{
void jni_cloud_context_clear(oc_cloud_context_t *ctx, bool dump_async)
{
#ifdef OC_CLOUD
  oc_cloud_context_clear(ctx, dump_async);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
  (void)ctx;
  (void)dump_async;
#endif /* !OC_CLOUD */
}
%}

#define OC_NONNULL(...)

// get oc_cloud_context_t definition, but ignore all other definitions
%ignore cloud_context_init;
%ignore cloud_context_deinit;
%ignore cloud_context_size;
%ignore cloud_context_iterator_cb_t;
%ignore cloud_context_has_access_token;
%ignore cloud_context_iterate;
%ignore cloud_context_clear;
%ignore cloud_context_has_permanent_access_token;
%ignore cloud_context_clear_access_token;
%ignore cloud_context_has_refresh_token;
%include "api/cloud/oc_cloud_context_internal.h"

#define OC_API
%include "oc_cloud.h"

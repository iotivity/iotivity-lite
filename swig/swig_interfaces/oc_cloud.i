/* file oc_core_res.i */
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
#include "oc_cloud.h"
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

// oc_cloud_status is a bitmask exposed through OCCloudStatusMask.java as ints
%ignore oc_cloud_status_t;
%rename (OCCloudPrivisoningStatus) oc_cps_t;
%rename (UNINITIALIZED) OC_CPS_UNINITIALIZED;
%rename (READYTOREGISTER) OC_CPS_READYTOREGISTER;
%rename (REGISTERING) OC_CPS_REGISTERING;
%rename (REGISTERED) OC_CPS_REGISTERED;
%rename (FAILED) OC_CPS_FAILED;

%rename (OCCloudStore) oc_cloud_store_t;
%rename (OCCloudError) oc_cloud_error_t;
%rename (OCCloudContext) oc_cloud_context_t;
%ignore oc_cloud_context_t::callback;
%ignore oc_cloud_context_t::user_data;
%rename (cloudEndpointState) oc_cloud_context_t::cloud_ep_state;
%rename (cloudEndpoint) oc_cloud_context_t::cloud_ep;
%rename (retryCount) oc_cloud_context_t::retry_count;
%rename (retryRefreshTokenCount) oc_cloud_context_t::retry_refresh_token_count;
%rename (lastError) oc_cloud_context_t::last_error;
%rename (expiresIn) oc_cloud_context_t::expires_in;
%rename (rdPublishResources) oc_cloud_context_t::rd_publish_resources;
%rename (rdPublishedResources) oc_cloud_context_t::rd_published_resources;
%rename (rdDeleteResources) oc_cloud_context_t::rd_delete_resources;
%rename (rdDeleteAll) oc_cloud_context_t::rd_delete_all;
%ignore oc_cloud_context_t::cps;
%rename (cloudConf) oc_cloud_context_t::cloud_conf;
%rename (cloudManager) oc_cloud_context_t::cloud_manager;

%ignore oc_cloud_get_context;
%rename (getContext) jni_cloud_get_context;
%inline %{
oc_cloud_context_t *jni_cloud_get_context(size_t device)
{
#ifdef OC_CLOUD
  return oc_cloud_get_context(device);
#else /* OC_CLOUD*/
  OC_DBG("JNI: %s - Must build with OC_CLOUD defined to use this function.\n", __func__);
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
  return -1;
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
  return -1;
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
  return -1;
#endif /* !OC_CLOUD */
}
%}

%ignore oc_cloud_discover_resources;
%rename (discoverResources) jni_cloud_discover_resources;

%inline %{
int jni_cloud_discover_resources( oc_cloud_context_t *ctx,
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
  return -1;
#endif /* !OC_CLOUD */
}
%}

%include "oc_cloud.h"
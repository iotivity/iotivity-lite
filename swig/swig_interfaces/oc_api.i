/* File oc_api.i */
%module OCMain
%include "carrays.i"
%include "arrays_java.i"
%include "stdint.i"
%include "typemaps.i"
%include "various.i"

%include "iotivity.swg"
%include "oc_ri.i"
%import "oc_collection.i"
%import "oc_clock.i"
%import "oc_endpoint.i"
%import "oc_rep.i"
%import "oc_uuid.i"
%import "oc_enums.i"

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

// DOCUMENTATION workaround
%pragma(java) moduleclassmodifiers="/**
   * Main API of IoTivity-lite for client and server.
   * <p>
   * This is the main entry for all server and client related OCF functions.
   */
  public class";

%{
#include "oc_iotivity_lite_jni.h"

#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include "oc_helpers.h"
#include <assert.h>
%}

/* Code and typemaps for mapping the oc_main_init to the java OCMainInitHandler */
%{
static jobject jinit_obj;

/* Callback handlers for oc_main_init */
int jni_oc_handler_init_callback(void)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_initialize = JCALL3(GetMethodID, jenv, cls_OCMainInitHandler, "initialize", "()I");
  assert(mid_initialize);
  jint ret_value = JCALL2(CallIntMethod, jenv, jinit_obj, mid_initialize);

  release_jni_env(getEnvResult);
  return (int)ret_value;
}

static void jni_signal_event_loop(void)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(_WIN32)
  WakeConditionVariable(&jni_cv);
#elif defined(__linux__)
  jni_mutex_lock(jni_cs);
  pthread_cond_signal(&jni_cv);
  jni_mutex_unlock(jni_cs);
#endif
}

void jni_oc_handler_register_resource_callback(void)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_registerResources = JCALL3(GetMethodID, jenv, cls_OCMainInitHandler, "registerResources", "()V");
  assert(mid_registerResources);
  JCALL2(CallVoidMethod, jenv, jinit_obj, mid_registerResources);

  release_jni_env(getEnvResult);
}

void jni_oc_handler_requests_entry_callback(void)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_requestEntry_method = JCALL3(GetMethodID, jenv, cls_OCMainInitHandler, "requestEntry", "()V");
  assert(mid_requestEntry_method);
  JCALL2(CallVoidMethod, jenv, jinit_obj, mid_requestEntry_method);

  release_jni_env(getEnvResult);
}

static oc_handler_t jni_handler = {
    jni_oc_handler_init_callback,              // init
    jni_signal_event_loop,                     // signal_event_loop
    jni_oc_handler_register_resource_callback, // register_resources
    jni_oc_handler_requests_entry_callback     // requests_entry
    };
%}

%ignore oc_handler_t;
%typemap(jni)    const oc_handler_t *handler "jobject";
%typemap(jtype)  const oc_handler_t *handler "OCMainInitHandler";
%typemap(jstype) const oc_handler_t *handler "OCMainInitHandler";
%typemap(javain) const oc_handler_t *handler "$javainput";
%typemap(in)     const oc_handler_t *handler {
  jinit_obj = JCALL1(NewGlobalRef, jenv, $input);
  $1 = &jni_handler;

  const jclass callback_interface = JCALL1(FindClass, jenv, "org/iotivity/OCMainInitHandler");
  assert(callback_interface);
  cls_OCMainInitHandler = (jclass)(JCALL1(NewGlobalRef, jenv, callback_interface));
}

%{
#if defined(_WIN32)
DWORD WINAPI
jni_poll_event(LPVOID lpParam)
{
  oc_clock_time_t next_event;
  while (jni_quit != 1) {
      OC_DBG("JNI: - lock %s\n", __func__);
      jni_mutex_lock(jni_sync_lock);
      OC_DBG("calling oc_main_poll from JNI code\n");
      next_event = oc_main_poll();
      jni_mutex_unlock(jni_sync_lock);
      OC_DBG("JNI: - unlock %s\n", __func__);

      if (next_event == 0) {
          SleepConditionVariableCS(&jni_cv, &jni_cs, INFINITE);
      }
      else {
          oc_clock_time_t now = oc_clock_time();
          if (now < next_event) {
              SleepConditionVariableCS(&jni_cv, &jni_cs,
                  (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
          }
      }
  }

  oc_main_shutdown();

  return TRUE;
}
#elif defined(__linux__)
static void *
jni_poll_event(void *data)
{
  OC_DBG("inside the JNI jni_poll_event\n");
  (void)data;
  oc_clock_time_t next_event;
  struct timespec ts;
  while (jni_quit != 1) {
    OC_DBG("JNI: - lock %s\n", __func__);
    jni_mutex_lock(jni_sync_lock);
    OC_DBG("calling oc_main_poll from JNI code\n");
    next_event = oc_main_poll();
    jni_mutex_unlock(jni_sync_lock);
    OC_DBG("JNI: - unlock %s\n", __func__);

    jni_mutex_lock(jni_cs);
    if (next_event == 0) {
      pthread_cond_wait(&jni_cv, &jni_cs);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&jni_cv, &jni_cs, &ts);
    }
    jni_mutex_unlock(jni_cs);
  }

  oc_main_shutdown();

  return NULL;
}
#endif

%}

%ignore oc_main_init;
%rename(mainInit) jni_main_init;
%inline %{
int jni_main_init(const oc_handler_t *handler)
{
  jni_quit = 0;

  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);
  assert(jenv);

  release_jni_env(getEnvResult);

  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  int return_value = oc_main_init(handler);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);

// start poll event thread.
#if defined(_WIN32)
  jni_poll_event_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)jni_poll_event, NULL, 0, NULL);
  if (NULL == jni_poll_event_thread) {
    return -1;
  }
#elif defined(__linux__)
  if (pthread_create(&jni_poll_event_thread, NULL, &jni_poll_event, NULL) != 0) {
    return -1;
  }
#endif

  return return_value;
}
%}
%ignore oc_main_poll;
%ignore oc_main_shutdown;
%rename(mainShutdown) jni_main_shutdown;
%inline %{
  void jni_main_shutdown(void) {
    jni_quit = 1;
    /*
     * Call the jni_signal_event_loop to wake condition variable mutex located in the
     * poll wait loop which call oc_main_shutdown once the jni_quit value is seen
     */
    jni_signal_event_loop();
#if defined(_WIN32)
    WaitForSingleObject(jni_poll_event_thread, INFINITE);
#elif defined(__linux__)
    pthread_join(jni_poll_event_thread, NULL);
#endif
    jni_list_clear();
  }
%}

/* Code and typemaps for mapping the oc_set_factory_presets_cb to the OCFactoryPresetsHandler */
%{
void jni_oc_factory_presets_callback(size_t device, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);

  assert(cls_OCFactoryPresetsHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCFactoryPresetsHandler,
                                       "handler",
                                       "(J)V");

  assert(mid_handler);
  JCALL3(CallVoidMethod, (data->jenv), data->jcb_obj, mid_handler, (jlong)device);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
}
%}

%typemap(jni)    oc_factory_presets_cb_t cb "jobject";
%typemap(jtype)  oc_factory_presets_cb_t cb "OCFactoryPresetsHandler";
%typemap(jstype) oc_factory_presets_cb_t cb "OCFactoryPresetsHandler";
%typemap(javain) oc_factory_presets_cb_t cb "$javainput";
%typemap(in,numinputs=1) (oc_factory_presets_cb_t cb, jni_callback_data *jcb) {
  // The C code only contains one instance of oc_factory_presets_cb_t if setFactoryPresetsHandler is
  // called multiple times we must release the old item.
  jni_callback_data * item = jni_list_get_item_by_callback_valid(OC_CALLBACK_VALID_TILL_SET_FACTORY_PRESETS_CB);
  if (item) {
    jni_list_remove(item);
  }
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  if(JCALL2(IsSameObject, jenv, $input, NULL)) {
    user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
    $1 = NULL;
  } else {
    user_data->cb_valid = OC_CALLBACK_VALID_TILL_SET_FACTORY_PRESETS_CB;
    $1 = jni_oc_factory_presets_callback;
  }
  $2 = user_data;
  jni_list_add(user_data);
}

%ignore oc_set_factory_presets_cb;
%rename(setFactoryPresetsHandler) jni_set_factory_presets_cb;
%inline %{
void jni_set_factory_presets_cb(oc_factory_presets_cb_t cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  oc_set_factory_presets_cb(cb, jcb);
}
%}

/* Code and typemaps for mapping the oc_add_device to the java OCAddDeviceHandler */
%{
void jni_oc_add_device_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  assert(cls_OCAddDeviceHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCAddDeviceHandler,
                                       "handler",
                                       "()V");
  assert(mid_handler);
  JCALL2(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }
}
%}
%typemap(jni)    oc_add_device_cb_t add_device_cb "jobject";
%typemap(jtype)  oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(jstype) oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(javain) oc_add_device_cb_t add_device_cb "$javainput";
%typemap(in,numinputs=1) (oc_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_FOR_A_SINGLE_CALL;
  jni_list_add(user_data);
  $1 = jni_oc_add_device_callback;
  $2 = user_data;
}
%ignore oc_add_device;
%rename(addDevice) jni_oc_add_device;
%inline %{
int jni_oc_add_device(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_add_device(uri, rt, name, spec_version, data_model_version, NULL, NULL);
}
%}

%rename(addDevice) jni_oc_add_device1;
%inline %{
int jni_oc_add_device1(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version,
                       oc_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_add_device(uri, rt, name, spec_version, data_model_version, add_device_cb, jcb);
}
%}

/* Code and typemaps for mapping the oc_init_platform to the java OCInitPlatformHandler */
%{
void jni_oc_init_platform_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  assert(cls_OCInitPlatformHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCInitPlatformHandler,
                                       "handler",
                                       "()V");
  assert(mid_handler);
  JCALL2(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }
}
%}
%typemap(jni)    oc_init_platform_cb_t init_platform_cb "jobject";
%typemap(jtype)  oc_init_platform_cb_t init_platform_cb "OCInitPlatformHandler";
%typemap(jstype) oc_init_platform_cb_t init_platform_cb "OCInitPlatformHandler";
%typemap(javain) oc_init_platform_cb_t init_platform_cb "$javainput";

%typemap(in,numinputs=1) (oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_TILL_SHUTDOWN;
  jni_list_add(user_data);
  $1 = jni_oc_init_platform_callback;
  $2 = user_data;
}
%ignore oc_init_platform;
/* the oc_init_platform without the callback or data pointer */
%rename(initPlatform) jni_oc_init_platform;
%inline %{
int jni_oc_init_platform(const char *mfg_name) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_init_platform(mfg_name, NULL, NULL);
}
%}
%rename(initPlatform) jni_oc_init_platform1;
%inline %{
int jni_oc_init_platform1(const char *mfg_name, oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  return oc_init_platform(mfg_name, init_platform_cb, jcb);
}
%}

/* Code and typemaps for mapping the oc_random_pin_cb_t to the OCRandomPinHandler */
%{
void jni_oc_random_pin_callback(const unsigned char *pin, size_t pin_len, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);

  assert(cls_OCRandomPinHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCRandomPinHandler,
                                       "handler",
                                       "(Ljava/lang/String;)V");
  assert(mid_handler);

  jstring jpin = JCALL1(NewStringUTF, (data->jenv), (const char *)pin);
  JCALL3(CallVoidMethod, (data->jenv), data->jcb_obj, mid_handler, jpin);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
}
%}

%typemap(jni)    oc_random_pin_cb_t cb "jobject";
%typemap(jtype)  oc_random_pin_cb_t cb "OCRandomPinHandler";
%typemap(jstype) oc_random_pin_cb_t cb "OCRandomPinHandler";
%typemap(javain) oc_random_pin_cb_t cb "$javainput";
%typemap(in,numinputs=1) (oc_random_pin_cb_t cb, jni_callback_data *jcb) {
  // The C code only contains one instance of oc_random_pin_cb_t if setRandomPinHandler is
  // called multiple times we must release the old item.
  jni_callback_data * item = jni_list_get_item_by_callback_valid(OC_CALLBACK_VALID_TILL_SET_RANDOM_PIN_CB);
  if(item) {
    jni_list_remove(item);
  }
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  if(JCALL2(IsSameObject, jenv, $input, NULL))
  {
    user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
    $1 = NULL;
    $2 = user_data;
  } else {
    user_data->cb_valid = OC_CALLBACK_VALID_TILL_SET_RANDOM_PIN_CB;
    $1 = jni_oc_random_pin_callback;
    $2 = user_data;
  }
  jni_list_add(user_data);
}

%ignore oc_set_random_pin_callback;
%rename(setRandomPinHandler) jni_set_random_pin_callback;
%inline %{
void jni_set_random_pin_callback(oc_random_pin_cb_t cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  #ifdef OC_SECURITY
  oc_set_random_pin_callback(cb, jcb);
  #endif /* OC_SECURITY */
}
%}
// DOCUMENTATION workaround
%javamethodmodifiers oc_get_con_res_announced "/**
   * Returns whether the oic.wk.con res is announced.
   *
   * @return true if announced (default) or false if not
   * @see setConResAnnounced
   * @see OCConWriteHandler
   */
  public";
%rename(getConResAnnounced) oc_get_con_res_announced;

// DOCUMENTATION workaround
%javamethodmodifiers oc_set_con_res_announced "/**
   * Sets whether the oic.wk.con res is announced.
   * <p>
   * <strong>Note</strong>: this should be set before invoking OCMain.init().
   *
   * @param announce true to announce (default) or false if not
   *
   * @see getConResAnnounced
   * @see OCConWriteHandler
   */
  public";
%rename(setConResAnnounced) oc_set_con_res_announced;
%ignore oc_reset;
%rename(reset) jni_reset;
%inline %{
void jni_reset() {
  OC_DBG("JNI: %s\n", __func__);
  #ifdef OC_SECURITY
  oc_reset();
  #endif /* OC_SECURITY */
}
%}

%ignore oc_reset_device;
%rename(resetDevice) jni_reset_device;
%inline %{
void jni_reset_device(size_t device) {
  OC_DBG("JNI: %s\n", __func__);
  #ifdef OC_SECURITY
  oc_reset_device(device);
  #endif /* OC_SECURITY */
}
%}

// server side
%rename(newResource) oc_new_resource;
%rename(resourceBindResourceInterface) oc_resource_bind_resource_interface;
%rename(resourceSetDefaultInterface) oc_resource_set_default_interface;
%rename(resourceBindResourceType) oc_resource_bind_resource_type;
%rename(deviceBindResourceType) oc_device_bind_resource_type;
%rename(resourceTagPositionDescription) oc_resource_tag_pos_desc;
%rename(resourceTagPositionRelative) oc_resource_tag_pos_rel;
%rename(resourceTagFunctionDescription) oc_resource_tag_func_desc;
%rename(processBaselineInterface) oc_process_baseline_interface;

// DOCUMENTATION workaround
%javamethodmodifiers oc_new_collection "/**
   * Creates a new empty collection.
   * <p>
   * The collection is created with interfaces `oic.if.baseline`,
   * `oic.if.ll` (also default) and `oic.if.b`. Initially it is neither
   * discoverable nor observable.
   * <p>
   * The function only allocates the collection. Use addCollection() after the
   * setup of the collection is complete.
   *
   * @param name name of the collection
   * @param uri Unique URI of this collection. Must not be NULL
   * @param num_resource_types Number of resources the caller will bind with this resource
   *                           (e.g. by invoking resourceBindResourceType(col, OIC_WK_COLLECTION)).
   *                           Must be 1 or higher
   * @param num_supported_rts number of resource types in links included in the
   *                          collection
   * @param num_mandatory_rts number of mandatory resource types if any in links
   *                          included in the collection
   * @param device The internal device that should carry this collection. This is typically 0
   * @return the new collection or NULL if out of memory.
   * @see addCollection
   * @see collectionAddLink
   */
  public";
%rename(newCollection) oc_new_collection;

// DOCUMENTATION workaround
%javamethodmodifiers oc_delete_collection "/**
   * Deletes the specified collection.
   * <p>
   * The function removes the collection from the internal list of collections
   * and releases all direct resources and links associated with this collection.
   * <p>
   * Note: The function does not delete the resources set in the links.
   *  The caller needs to do this on their own in case these are
   *  no longer required.
   *
   * @param collection The pointer to the collection to delete.
   *                   If this is NULL, the function does nothing
   *
   * @see collectionGetLinks
   * @see deleteLink
   */
  public";
%rename(deleteCollection) oc_delete_collection;

// DOCUMENTATION workaround
%javamethodmodifiers oc_new_link "/**
   * Creates a new link for collections with the specified resource.
   *
   * @param resource Resource to set in the link. The resource is not copied.
   *  Must not be NULL
   *
   * @return The created link or NULL if out of memory or resource is NULL.
   *
   * @see deleteLink
   * @see collectionAddLink
   * @see newResource
   */
  public";
%rename(newLink) oc_new_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_delete_link "/**
   * Deletes the link.
   * <p>
   * <strong>Note</strong>: the function neither removes the resource set on this link
   *  nor does it remove it from any collection.
   *
   * @param link The link to delete. The function does nothing, if
   *  the parameter is NULL
   */
  public";
%rename(deleteLink) oc_delete_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_link_add_rel "/**
   * Adds a relation to the link.
   *
   * @param link Link to add the relation to. Must not be null
   * @param rel Relation to add. Must not be null
   */
  public";
%rename(linkAddRelation) oc_link_add_rel;

// DOCUMENTATION workaround
%javamethodmodifiers oc_link_add_link_param "/**
   * Adds a link parameter with specified key and value.
   *
   * @param link Link to which to add a link parameter. Must not be null.
   * @param key Key to identify the link parameter. Must not be null.
   * @param value Link parameter value. Must not be null.
   */
  public";
%rename(linkAddLinkParameter) oc_link_add_link_param;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_add_link "/**
   * Adds the link to the collection.
   * <p>
   * The collection and link must not be null.
   * <p>
   * The link is not copied. The link Must not be added again to this or a
   * different collection; this will cause a list corruption to occur. To re-add
   * a link, remove the link first.
   *
   * @param collection Collection to add the link to. Must not be NULL.
   * @param link Link to add to the collection 
   *
   * @see newLink
   * @see collectionRemoveLink
   */
  public";
%rename(collectionAddLink) oc_collection_add_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_remove_link "/**
   * Removes a link from the collection.
   * <p>
   * Does nothing if the collection or link is null.
   * <p>
   * Does nothing if the link is not part of the collection.
   * <p>
   * @param collection Collection to remove the link from
   * @param link The link to remove
   */
  public";
%rename(collectionRemoveLink) oc_collection_remove_link;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_get_links "/**
   * Returns the list of links belonging to this collection.
   *
   * @param collection Collection to get the links from.
   *
   * @return All links of this collection. The links are not copied. Returns
   *  null if the collection is null or contains no links.
   *
   * @see collectionAddLink
   */
  public";
%rename(collectionGetLinks) oc_collection_get_links;

// DOCUMENTATION workaround
%javamethodmodifiers oc_add_collection "/**
   * Adds a collection to the list of collections.
   * <p>
   * If the caller makes the collection discoverable, then it will
   * be included in the collection discovery once it has been added
   * with this function.
   * <p>
   * The collection must not be null. Must not be added twice or a list corruption
   * will occur. The collection is not copied.
   *
   * @param collection Collection to add to the list of collections
   *
   * @see resourceSetDiscoverable
   * @see newCollection
   */
  public";
%rename(addCollection) oc_add_collection;

// DOCUMENTATION workaround
%javamethodmodifiers oc_collection_get_collections "/**
   * Gets all known collections.
   *
   * @return All collections that have been added via addCollection(). The
   * collections are not copied.  Returns null if there are no collections.
   * Collections created using newCollection() but not added will not be
   * returned by this method.
   */
  public";
%rename(collectionGetCollections) oc_collection_get_collections;
%rename(collectionAddSupportedResourceType) oc_collection_add_supported_rt;
%rename(collectionAddMandatoryResourceType) oc_collection_add_mandatory_rt;
// custom instance of oc_resource_make_public to handle OC_SECURITY
%ignore oc_resource_make_public;
%rename(resourceMakePublic) jni_resource_make_public;
%inline %{
void jni_resource_make_public(oc_resource_t *resource) {
  OC_DBG("JNI: %s\n", __func__);
#ifdef OC_SECURITY
  oc_resource_make_public(resource);
#endif /* OC_SECURITY */
}
%}
%rename(resourceSetDiscoverable) oc_resource_set_discoverable;
%rename(resourceSetObservable) oc_resource_set_observable;
%rename(resourceSetPeriodicObservable) oc_resource_set_periodic_observable;

/* Code and typemaps for mapping the oc_resource_set_request_handler to the java OCRequestHandler */
%{
void jni_oc_request_callback(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCRequestHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCRequestHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCRequest;I)V");
  assert(mid_handler);

  jobject jrequest = NULL;
  if (request) {
    assert(cls_OCRequest);
    const jmethodID mid_OCRequest_init = JCALL3(GetMethodID, (data->jenv), cls_OCRequest, "<init>", "(JZ)V");
    assert(mid_OCRequest_init);
    jrequest = JCALL4(NewObject, (data->jenv), cls_OCRequest, mid_OCRequest_init, (jlong)request, false);
  }
  JCALL4(CallVoidMethod,
         (data->jenv),
         data->jcb_obj,
         mid_handler,
         jrequest,
         (jint)interfaces);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
}
%}
%typemap(jni)    oc_request_callback_t callback "jobject";
%typemap(jtype)  oc_request_callback_t callback "OCRequestHandler";
%typemap(jstype) oc_request_callback_t callback "OCRequestHandler";
%typemap(javain) oc_request_callback_t callback "$javainput";
%typemap(in,numinputs=1) (oc_request_callback_t callback, jni_callback_data *jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  // see jni_delete_resource for the deletion of the GlobalRef in the jni_list_remove calls
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_TILL_DELETE_RESOURCE;
  jni_list_add(user_data);
  $1 = jni_oc_request_callback;
  $2 = user_data;
}
%ignore oc_resource_set_request_handler;
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler;
%inline %{
void jni_oc_resource_set_request_handler(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback,
                                          jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  oc_resource_set_request_handler(resource, method, callback, jcb);
}
%}
/* Code and typemaps for mapping the oc_get_properties_cb_t to the java OCGetPropertiesHandler */
%{
void jni_oc_get_properties_callback(oc_resource_t *resource, oc_interface_mask_t iface_mask, void *user_data) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCGetPropertiesHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCGetPropertiesHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCResource;I)V");
  assert(mid_handler);

  jobject jresource = NULL;
  if (resource) {
    assert(cls_OCResource);
    const jmethodID mid_OCResource_init = JCALL3(GetMethodID, (data->jenv), cls_OCResource, "<init>", "(JZ)V");
    assert(mid_OCResource_init);
    jresource = JCALL4(NewObject, (data->jenv), cls_OCResource, mid_OCResource_init, (jlong)resource, false);
  }
  JCALL4(CallVoidMethod,
         (data->jenv),
         data->jcb_obj,
         mid_handler,
         jresource,
         (jint)iface_mask);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
}
%}
%typemap(jni)    oc_get_properties_cb_t getPropertiesHandler "jobject";
%typemap(jtype)  oc_get_properties_cb_t getPropertiesHandler "OCGetPropertiesHandler";
%typemap(jstype) oc_get_properties_cb_t getPropertiesHandler "OCGetPropertiesHandler";
%typemap(javain) oc_get_properties_cb_t getPropertiesHandler "$javainput";
%typemap(in,numinputs=1) (oc_get_properties_cb_t getPropertiesHandler, jni_callback_data *get_properties_jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  // see jni_delete_resource for the deletion of the GlobalRef in the jni_list_remove calls
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_get_properties_callback;
  $2 = user_data;
}

/* Code and typemaps for mapping the oc_set_properties_cb_t to the java OCSetPropertiesHandler */
%{
bool jni_oc_set_properties_callback(oc_resource_t *resource, oc_rep_t *rep, void *user_data) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCSetPropertiesHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCSetPropertiesHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCResource;Lorg/iotivity/OCRepresentation;)Z");
  assert(mid_handler);

  jobject jresource = NULL;
  if (resource) {
    assert(cls_OCResource);
    const jmethodID mid_OCResource_init = JCALL3(GetMethodID, (data->jenv), cls_OCResource, "<init>", "(JZ)V");
    assert(mid_OCResource_init);
    jresource = JCALL4(NewObject, (data->jenv), cls_OCResource, mid_OCResource_init, (jlong)resource, false);
  }

  jobject jrep = NULL;
  if (rep) {
    assert(cls_OCRepresentation);
    const jmethodID mid_OCRepresentation_init = JCALL3(GetMethodID,
                                                       (data->jenv),
                                                       cls_OCRepresentation, "<init>",
                                                       "(JZ)V");
    assert(mid_OCRepresentation_init);
    jrep = JCALL4(NewObject, (data->jenv), cls_OCRepresentation, mid_OCRepresentation_init, (jlong)rep, false);
  }

  bool returnValue = JCALL4(CallBooleanMethod,
                            (data->jenv),
                            data->jcb_obj,
                            mid_handler,
                            jresource,
                            jrep);

  if (data->cb_valid == OC_CALLBACK_VALID_FOR_A_SINGLE_CALL) {
    jni_list_remove(data);
  }

  release_jni_env(getEnvResult);
  return returnValue;
}
%}
%typemap(jni)    oc_set_properties_cb_t setPropertiesHandler "jobject";
%typemap(jtype)  oc_set_properties_cb_t setPropertiesHandler "OCSetPropertiesHandler";
%typemap(jstype) oc_set_properties_cb_t setPropertiesHandler "OCSetPropertiesHandler";
%typemap(javain) oc_set_properties_cb_t setPropertiesHandler "$javainput";
%typemap(in,numinputs=1) (oc_set_properties_cb_t setPropertiesHandler, jni_callback_data *set_properties_jcb)
{
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  // see jni_delete_resource for the deletion of the GlobalRef in the jni_list_remove calls
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_set_properties_callback;
  $2 = user_data;
}

%ignore oc_resource_set_properties_cbs;
%rename(resourceSetPropertiesHandlers) jni_resource_set_properties_cbs;
%inline %{
void jni_resource_set_properties_cbs(oc_resource_t *resource,
                                     oc_get_properties_cb_t getPropertiesHandler,
                                     jni_callback_data *get_properties_jcb,
                                     oc_set_properties_cb_t setPropertiesHandler,
                                     jni_callback_data *set_properties_jcb) {
  OC_DBG("JNI: %s\n", __func__);
  oc_resource_set_properties_cbs(resource, getPropertiesHandler, get_properties_jcb, setPropertiesHandler, set_properties_jcb);
}
%}
%rename(addResource) oc_add_resource;
%ignore oc_delete_resource;
%rename(deleteResource) jni_delete_resource;
%inline %{
bool jni_delete_resource(oc_resource_t *resource) {
  if(resource) {
    if(resource->get_handler.user_data) {
      jni_callback_data *data = (jni_callback_data *)resource->get_handler.user_data;
      assert(data->cb_valid == OC_CALLBACK_VALID_TILL_DELETE_RESOURCE);
      jni_list_remove(data);
    }
    if(resource->put_handler.user_data) {
      jni_callback_data *data = (jni_callback_data *)resource->put_handler.user_data;
      assert(data->cb_valid == OC_CALLBACK_VALID_TILL_DELETE_RESOURCE);
      jni_list_remove(data);
    }
    if(resource->post_handler.user_data) {
      jni_callback_data *data = (jni_callback_data *)resource->post_handler.user_data;
      assert(data->cb_valid == OC_CALLBACK_VALID_TILL_DELETE_RESOURCE);
      jni_list_remove(data);
    }
    if(resource->delete_handler.user_data) {
      jni_callback_data *data = (jni_callback_data *)resource->delete_handler.user_data;
      assert(data->cb_valid == OC_CALLBACK_VALID_TILL_DELETE_RESOURCE);
      jni_list_remove(data);
    }
  }
  return oc_delete_resource(resource);
}
%}

/*
 * Code and typemaps for mapping the `oc_set_con_write_cb` to the java `OCConWriteHandler`
 * Since `oc_set_con_write_cb` does not have a `void *user_data` to pass the JNIEnv and the callback
 * java object a global instance of this information is created for the `oc_set_con_write_cb` named
 * `oc_con_write_cb_data`.
 */
%{
static struct jni_callback_data_s oc_con_write_cb_data;

void jni_oc_con_callback(size_t device_index, oc_rep_t *rep)
{
  OC_DBG("JNI: %s\n", __func__);

  assert(cls_OCConWriteHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (oc_con_write_cb_data.jenv),
                                       cls_OCConWriteHandler,
                                       "handler",
                                       "(JLorg/iotivity/OCRepresentation;)V");
  assert(mid_handler);

  jobject jrep = NULL;
  if (rep) {
    assert(cls_OCRepresentation);
    const jmethodID mid_OCRepresentation_init = JCALL3(GetMethodID,
                                                       (oc_con_write_cb_data.jenv),
                                                       cls_OCRepresentation, "<init>",
                                                       "(JZ)V");
    assert(mid_OCRepresentation_init);
    jrep = JCALL4(NewObject, (oc_con_write_cb_data.jenv),
                  cls_OCRepresentation,
                  mid_OCRepresentation_init,
                  (jlong)rep,
                  false);
  }
  JCALL4(CallVoidMethod, (oc_con_write_cb_data.jenv),
         oc_con_write_cb_data.jcb_obj,
         mid_handler,
         (jlong)device_index,
         jrep);
}
%}
%typemap(jni)    oc_con_write_cb_t callback "jobject";
%typemap(jtype)  oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(jstype) oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(javain) oc_con_write_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_con_write_cb_t callback)
{
  //Delete GlobalRef on old callback jcb_obj if this method is called multiple times
  if(oc_con_write_cb_data.cb_valid == OC_CALLBACK_VALID_TILL_SET_CON_WRITE_CB) {
    JCALL1(DeleteGlobalRef, jenv, oc_con_write_cb_data.jcb_obj);
  }
  oc_con_write_cb_data.jenv = jenv;
  oc_con_write_cb_data.jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  if(JCALL2(IsSameObject, jenv, $input, NULL))
  {
    oc_con_write_cb_data.cb_valid = OC_CALLBACK_VALID_UNKNOWN;
    $1 = NULL;
  } else {
    oc_con_write_cb_data.cb_valid = OC_CALLBACK_VALID_TILL_SET_CON_WRITE_CB;
    $1 = jni_oc_con_callback;
  }
}
// DOCUMENTATION workaround
%javamethodmodifiers oc_set_con_write_cb "/**
   * Sets the callback handler to receive change notifications for
   * the oic.wk.con resource.
   * <p>
   * The method can be used to set or unset the callback handler.
   * Whenever an attribute of the oic.wk.con resource is changed,
   * the callback will be invoked.
   * <p>
   * If the method is invoked a second time, then the previously set callback
   * handler is replaced.
   *
   * @param callback The callback handler to register or null to unset it
   */
  public";
%rename(setConWriteHandler) oc_set_con_write_cb;

%ignore oc_init_query_iterator;
%ignore oc_iterate_query;
%ignore oc_get_query_value;
%ignore oc_iterate_query_get_values;

%typemap(jni)    jobject getQueryValues "jobject";
%typemap(jtype)  jobject getQueryValues "java.util.List<OCQueryValue>";
%typemap(jstype) jobject getQueryValues "java.util.List<OCQueryValue>";
%typemap(javain) jobject getQueryValues "$javainput";
%pragma(java) jniclassimports="import java.util.List;"
%native (getQueryValues) jobject getQueryValues(oc_request_t *request);
%{
#ifdef __cplusplus
extern "C"
#endif
SWIGEXPORT jobject JNICALL Java_org_iotivity_OCMainJNI_getQueryValues(JNIEnv *jenv,
                                                                      jclass jcls,
                                                                      jlong jrequest,
                                                                      jobject jrequest_)
{
  jobject jresult = 0;
  oc_request_t *request = (oc_request_t *)0;
  jobject result;

  (void)jenv;
  (void)jcls;
  (void)jrequest_;
  request = *(oc_request_t **)&jrequest;

  assert(cls_ArrayList);
  jmethodID mid_arrayListConstructor = JCALL3(GetMethodID, jenv, cls_ArrayList, "<init>", "()V");
  jmethodID mid_add = JCALL3(GetMethodID, jenv, cls_ArrayList, "add", "(Ljava/lang/Object;)Z");

  jmethodID mid_OCQueryConstructor = JCALL3(GetMethodID,
                                            jenv,
                                            cls_OCQueryValue,
                                            "<init>",
                                            "(Ljava/lang/String;Ljava/lang/String;)V");

  result = JCALL2(NewObject, jenv, cls_ArrayList, mid_arrayListConstructor);

  char *current_key = 0;
  size_t key_len = 0;
  char *current_value;
  size_t value_len = 0;
  char temp_buffer[512];
  int pos = 0;

  oc_init_query_iterator();
  do {
    pos = oc_iterate_query(request, &current_key, &key_len, &current_value, &value_len);
    // check that a value was found and it will fit in the temp_buffer with room for the '\0' char
    if (pos != -1 && key_len < 512 && value_len < 512) {
      strncpy(temp_buffer, current_key, key_len);
      temp_buffer[key_len] = '\0';
      jstring jkey = JCALL1(NewStringUTF, jenv, temp_buffer);

      strncpy(temp_buffer, current_value, value_len);
      temp_buffer[value_len] = '\0';
      jstring jvalue = JCALL1(NewStringUTF, jenv, temp_buffer);

      jobject jQueryValue = JCALL4(NewObject,
                                   jenv,
                                   cls_OCQueryValue,
                                   mid_OCQueryConstructor,
                                   jkey,
                                   jvalue);
      JCALL3(CallBooleanMethod, jenv, result, mid_add, jQueryValue);
    }
  } while (pos != -1);

  jresult = result;
  return jresult;
}
%}


%rename(sendResponse) oc_send_response;
%rename(ignoreRequest) oc_ignore_request;
%rename(indicateSeparateResponse) oc_indicate_separate_response;
%rename(setSeparateResponseBuffer) oc_set_separate_response_buffer;
%rename(sendSeparateResponse) oc_send_separate_response;
%rename(notifyObservers) oc_notify_observers;

// client side
%{
oc_discovery_flags_t
jni_oc_discovery_handler_callback(const char *anchor, const char *uri,
                                  oc_string_array_t types,
                                  oc_interface_mask_t interfaces,
                                  oc_endpoint_t *endpoint,
                                  oc_resource_properties_t bm, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  jstring janchor = JCALL1(NewStringUTF, (data->jenv), anchor);
  jstring juri = JCALL1(NewStringUTF, (data->jenv), uri);
  jobjectArray jtypes =
    JCALL3(NewObjectArray, (data->jenv),
           (jsize)oc_string_array_get_allocated_size(types),
           JCALL1(FindClass, (data->jenv), "java/lang/String"), 0);
  for (jsize i = 0; i < (jsize)oc_string_array_get_allocated_size(types); i++) {
    jstring str =
      JCALL1(NewStringUTF, (data->jenv), oc_string_array_get_item(types, i));
    JCALL3(SetObjectArrayElement, (data->jenv), jtypes, i, str);
  }
  jint jinterfaceMask = (jint)interfaces;

  // create java endpoint
  assert(cls_OCEndpoint);
  const jmethodID mid_OCEndpoint_init =
    JCALL3(GetMethodID, (data->jenv), cls_OCEndpoint, "<init>", "(JZ)V");
  assert(mid_OCEndpoint_init);
  jobject jendpoint = JCALL4(NewObject, (data->jenv), cls_OCEndpoint,
                             mid_OCEndpoint_init, (jlong)endpoint, false);

  jint jresourcePropertiesMask = (jint)bm;
  assert(cls_OCDiscoveryHandler);
  const jmethodID mid_handler =
    JCALL3(GetMethodID, (data->jenv), cls_OCDiscoveryHandler, "handler",
           "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ILorg/"
           "iotivity/OCEndpoint;I)Lorg/iotivity/OCDiscoveryFlags;");
  assert(mid_handler);
  jobject jDiscoveryFlag =
    JCALL8(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler, janchor,
           juri, jtypes, jinterfaceMask, jendpoint, jresourcePropertiesMask);
  jclass cls_DiscoveryFlags =
    JCALL1(GetObjectClass, (data->jenv), jDiscoveryFlag);
  assert(cls_DiscoveryFlags);
  const jmethodID mid_OCDiscoveryFlags_swigValue =
    JCALL3(GetMethodID, (data->jenv), cls_DiscoveryFlags, "swigValue", "()I");
  assert(mid_OCDiscoveryFlags_swigValue);
  jint return_value = JCALL2(CallIntMethod, (data->jenv), jDiscoveryFlag,
                             mid_OCDiscoveryFlags_swigValue);

  release_jni_env(getEnvResult);

  return (oc_discovery_flags_t)return_value;
}
%}
/*
 * Code and typemaps for mapping the oc_do_ip_discovery and oc_do_ip_discovery_at_endpoint to the
 * java OCDiscoveryHandler
 */
%typemap(jni)    oc_discovery_handler_t handler "jobject";
%typemap(jtype)  oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(jstype) oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(javain) oc_discovery_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_discovery_handler_t handler, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  // TODO figure out the lifetime of the oc_discovery_handler_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_discovery_handler_callback;
  $2 = user_data;
}

/*
 * Code and typemaps for mapping the oc_do_ip_discovery and oc_do_ip_discovery_at_endpoint to the
 * java OCDiscoveryHandler
 */
%typemap(jni)    oc_discovery_all_handler_t handler "jobject";
%typemap(jtype)  oc_discovery_all_handler_t handler "OCDiscoveryAllHandler";
%typemap(jstype) oc_discovery_all_handler_t handler "OCDiscoveryAllHandler";
%typemap(javain) oc_discovery_all_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_discovery_all_handler_t handler, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  // TODO figure out the lifetime of the oc_discovery_all_handler_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_discovery_all_handler_callback;
  $2 = user_data;
}

%ignore oc_do_site_local_ipv6_discovery;
%rename(doSiteLocalIPv6Discovery) jni_do_site_local_ipv6_discovery;
%inline %{
bool jni_do_site_local_ipv6_discovery(const char *rt,
                                      oc_discovery_handler_t handler,
                                      jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_site_local_ipv6_discovery(rt, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_site_local_ipv6_discovery_all;
%rename(doSiteLocalIPv6DiscoveryAll) jni_do_site_local_ipv6_discovery_all;
%inline %{
bool jni_do_site_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                          jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_site_local_ipv6_discovery_all(handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_realm_local_ipv6_discovery;
%rename(doRealmLocalIPv6Discovery) jni_do_realm_local_ipv6_discovery;
%inline %{
bool jni_do_realm_local_ipv6_discovery(const char *rt,
                                       oc_discovery_handler_t handler,
                                       jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_realm_local_ipv6_discovery(rt, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_realm_local_ipv6_discovery_all;
%rename(doRealmLocalIPv6DiscoveryAll) jni_do_realm_local_ipv6_discovery_all;
%inline %{
bool jni_do_realm_local_ipv6_discovery_all(oc_discovery_all_handler_t handler,
                                           jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_realm_local_ipv6_discovery_all(handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_ip_discovery;
%rename(doIPDiscovery) jni_oc_do_ip_discovery;
%inline %{
bool jni_oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_ip_discovery(rt, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_ip_discovery_all;
%rename(doIPDiscoveryAll) jni_oc_do_ip_discovery_all;
%inline %{
bool jni_oc_do_ip_discovery_all(oc_discovery_all_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_ip_discovery_all(handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_oc_do_ip_discovery_at_endpoint "/**
   * Discover resources in specific endpoint.
   * <p>
   * The callback handler and endpoint <strong>must not</strong> be null.
   * @param  rt         Resource type query to discover
   * @param  handler    The callback handler for discovered resources
   * @param  endpoint   Endpoint at which to discover resources
   *
   * @return Returns true if it successfully makes and dispatches a coap packet.
   */
  public";
%ignore oc_do_ip_discovery_at_endpoint;
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint;
%inline %{
bool jni_oc_do_ip_discovery_at_endpoint(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_ip_discovery_all_at_endpoint;
%rename(doIPDiscoveryAllAtEndpoint) jni_oc_do_ip_discovery_all_at_endpoint;
%inline %{
bool jni_oc_do_ip_discovery_all_at_endpoint(oc_discovery_all_handler_t handler, jni_callback_data *jcb,
                                            oc_endpoint_t *endpoint)
{
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_ip_discovery_all_at_endpoint(handler, endpoint, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

/* Code and typemaps for mapping the oc_do_get, oc_do_delete, oc_init_put, oc_init_post, oc_do_observe,
 * and oc_do_ip_multicast to the java OCResponseHandler */
%{
void jni_oc_response_handler(oc_client_response_t *response)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)response->user_data;

  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCResponseHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCResponseHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCClientResponse;)V");
  assert(mid_handler);

  jobject jresponse = NULL;
  if (response) {
    assert(cls_OCClientResponse);
    const jmethodID mid_OCClientResponse_init = JCALL3(GetMethodID,
                                                       (data->jenv),
                                                       cls_OCClientResponse,
                                                       "<init>",
                                                       "(JZ)V");
    assert(mid_OCClientResponse_init);
    jresponse = JCALL4(NewObject, (data->jenv),
                       cls_OCClientResponse,
                       mid_OCClientResponse_init,
                       (jlong)response,
                       false);
  }

  JCALL3(CallVoidMethod, (data->jenv), data->jcb_obj, mid_handler, jresponse);

  release_jni_env(getEnvResult);
}
%}
%typemap(jni)    oc_response_handler_t handler "jobject";
%typemap(jtype)  oc_response_handler_t handler "OCResponseHandler";
%typemap(jstype) oc_response_handler_t handler "OCResponseHandler";
%typemap(javain) oc_response_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_response_handler_t handler, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  // TODO figure out the lifetime of the oc_response_handler_t
  user_data->cb_valid = OC_CALLBACK_VALID_UNKNOWN;
  jni_list_add(user_data);
  $1 = jni_oc_response_handler;
  $2 = user_data;
}
%ignore oc_do_get;
%rename(doGet) jni_oc_do_get;
%inline %{
bool jni_oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler,  jni_callback_data *jcb,
                   oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_get(uri, endpoint, query, handler, qos, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_delete;
%rename(doDelete) jni_oc_do_delete;
%inline %{
bool jni_oc_do_delete(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos){
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_delete(uri, endpoint, query, handler, qos, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_init_put;
%rename(initPut) jni_oc_init_put;
%inline %{
bool jni_oc_init_put(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool returnValue = oc_init_put(uri, endpoint, query, handler, qos, jcb);
  if (returnValue == false) {
    jni_mutex_unlock(jni_sync_lock);
    OC_DBG("JNI - initPut failed releasing jni_sync_lock");
    OC_DBG("JNI: - unlock %s\n", __func__);
  }
  return returnValue;
}
%}

%ignore oc_do_put;
%rename(doPut) jni_do_put;
%inline %{
bool jni_do_put(void) {
  bool return_value = oc_do_put();
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_init_post;
%rename(initPost) jni_oc_init_post;
%inline %{
bool jni_oc_init_post(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool returnValue = oc_init_post(uri, endpoint, query, handler, qos, jcb);
  if (returnValue == false) {
    jni_mutex_unlock(jni_sync_lock);
    OC_DBG("JNI - initPost failed releasing jni_sync_lock");
    OC_DBG("JNI: - unlock %s\n", __func__);
  }
  return returnValue;
}
%}

%ignore oc_do_post;
%rename(doPost) jni_do_post;
%inline %{
bool jni_do_post(void) {
  bool return_value = oc_do_post();
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_observe;
%rename(doObserve) jni_oc_do_observe;
%inline %{
bool jni_oc_do_observe(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_observe(uri, endpoint, query, handler, qos, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_stop_observe;
%rename(stopObserve) jni_stop_observe;
%inline %{
bool jni_stop_observe(const char *uri, oc_endpoint_t *endpoint) {
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_stop_observe(uri, endpoint);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_realm_local_ipv6_multicast;
%rename(doRealmLocalIPv6Multicast) jni_do_realm_local_ipv6_multicast;
%inline %{
bool jni_do_realm_local_ipv6_multicast(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_realm_local_ipv6_multicast(uri, query, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_site_local_ipv6_multicast;
%rename(doSiteLocalIPv6Multicast) jni_do_site_local_ipv6_multicast;
%inline %{
bool jni_do_site_local_ipv6_multicast(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_site_local_ipv6_multicast(uri, query, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_do_ip_multicast;
%rename(doIPMulticast) jni_oc_do_ip_multicast;
%inline %{
bool jni_oc_do_ip_multicast(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_do_ip_multicast(uri, query, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
}
%}

%ignore oc_stop_multicast;
%rename(stopMulticast) jni_stop_multicast;
%inline %{
void jni_stop_multicast(oc_client_response_t *response) {
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_stop_multicast(response);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
}
%}

%ignore oc_free_server_endpoints;
%rename(freeServerEndpoints) jni_free_server_endpoints;
%inline %{
void jni_free_server_endpoints(oc_endpoint_t *endpoints) {
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_free_server_endpoints(endpoints);
  endpoints = NULL;
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
}
%}

%rename(closeSession) oc_close_session;
%rename(OCRole) oc_role_t;
%nodefaultctor oc_role_t;
%nodefaultdtor oc_role_t;
%immutable oc_role_t::role;
%immutable oc_role_t::authority;
%ignore oc_get_all_roles;
%rename(getAllRoles) jni_get_all_roles;
%inline %{
oc_role_t *jni_get_all_roles(void) {
#if defined(OC_SECURITY) && defined(OC_PKI)
  return oc_get_all_roles();
#else
  return NULL;
#endif /* OC_SECURITY && OC_PKI */
}
%}

%ignore oc_assert_role;
%rename(assertRole) jni_assert_role;
%inline %{
bool jni_assert_role(const char *role, const char *authority, oc_endpoint_t *endpoint,
                     oc_response_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_assert_role(role, authority, endpoint, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else
  return false;
#endif /* OC_SECURITY && OC_PKI */
}
%}

%ignore oc_auto_assert_roles;
%rename(autoAssertRoles) jni_auto_assert_roles;
%inline %{
void jni_auto_assert_roles(bool auto_assert) {
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_auto_assert_roles(auto_assert);
#endif /* OC_SECURITY && OC_PKI */
}
%}

%ignore oc_assert_all_roles;
%rename(assertAllRoles) jni_assert_all_roles;
%inline %{
void jni_assert_all_roles(oc_endpoint_t *endpoint, oc_response_handler_t handler, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_assert_all_roles(endpoint, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
#endif /* OC_SECURITY && OC_PKI */
}
%}
%ignore oc_send_ping;
%rename(sendPing) jni_send_ping;
%inline %{
bool jni_send_ping(bool custody, oc_endpoint_t *endpoint, uint16_t timeout_seconds,
                   oc_response_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_TCP)
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  bool return_value = oc_send_ping(custody, endpoint, timeout_seconds, handler, jcb);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  return return_value;
#else
  return false;
#endif /* OC_TCP */
}
%}

// common operations
%rename(setImmutableDeviceIdentifier) oc_set_immutable_device_identifier;
/* Code and typemaps for mapping the oc_set_delayed_callback to the java OCTriggerHandler */
%{
oc_event_callback_retval_t jni_oc_trigger_handler(void* cb_data) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)cb_data;
  assert(data);
  jint getEnvResult = 0;
  data->jenv = get_jni_env(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCTriggerHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCTriggerHandler,
                                       "handler",
                                       "()Lorg/iotivity/OCEventCallbackResult;");
  assert(mid_handler);
  jobject jEventCallbackRet = JCALL2(CallObjectMethod,
                                     (data->jenv),
                                     data->jcb_obj,
                                     mid_handler);
  assert(jEventCallbackRet);
  jclass cls_OCEventCallbackResult = JCALL1(GetObjectClass, (data->jenv), jEventCallbackRet);
  assert(cls_OCEventCallbackResult);
  const jmethodID mid_OCEventCallbackResult_swigValue = JCALL3(GetMethodID,
                                                               (data->jenv),
                                                               cls_OCEventCallbackResult,
                                                               "swigValue",
                                                               "()I");
  assert(mid_OCEventCallbackResult_swigValue);
  jint return_value = JCALL2(CallIntMethod,
                             (data->jenv),
                             jEventCallbackRet,
                             mid_OCEventCallbackResult_swigValue);
  return (oc_event_callback_retval_t) return_value;
}
%}
%typemap(jni)    oc_trigger_t callback "jobject";
%typemap(jtype)  oc_trigger_t callback "OCTriggerHandler";
%typemap(jstype) oc_trigger_t callback "OCTriggerHandler";
%typemap(javain) oc_trigger_t callback "$javainput";
%typemap(in,numinputs=1) (oc_trigger_t callback, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  user_data->cb_valid = OC_CALLBACK_VALID_TILL_REMOVE_DELAYED_CALLBACK;
  jni_list_add(user_data);
  $1 = jni_oc_trigger_handler;
  $2 = user_data;
}
%ignore oc_set_delayed_callback;
%rename(setDelayedHandler) jni_oc_set_delayed_callback;
%inline %{
void jni_oc_set_delayed_callback(oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __func__);
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_set_delayed_callback(jcb, callback, seconds);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
}
%}

// TODO consider renaming the `jobject callback` to be less generic
%typemap(jtype)  jobject callback "OCTriggerHandler";
%typemap(jstype) jobject callback "OCTriggerHandler";
%ignore oc_remove_delayed_callback;
%rename(removeDelayedHandler) jni_oc_remove_delayed_callback;
/*
 * Version of oc_remove_delayed_callback that also removes java GlobalRefs and frees memory
 * associated with the now removed java callback handler
 */
%inline %{
void jni_oc_remove_delayed_callback(jobject callback) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *item = jni_list_get_item_by_java_callback(callback);
  if (item) {
    assert(item->cb_valid == OC_CALLBACK_VALID_TILL_REMOVE_DELAYED_CALLBACK);
    oc_remove_delayed_callback(item, jni_oc_trigger_handler);
  }
  jni_list_remove(item);
}
%}
%include "oc_api.h"

/*******************Begin oc_client_state.h*****************/
/* 
 * NOTE: currently We only expose callbacks and enum types from oc_client_state.h
 * This is why we are not currently using an independent swig interface file. It
 * would just create an empty Java class. If any functions are exposed this should
 * be moved to its own interface file. (i.e. oc_ri_alloc_client_cb,
 * oc_ri_get_client_cb, etc.)
 */
/* TODO check if any of these ignored functions and data types are needed */
%rename(OCQos) oc_qos_t;
%rename(OCClientResponse) oc_client_response_t;
%ignore user_data;
%ignore client_cb;
%rename(OCDiscoveryFlags) oc_discovery_flags_t;
%ignore oc_client_handler_s;
%ignore oc_client_handler_t;
%ignore oc_response_handler_t;
%ignore oc_discovery_handler_t;
%ignore oc_discovery_all_handler_t;
%rename (OCClientCallback) oc_client_cb_t;
%ignore oc_client_cb_t::handler; /*part of the oc_client_cb_t */
%ignore oc_client_cb_t::user_data;
%rename(observeSeq) oc_client_cb_t::observe_seq;
%rename(tokenLen) oc_client_cb_t::token_len;
%rename(stopMulticastReceive) oc_client_cb_t::stop_multicast_receive;
%rename(refCount) oc_client_cb_t::ref_count;
%ignore oc_ri_invoke_client_cb;
%ignore oc_ri_alloc_client_cb;
%ignore oc_ri_get_client_cb;
%ignore oc_ri_find_client_cb_by_token;
%ignore oc_ri_find_client_cb_by_mid;
%ignore oc_ri_remove_client_cb_by_mid;
%ignore oc_ri_free_client_cbs_by_endpoint;
%ignore oc_ri_free_client_cbs_by_mid;
%ignore oc_ri_process_discovery_payload;
%include "oc_client_state.h"
/*******************End oc_client_state.h*******************/
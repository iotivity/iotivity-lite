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
%import "oc_rep.i"
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

#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include "oc_helpers.h"
#include <assert.h>
%}

/* Code and typemaps for mapping the oc_main_init to the java OCMainInitHandler */
%{
static jobject jinit_obj;
static jclass cls_ArrayList;
static jclass cls_OCMainInitHandler;
static jclass cls_OCAddDeviceHandler;
static jclass cls_OCClientResponse;
static jclass cls_OCConWriteHandler;
static jclass cls_OCDiscoveryHandler;
static jclass cls_OCFactoryPresetsHandler;
static jclass cls_OCInitPlatformHandler;
static jclass cls_OCQueryValue;
static jclass cls_OCRandomPinHandler;
static jclass cls_OCRepresentation;
static jclass cls_OCRequest;
static jclass cls_OCRequestHandler;
static jclass cls_OCResponseHandler;
static jclass cls_OCTriggerHandler;

jclass cls_OCEndpoint;
jclass cls_OCUuid;
jclass cls_OCObtDiscoveryHandler;
jclass cls_OCObtDeviceStatusHandler;
jclass cls_OCObtStatusHandler;

/* Callback handlers for oc_main_init */
int jni_oc_handler_init_callback(void)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_initialize = JCALL3(GetMethodID, jenv, cls_OCMainInitHandler, "initialize", "()I");
  assert(mid_initialize);
  jint ret_value = JCALL2(CallIntMethod, jenv, jinit_obj, mid_initialize);

  ReleaseJNIEnv(getEnvResult);
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
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_registerResources = JCALL3(GetMethodID, jenv, cls_OCMainInitHandler, "registerResources", "()V");
  assert(mid_registerResources);
  JCALL2(CallVoidMethod, jenv, jinit_obj, mid_registerResources);

  ReleaseJNIEnv(getEnvResult);
}

void jni_oc_handler_requests_entry_callback(void)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_requestEntry_method = JCALL3(GetMethodID, jenv, cls_OCMainInitHandler, "requestEntry", "()V");
  assert(mid_requestEntry_method);
  JCALL2(CallVoidMethod, jenv, jinit_obj, mid_requestEntry_method);

  ReleaseJNIEnv(getEnvResult);
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
  JCALL1(GetJavaVM, jenv, &jvm);
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
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);
  assert(jenv);

  jclass ocAddDeviceHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCAddDeviceHandler");
  assert(ocAddDeviceHandlerClass);
  cls_OCAddDeviceHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocAddDeviceHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocAddDeviceHandlerClass);

  jclass ocClientResponseClass = JCALL1(FindClass, jenv, "org/iotivity/OCClientResponse");
  assert(ocClientResponseClass);
  cls_OCClientResponse = (jclass)(JCALL1(NewGlobalRef, jenv, ocClientResponseClass));
  JCALL1(DeleteLocalRef, jenv, ocClientResponseClass);

  jclass ocConWriteHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCConWriteHandler");
  assert(ocConWriteHandlerClass);
  cls_OCConWriteHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocConWriteHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocConWriteHandlerClass);

  jclass ocDiscoveryHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCDiscoveryHandler");
  assert(ocDiscoveryHandlerClass);
  cls_OCDiscoveryHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocDiscoveryHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocDiscoveryHandlerClass);

  jclass ocEndpointClass = JCALL1(FindClass, jenv, "org/iotivity/OCEndpoint");
  assert(ocEndpointClass);
  cls_OCEndpoint = (jclass)(JCALL1(NewGlobalRef, jenv, ocEndpointClass));
  JCALL1(DeleteLocalRef, jenv, ocEndpointClass);

  jclass ocFactoryPresetsHandler = JCALL1(FindClass, jenv, "org/iotivity/OCFactoryPresetsHandler");
  assert(ocFactoryPresetsHandler);
  cls_OCFactoryPresetsHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocFactoryPresetsHandler));
  JCALL1(DeleteLocalRef, jenv, ocFactoryPresetsHandler);

  jclass ocInitPlatformHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCInitPlatformHandler");
  assert(ocInitPlatformHandlerClass);
  cls_OCInitPlatformHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocInitPlatformHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocInitPlatformHandlerClass);

  jclass ocQueryValueClass = JCALL1(FindClass, jenv, "org/iotivity/OCQueryValue");
  assert(ocQueryValueClass);
  cls_OCQueryValue = (jclass)(JCALL1(NewGlobalRef, jenv, ocQueryValueClass));
  JCALL1(DeleteLocalRef, jenv, ocQueryValueClass);

  jclass ocRandomPinHandler = JCALL1(FindClass, jenv, "org/iotivity/OCRandomPinHandler");
  assert(ocRandomPinHandler);
  cls_OCRandomPinHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocRandomPinHandler));
  JCALL1(DeleteLocalRef, jenv, ocRandomPinHandler);


  jclass ocRepresentationClass = JCALL1(FindClass, jenv, "org/iotivity/OCRepresentation");
  assert(ocRepresentationClass);
  cls_OCRepresentation = (jclass)(JCALL1(NewGlobalRef, jenv, ocRepresentationClass));
  JCALL1(DeleteLocalRef, jenv, ocRepresentationClass);

  jclass ocRequestClass = JCALL1(FindClass, jenv, "org/iotivity/OCRequest");
  assert(ocRequestClass);
  cls_OCRequest = (jclass)(JCALL1(NewGlobalRef, jenv, ocRequestClass));
  JCALL1(DeleteLocalRef, jenv, ocRequestClass);

  jclass ocRequestHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCRequestHandler");
  assert(ocRequestHandlerClass);
  cls_OCRequestHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocRequestHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocRequestHandlerClass);

  jclass ocResponseHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCResponseHandler");
  assert(ocResponseHandlerClass);
  cls_OCResponseHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocResponseHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocResponseHandlerClass);

  jclass ocTriggerHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCTriggerHandler");
  assert(ocTriggerHandlerClass);
  cls_OCTriggerHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocTriggerHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocTriggerHandlerClass);

  jclass ocUuidClass = JCALL1(FindClass, jenv, "org/iotivity/OCUuid");
  assert(ocUuidClass);
  cls_OCUuid = (jclass)(JCALL1(NewGlobalRef, jenv, ocUuidClass));
  JCALL1(DeleteLocalRef, jenv, ocUuidClass);

  jclass ocObtDiscoveryHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCObtDiscoveryHandler");
  assert(ocObtDiscoveryHandlerClass);
  cls_OCObtDiscoveryHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocObtDiscoveryHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocObtDiscoveryHandlerClass);

  jclass ocObtDeviceStatusHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCObtDeviceStatusHandler");
  assert(ocObtDeviceStatusHandlerClass);
  cls_OCObtDeviceStatusHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocObtDeviceStatusHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocObtDeviceStatusHandlerClass);

  jclass ocObtStatusHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCObtStatusHandler");
  assert(ocObtStatusHandlerClass);
  cls_OCObtStatusHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocObtStatusHandlerClass));
  JCALL1(DeleteLocalRef, jenv, ocObtStatusHandlerClass);

  jclass utilArrayListClass = JCALL1(FindClass, jenv, "java/util/ArrayList");
  assert(utilArrayListClass);
  cls_ArrayList = (jclass)(JCALL1(NewGlobalRef, jenv, utilArrayListClass));
  JCALL1(DeleteLocalRef, jenv, utilArrayListClass);

  ReleaseJNIEnv(getEnvResult);

// initialize threads
#if defined(_WIN32)
  InitializeCriticalSection(&jni_cs);
  InitializeConditionVariable(&jni_cv);
  InitializeCriticalSection(&jni_sync_lock);
#elif defined(__linux__)
  pthread_mutexattr_init(&jni_sync_lock_attr);
  pthread_mutexattr_settype(&jni_sync_lock_attr, PTHREAD_MUTEX_ERRORCHECK);  // was PTHREAD_MUTEX_RECURSIVE
  pthread_mutex_init(&jni_sync_lock, &jni_sync_lock_attr);
#endif

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
    // TODO do we need to join this thread and the jni_pool_event_thread?
    // TODO empty the jni_callback list on shutdown.
  }
%}

/* Code and typemaps for mapping the oc_set_factory_presets_cb to the OCFactoryPresetsHandler */
%{
void jni_oc_factory_presets_callback(size_t device, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  assert(cls_OCFactoryPresetsHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCFactoryPresetsHandler,
                                       "handler",
                                       "(J)V");
  assert(mid_handler);
  JCALL3(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler, (jlong)device);
}
%}

%typemap(jni)    oc_factory_presets_cb_t cb "jobject";
%typemap(jtype)  oc_factory_presets_cb_t cb "OCFactoryPresetsHandler";
%typemap(jstype) oc_factory_presets_cb_t cb "OCFactoryPresetsHandler";
%typemap(javain) oc_factory_presets_cb_t cb "$javainput";
%typemap(in,numinputs=1) (oc_factory_presets_cb_t cb, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
  $1 = jni_oc_factory_presets_callback;
  $2 = user_data;
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
  jni_list_add(jni_callbacks, user_data);
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
  jni_list_add(jni_callbacks, user_data);
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

/* Code and typemaps for mapping the oc_random_pin_cb_t to the OCRandomPinHandler */
%{
void jni_oc_random_pin_callback(const unsigned char *pin, size_t pin_len, void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  assert(cls_OCRandomPinHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCRandomPinHandler,
                                       "handler",
                                       "(Ljava/lang/String;)V");
  assert(mid_handler);

  jstring jpin = JCALL1(NewStringUTF, (data->jenv), (const char *)pin);

  /* TODO convert pin to java string */
  JCALL3(CallObjectMethod, (data->jenv), data->jcb_obj, mid_handler, jpin);
}
%}

%typemap(jni)    oc_random_pin_cb_t cb "jobject";
%typemap(jtype)  oc_random_pin_cb_t cb "OCRandomPinHandler";
%typemap(jstype) oc_random_pin_cb_t cb "OCRandomPinHandler";
%typemap(javain) oc_random_pin_cb_t cb "$javainput";
%typemap(in,numinputs=1) (oc_random_pin_cb_t cb, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
  $1 = jni_oc_random_pin_callback;
  $2 = user_data;
}

%ignore oc_set_random_pin_callback;
%rename(setRandomPinHandler) jni_set_random_pin_callback;
%inline %{
void jni_set_random_pin_callback(oc_random_pin_cb_t cb, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __func__);
  oc_set_random_pin_callback(cb, jcb);
}
%}

%rename(getConResAnnounced) oc_get_con_res_announced;
%rename(setConResAnnounce) oc_set_con_res_announced;

// server side
%rename(newResource) oc_new_resource;
%rename(resourceBindResourceInterface) oc_resource_bind_resource_interface;
%rename(resourceSetDefaultInterface) oc_resource_set_default_interface;
%rename(resourceBindResourceType) oc_resource_bind_resource_type;
%rename(processBaselineInterface) oc_process_baseline_interface;
%rename(newCollection) oc_new_collection;
%rename(deleteCollection) oc_delete_collection;
%rename(newLink) oc_new_link;
%rename(deleteLink) oc_delete_link;
%rename(linkAddRelation) oc_link_add_rel;
%rename(linkSetInstance) oc_link_set_ins;
%rename(collectionAddLink) oc_collection_add_link;
%rename(collectionRemoveLink) oc_collection_remove_link;
%rename(collectionGetLinks) oc_collection_get_links;
%rename(addCollection) oc_add_collection;
%rename(collectionGetCollection) oc_collection_get_collections;
%rename(collectionAddSupportedResourceType) oc_collection_add_supported_rt;
%rename(collectionAddMandatoryResourceType) oc_collection_add_mandatory_rt;
// custom instance of oc_resource_make_public to handle OC_SECURITY
%ignore oc_resource_make_public;
%rename(resourceMakePublic) jni_oc_resource_make_public;
%inline %{
void jni_oc_resource_make_public(oc_resource_t *resource) {
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
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCRequestHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCRequestHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCRequest;I)V");
  assert(mid_handler);

  assert(cls_OCRequest);
  const jmethodID mid_OCRequest_init = JCALL3(GetMethodID, (data->jenv), cls_OCRequest, "<init>", "(JZ)V");
  assert(mid_OCRequest_init);
  JCALL4(CallVoidMethod,
         (data->jenv),
         data->jcb_obj,
         mid_handler,
        JCALL4(NewObject, (data->jenv), cls_OCRequest, mid_OCRequest_init, (jlong)request, false),
        (jint)interfaces);

  ReleaseJNIEnv(getEnvResult);
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
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
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

%rename(addResource) oc_add_resource;
%rename(deleteResource) oc_delete_resource;

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

  assert(cls_OCRepresentation);
  const jmethodID mid_OCRepresentation_init = JCALL3(GetMethodID,
                                                     (oc_con_write_cb_data.jenv),
                                                     cls_OCRepresentation, "<init>",
                                                     "(JZ)V");
  assert(mid_OCRepresentation_init);
  JCALL4(CallVoidMethod,
         (oc_con_write_cb_data.jenv),
         oc_con_write_cb_data.jcb_obj,
         mid_handler,
         (jlong)device_index,
         JCALL4(NewObject,
                (oc_con_write_cb_data.jenv),
                cls_OCRepresentation,
                mid_OCRepresentation_init,
                (jlong)rep, false)
         );
}
%}
%typemap(jni)    oc_con_write_cb_t callback "jobject";
%typemap(jtype)  oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(jstype) oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(javain) oc_con_write_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_con_write_cb_t callback)
{
  if(!JCALL2(IsSameObject, jenv, oc_con_write_cb_data.jcb_obj, NULL)) {
    //Delete the old callback jcb_obj if this method is called multiple times
    JCALL1(DeleteGlobalRef, jenv, oc_con_write_cb_data.jcb_obj);
  }
  oc_con_write_cb_data.jenv = jenv;
  oc_con_write_cb_data.jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  if(JCALL2(IsSameObject, jenv, $input, NULL))
  {
    $1 = NULL;
  } else {
    $1 = jni_oc_con_callback;
  }
}
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

/*
 * Code and typemaps for mapping the oc_do_ip_discovery and oc_do_ip_discovery_at_endpoint to the
 * java OCDiscoveryHandler
 */
%{
oc_discovery_flags_t jni_oc_discovery_handler_callback(const char *anchor,
                                                        const char *uri,
                                                        oc_string_array_t types,
                                                        oc_interface_mask_t interfaces,
                                                        oc_endpoint_t *endpoint,
                                                        oc_resource_properties_t bm,
                                                        void *user_data)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)user_data;

  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  jstring janchor = JCALL1(NewStringUTF, (data->jenv), anchor);
  jstring juri = JCALL1(NewStringUTF, (data->jenv), uri);
  jobjectArray jtypes = JCALL3(NewObjectArray,
                               (data->jenv),
                               (jsize)oc_string_array_get_allocated_size(types),
                               JCALL1(FindClass, (data->jenv), "java/lang/String"),
                               0);
  for (jsize i = 0; i < (jsize)oc_string_array_get_allocated_size(types); i++) {
    jstring str = JCALL1(NewStringUTF, (data->jenv), oc_string_array_get_item(types, i));
    JCALL3(SetObjectArrayElement, (data->jenv), jtypes, i, str);
  }
  jint jinterfaceMask = (jint)interfaces;

  // create java endpoint
  assert(cls_OCEndpoint);
  const jmethodID mid_OCEndpoint_init = JCALL3(GetMethodID,
                                               (data->jenv),
                                               cls_OCEndpoint,
                                               "<init>",
                                               "(JZ)V");
  assert(mid_OCEndpoint_init);
  jobject jendpoint = JCALL4(NewObject,
                             (data->jenv),
                             cls_OCEndpoint,
                             mid_OCEndpoint_init,
                             (jlong)endpoint,
                             false);

  jint jresourcePropertiesMask = (jint)bm;
  assert(cls_OCDiscoveryHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
          (data->jenv),
          cls_OCDiscoveryHandler,
          "handler",
          "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ILorg/iotivity/OCEndpoint;I)Lorg/iotivity/OCDiscoveryFlags;");
  assert(mid_handler);
  jobject jDiscoveryFlag = JCALL8(CallObjectMethod,
                                  (data->jenv),
                                  data->jcb_obj,
                                  mid_handler,
                                  janchor,
                                  juri,
                                  jtypes,
                                  jinterfaceMask,
                                  jendpoint,
                                  jresourcePropertiesMask);
  jclass cls_DiscoveryFlags = JCALL1(GetObjectClass, (data->jenv), jDiscoveryFlag);
  assert(cls_DiscoveryFlags);
  const jmethodID mid_OCDiscoveryFlags_swigValue = JCALL3(GetMethodID,
                                                          (data->jenv),
                                                          cls_DiscoveryFlags,
                                                          "swigValue",
                                                          "()I");
  assert(mid_OCDiscoveryFlags_swigValue);
  jint return_value = JCALL2(CallIntMethod,
                             (data->jenv),
                             jDiscoveryFlag,
                             mid_OCDiscoveryFlags_swigValue);

  ReleaseJNIEnv(getEnvResult);

  return (oc_discovery_flags_t) return_value;
}
%}
%typemap(jni)    oc_discovery_handler_t handler "jobject";
%typemap(jtype)  oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(jstype) oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(javain) oc_discovery_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_discovery_handler_t handler, jni_callback_data *jcb) {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_list_add(jni_callbacks, user_data);
  $1 = jni_oc_discovery_handler_callback;
  $2 = user_data;
}
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

/* Code and typemaps for mapping the oc_do_get, oc_do_delete, oc_init_put, oc_init_post, oc_do_observe,
 * and oc_do_ip_multicast to the java OCResponseHandler */
%{
void jni_oc_response_handler(oc_client_response_t *response)
{
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)response->user_data;

  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  assert(cls_OCClientResponse);
  const jmethodID mid_OCClientResponse_init = JCALL3(GetMethodID,
                                                     (data->jenv),
                                                     cls_OCClientResponse,
                                                     "<init>",
                                                     "(JZ)V");
  assert(mid_OCClientResponse_init);
  jobject jresponse = JCALL4(NewObject,
                             (data->jenv),
                             cls_OCClientResponse,
                             mid_OCClientResponse_init,
                             (jlong)response,
                             false);

  assert(cls_OCResponseHandler);
  const jmethodID mid_handler = JCALL3(GetMethodID,
                                       (data->jenv),
                                       cls_OCResponseHandler,
                                       "handler",
                                       "(Lorg/iotivity/OCClientResponse;)V");
  assert(mid_handler);
  JCALL3(CallVoidMethod, (data->jenv), data->jcb_obj, mid_handler, jresponse);

  ReleaseJNIEnv(getEnvResult);
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
  jni_list_add(jni_callbacks, user_data);
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
  return oc_init_put(uri, endpoint, query, handler, qos, jcb);
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
  return oc_init_post(uri, endpoint, query, handler, qos, jcb);
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
void jni_free_server_endpoints(oc_endpoint_t *endpoint) {
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_free_server_endpoints(endpoint);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
}
%}

%rename(closeSession) oc_close_session;
%rename(OCRole) oc_role_t;
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
/* Code and typemaps for mapping the oc_set_delayed_callback to the java OCTriggerHandler */
%{
oc_event_callback_retval_t jni_oc_trigger_handler(void* cb_data) {
  OC_DBG("JNI: %s\n", __func__);
  jni_callback_data *data = (jni_callback_data *)cb_data;
  assert(data);
  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
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
  jni_list_add(jni_callbacks, user_data);
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
  jni_callback_data *item = (jni_callback_data *)oc_list_head(jni_callbacks);
  while (item) {
    if (JCALL2(IsSameObject, (item->jenv), callback, item->jcb_obj)) {
      oc_remove_delayed_callback(item, jni_oc_trigger_handler);
      JCALL1(DeleteGlobalRef, (item->jenv), item->jcb_obj);
      break;
    }
    item = (jni_callback_data *)oc_list_item_next(item);
  }
  if (item) {
    oc_list_remove(jni_callbacks, item);
    free(item);
  }
}
%}
%include "oc_api.h"

/*******************Begin oc_endpoint.h*********************/
%rename(OCEndpoint) oc_endpoint_t;
// transport flags are pulled from hand generated class as `int` not `enum`
%ignore transport_flags;
//%rename (OCTransportFlags) transport_flags;
%rename(DevAddr) dev_addr;
//if uncommented the following apply lines will cause the output to be byte[] vs short[]
//%apply signed char[ANY] { uint8_t address[4] };
//%apply signed char[ANY] { uint8_t address[16] };
%rename(OCIPv6Addr) oc_ipv6_addr_t;
%rename(OCIPv4Addr) oc_ipv4_addr_t;
%rename(OCLEAddr) oc_le_addr_t;
%rename(addrLocal) addr_local;
%rename(OCFVersion) ocf_version_t;
%rename(interfaceIndex) interface_index;
// look into exposing oc_make_ipv4_endpoint and oc_make_ipv6_endpoint
%rename(newEndpoint) oc_new_endpoint;
%rename(freeEndpoint) oc_free_endpoint;
%rename(endpointSetDi) oc_endpoint_set_di;
%apply oc_string_t *OUTPUT { oc_string_t *endpointStrOut };
%rename(endpointToString) oc_endpoint_to_string;
int oc_endpoint_to_string(oc_endpoint_t *endpoint, oc_string_t *endpointStrOut);
%apply oc_string_t *INPUT { oc_string_t *endpoint_str };
%apply oc_string_t *OUTPUT { oc_string_t *uri };
%rename(stringToEndpoint) oc_string_to_endpoint;
%rename(ipv6EndpointIsLinkLocal) oc_ipv6_endpoint_is_link_local;
%rename(endpointCompare) oc_endpoint_compare;
%rename(endpointCompareAddress) oc_endpoint_compare_address;
%include "oc_endpoint.h"
/*******************End oc_endpoint.h***********************/
/*******************Begin oc_client_state.h*****************/
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
%rename (OCClientCallback) oc_client_cb_s;
%ignore handler; /*part of the oc_client_cb_s */
%ignore oc_ri_invoke_client_cb;
%ignore oc_ri_alloc_client_cb;
%ignore oc_ri_get_client_cb;
%ignore oc_ri_find_client_cb_by_token;
%ignore oc_ri_find_client_cb_by_mid;
%ignore oc_ri_remove_client_cb_by_mid;
%ignore oc_ri_process_discovery_payload;
%include "oc_client_state.h"
/*******************End oc_client_state.h*******************/
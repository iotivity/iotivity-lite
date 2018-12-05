/* File oc_api.i */
%module OCMain
%include "carrays.i"
%include "arrays_java.i"
%include "stdint.i"
%include "typemaps.i"
%include "various.i"
%include "iotivity.swg"

%import "oc_clock.i"
%include <oc_ri.i>

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
#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include "oc_helpers.h"
#include <assert.h>

/*
 * This struct used to hold information needed for java callbacks.
 * When registering a callback handler from java the `JNIEnv`
 * and the java callback handler object must be stored so they
 * can later be used when the callback comes from C this is
 * the `jcb_obj`.
 *
 * If the function used to register the callback also accepts
 * user_data in the form of a void* the `jni_callback_data`
 * can be passed up to the C layer so it can be used in the
 * callback function.
 *
 * The `juser_data` is used to hold a java object that is passed
 * in when registering a callback handler. This value can then be
 * passed back upto the java callback class. Serving the same
 * function as the C void *user_data pointer.
 */
struct jni_callback_data {
  struct jni_callback_data *next;
  JNIEnv *jenv;
  jobject jcb_obj;
  jobject juser_data;
};

/*
 * Container used to hold all `jni_callback_data` that is
 * allocated dynamically. This can be used to find the
 * memory allocated for the `jni_callback_data` if the callback
 * is removed or unregistered. This can all so be used to clean
 * up the allocated memory when shutting down the stack.
 */
OC_LIST(jni_callbacks);
%}

%typemap(jni)    void *user_data "jobject";
%typemap(jtype)  void *user_data "Object";
%typemap(jstype) void *user_data "Object";
%typemap(javain) void *user_data "$javainput";
%typemap(in)     void *user_data {
  jobject juser_data = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  $1 = (void*)&juser_data;
}
%typemap(javaout) void *user_data {
   return $jnicall;
}
%typemap(out) void *user_data {
    struct jni_callback_data *data = (jni_callback_data *)result;
    jresult = data->juser_data;
}

/* Code and typemaps for mapping the oc_main_init to the java OCMainInitHandler */
%{
#define JNI_CURRENT_VERSION JNI_VERSION_1_6

static JavaVM *jvm;
static jobject jinit_obj;
static jclass cls_OCMainInitHandler;

static JNIEnv* GetJNIEnv(jint* getEnvResult)
{
    JNIEnv *env = nullptr;
#ifdef __cplusplus
    *getEnvResult = jvm->GetEnv((void **)&env, JNI_CURRENT_VERSION);
    switch (*getEnvResult)
    {
        case JNI_OK:
            return env;
        case JNI_EDETACHED:
#ifdef __ANDROID__
            if (jvm->AttachCurrentThread(&env, nullptr) < 0)
#else
            if (jvm->AttachCurrentThread((void **)&env, nullptr) < 0)
#endif
            {
                OC_DBG("Failed to get the environment");
                return nullptr;
            }
            else
            {
                return env;
            }
        case JNI_EVERSION:
            OC_DBG("JNI version not supported");
            break;
        default:
            OC_DBG("Failed to get the environment");
            return nullptr;
    }
#else
    *getEnvResult = (*jvm)->GetEnv(jvm, (void**)&jenv, JNI_CURRENT_VERSION);
    switch (*getEnvResult)
    {
        case JNI_OK:
            return env;
        case JNI_EDETACHED:
#ifdef __ANDROID__
      if((*jvm)->AttachCurrentThread(jvm, &jenv, NULL) < 0)
#else
      if((*jvm)->AttachCurrentThread(jvm, (void**)&jenv, NULL) < 0)
#endif
            {
                OC_DBG("Failed to get the environment");
                return nullptr;
            }
            else
            {
                return env;
            }
        case JNI_EVERSION:
            OC_DBG("JNI version not supported");
            break;
        default:
            OC_DBG("Failed to get the environment");
            return nullptr;
    }
#endif
    return nullptr;
}

void ReleaseJNIEnv(jint getEnvResult) {
#ifdef __cplusplus
if (JNI_EDETACHED == getEnvResult) {
      jvm->DetachCurrentThread();
  }
#else
if (JNI_EDETACHED == getEnvResult) {
      (*jvm)->DetachCurrentThread(jvm);
  }
#endif
}

/* Callback handlers for oc_main_init */
int oc_handler_init_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jint getEnvResult = 0;
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);
  assert(jenv);
  assert(cls_OCMainInitHandler);
#ifdef __cplusplus
  const jmethodID mid_initialize = jenv->GetMethodID(cls_OCMainInitHandler, "initialize", "()I");
  assert(mid_initialize);
  jint ret_value = jenv->CallIntMethod(jinit_obj, mid_initialize);
#else
  const jmethodID mid_initialize = (*jenv)->GetMethodID(jenv, cls_OCMainInitHandler, "initialize", "()I");
  assert(mid_initialize);
  jint ret_value = (*jenv)->CallIntMethod(jenv, jinit_obj, mid_initialize);
#endif
  ReleaseJNIEnv(getEnvResult);
  return (int)ret_value;
}

void oc_handler_signal_event_loop_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jint getEnvResult = 0;
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_signalEventLoop = jenv->GetMethodID(cls_OCMainInitHandler, "signalEventLoop", "()V");
  assert(mid_signalEventLoop);
  jenv->CallVoidMethod(jinit_obj, mid_signalEventLoop);

  ReleaseJNIEnv(getEnvResult);
}

void oc_handler_register_resource_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jint getEnvResult = 0;
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_registerResources = jenv->GetMethodID(cls_OCMainInitHandler, "registerResources", "()V");
  assert(mid_registerResources);
  jenv->CallVoidMethod(jinit_obj, mid_registerResources);

  ReleaseJNIEnv(getEnvResult);
}

void oc_handler_requests_entry_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jint getEnvResult = 0;
  JNIEnv *jenv = GetJNIEnv(&getEnvResult);

  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_requestEntry_method = jenv->GetMethodID(cls_OCMainInitHandler, "requestEntry", "()V");
  assert(mid_requestEntry_method);
  jenv->CallVoidMethod(jinit_obj, mid_requestEntry_method);
  
  ReleaseJNIEnv(getEnvResult);
}

static oc_handler_t jni_handler = {
    oc_handler_init_callback,              // init
    oc_handler_signal_event_loop_callback, // signal_event_loop
    oc_handler_register_resource_callback, // register_resources
    oc_handler_requests_entry_callback     // requests_entry
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
  JCALL1(DeleteLocalRef, jenv, $input);
  $1 = &jni_handler;

  const jclass callback_interface = jenv->FindClass("org/iotivity/OCMainInitHandler");
  assert(callback_interface);
  cls_OCMainInitHandler = static_cast<jclass>(jenv->NewGlobalRef(callback_interface));
}

%rename(mainInit) oc_main_init;
%rename(mainPoll) oc_main_poll;
%rename(mainShutdown) oc_main_shutdown;

/* Code and typemaps for mapping the oc_add_device to the java OCAddDeviceHandler */
%{
void jni_oc_add_device_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;

  const jclass cls_OCAddDeviceHandler = (data->jenv)->FindClass("org/iotivity/OCAddDeviceHandler");
  assert(cls_OCAddDeviceHandler);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(cls_OCAddDeviceHandler,
                                                         "handler",
                                                         "(Ljava/lang/Object;)V");
  assert(mid_handler);
  (data->jenv)->CallObjectMethod(data->jcb_obj, mid_handler, data->juser_data);
}

void jni_oc_resource_make_public(oc_resource_t *resource) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
#ifdef OC_SECURITY
  oc_resource_make_public(resource);
#endif /* OC_SECURITY */
}
%}
%typemap(jni)    oc_add_device_cb_t add_device_cb "jobject";
%typemap(jtype)  oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(jstype) oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(javain) oc_add_device_cb_t add_device_cb "$javainput";
%typemap(in,numinputs=1) (oc_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_oc_add_device_callback;
  $2 = user_data;
}
%ignore oc_add_device;
%rename(addDevice) jni_oc_add_device0;
%inline %{
int jni_oc_add_device0(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return oc_add_device(uri, rt, name, spec_version, data_model_version, NULL, NULL);
}
%}

%rename(addDevice) jni_oc_add_device1;
%inline %{
int jni_oc_add_device1(const char *uri, const char *rt, const char *name,
                  const char *spec_version, const char *data_model_version,
                  oc_add_device_cb_t add_device_cb, jni_callback_data *jcb,
                  void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_add_device(uri, rt, name, spec_version, data_model_version, add_device_cb, jcb);
}
%}

/* Code and typemaps for mapping the oc_init_platform to the java OCInitPlatformHandler */
%{
void jni_oc_init_platform_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;

  const jclass cls_OCInitPlatformHandler = (data->jenv)->FindClass("org/iotivity/OCInitPlatformHandler");
  assert(cls_OCInitPlatformHandler);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(cls_OCInitPlatformHandler,
                                                         "handler",
                                                         "(Ljava/lang/Object;)V");
  assert(mid_handler);
  (data->jenv)->CallObjectMethod(data->jcb_obj, mid_handler, data->juser_data);
}
%}
%typemap(jni)    oc_init_platform_cb_t init_platform_cb "jobject";
%typemap(jtype)  oc_init_platform_cb_t init_platform_cb "OCInitPlatformHandler";
%typemap(jstype) oc_init_platform_cb_t init_platform_cb "OCInitPlatformHandler";
%typemap(javain) oc_init_platform_cb_t init_platform_cb "$javainput";

%typemap(in,numinputs=1) (oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_oc_init_platform_callback;
  $2 = user_data;
}
%ignore oc_init_platform;
/* the oc_init_platform without the callback or data pointer */
%rename(initPlatform) jni_oc_init_platform0;
%inline %{
int jni_oc_init_platform0(const char *mfg_name) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return oc_init_platform(mfg_name, NULL, NULL);
}
%}
%rename(initPlatform) jni_oc_init_platform1;
%inline %{
int jni_oc_init_platform1(const char *mfg_name, oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb, void *user_data) {
 OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_platform(mfg_name, init_platform_cb, jcb);
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
// custom instance of oc_resource_make_public to handle OC_SECURITY
%rename(resourceMakePublic) jni_oc_resource_make_public;
%ignore oc_resource_make_public;
%rename(resourceSetDiscoverable) oc_resource_set_discoverable;
%rename(resourceSetObservable) oc_resource_set_observable;
%rename(resourceSetPeriodicObservable) oc_resource_set_periodic_observable;

/* Code and typemaps for mapping the oc_resource_set_request_handler to the java OCRequestHandler */
%{
void jni_oc_request_callback(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;
  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  const jclass callbackInterfaceClass = (data->jenv)->FindClass("org/iotivity/OCRequestHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(callbackInterfaceClass, "handler", "(Lorg/iotivity/OCRequest;ILjava/lang/Object;)V");
  assert(mid_handler);

  const jclass cls_OCRequest = (data->jenv)->FindClass("org/iotivity/OCRequest");
  assert(cls_OCRequest);
  const jmethodID mid_OCRequest_init = (data->jenv)->GetMethodID(cls_OCRequest, "<init>", "(JZ)V");
  assert(mid_OCRequest_init);
  (data->jenv)->CallVoidMethod(data->jcb_obj, mid_handler, (data->jenv)->NewObject(cls_OCRequest, mid_OCRequest_init, (jlong)request, false), (jint)interfaces, data->juser_data);

  ReleaseJNIEnv(getEnvResult);
}
%}
%typemap(jni)    oc_request_callback_t callback "jobject";
%typemap(jtype)  oc_request_callback_t callback "OCRequestHandler";
%typemap(jstype) oc_request_callback_t callback "OCRequestHandler";
%typemap(javain) oc_request_callback_t callback "$javainput";
%typemap(in,numinputs=1) (oc_request_callback_t callback, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_oc_request_callback;
  $2 = user_data;
}
%ignore oc_resource_set_request_handler;
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler0;
%inline %{
void jni_oc_resource_set_request_handler0(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_resource_set_request_handler(resource, method, callback, jcb);
}
%}
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler1;
%inline %{
void jni_oc_resource_set_request_handler1(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb,
                                          void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_resource_set_request_handler(resource, method, callback, jcb);
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
static struct jni_callback_data oc_con_write_cb_data;

void jni_oc_con_callback(size_t device_index, oc_rep_t *rep)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  const jclass cls_OCConWriteHandler = (oc_con_write_cb_data.jenv)->FindClass("org/iotivity/OCConWriteHandler");
  assert(cls_OCConWriteHandler);
  const jmethodID mid_handler = (oc_con_write_cb_data.jenv)->GetMethodID(cls_OCConWriteHandler, "handler", "(JLorg/iotivity/OCRepresentation;)V");
  assert(mid_handler);

  const jclass cls_OCRepresentation = (oc_con_write_cb_data.jenv)->FindClass("org/iotivity/OCRepresentation");
  assert(cls_OCRepresentation);
  const jmethodID mid_OCRepresentation_init = (oc_con_write_cb_data.jenv)->GetMethodID(cls_OCRepresentation, "<init>", "(JZ)V");
  assert(mid_OCRepresentation_init);
  (oc_con_write_cb_data.jenv)->CallVoidMethod(oc_con_write_cb_data.jcb_obj, mid_handler, (jlong)device_index,
                                            (oc_con_write_cb_data.jenv)->NewObject(cls_OCRepresentation, mid_OCRepresentation_init, (jlong)rep, false));
}
%}
%typemap(jni)    oc_con_write_cb_t callback "jobject";
%typemap(jtype)  oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(jstype) oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(javain) oc_con_write_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_con_write_cb_t callback) {
  if(!JCALL2(IsSameObject, jenv, oc_con_write_cb_data.jcb_obj, NULL)) {
    //Delete the old callback jcb_obj if this method is called multiple times
    JCALL1(DeleteGlobalRef, jenv, oc_con_write_cb_data.jcb_obj);
  }
  oc_con_write_cb_data.jenv = jenv;
  oc_con_write_cb_data.jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
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
SWIGEXPORT jobject JNICALL Java_org_iotivity_OCMainJNI_getQueryValues(JNIEnv *jenv, jclass jcls, jlong jrequest, jobject jrequest_) {
  jobject jresult = 0;
  oc_request_t *request = (oc_request_t *)0;
  jobject result;

  (void)jenv;
  (void)jcls;
  (void)jrequest_;
  request = *(oc_request_t **)&jrequest;

  jclass cls_ArrayList = jenv->FindClass("java/util/ArrayList");
  jmethodID mid_arrayListConstructor = jenv->GetMethodID(cls_ArrayList, "<init>", "()V");
  jmethodID mid_add = jenv->GetMethodID(cls_ArrayList, "add", "(Ljava/lang/Object;)Z");

  jclass cls_OCQueryValue = jenv->FindClass("org/iotivity/OCQueryValue");
  jmethodID mid_OCQueryConstructor = jenv->GetMethodID(cls_OCQueryValue, "<init>", "(Ljava/lang/String;Ljava/lang/String;)V");

  result = jenv->NewObject(cls_ArrayList, mid_arrayListConstructor);

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
      jstring jkey = jenv->NewStringUTF(temp_buffer);

      strncpy(temp_buffer, current_value, value_len);
      temp_buffer[value_len] = '\0';
      jstring jvalue = jenv->NewStringUTF(temp_buffer);

      jobject jQueryValue = jenv->NewObject(cls_OCQueryValue, mid_OCQueryConstructor, jkey, jvalue);
      jenv->CallBooleanMethod(result, mid_add, jQueryValue);
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
/* Code and typemaps for mapping the oc_do_ip_discovery and oc_do_ip_discovery_at_endpoint to the java OCDiscoveryHandler */
%{
oc_discovery_flags_t jni_oc_discovery_handler_callback(const char *anchor,
                                                        const char *uri,
                                                        oc_string_array_t types,
                                                        oc_interface_mask_t interfaces,
                                                        oc_endpoint_t *endpoint,
                                                        oc_resource_properties_t bm,
                                                        void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;

  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  jstring janchor = (data->jenv)->NewStringUTF(anchor);
  jstring juri = (data->jenv)->NewStringUTF(uri);
  jobjectArray jtypes = (data->jenv)->NewObjectArray((jsize)oc_string_array_get_allocated_size(types),
                                                    (data->jenv)->FindClass("java/lang/String"),0);
  for (jsize i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    jstring str = (data->jenv)->NewStringUTF(oc_string_array_get_item(types, i));
    (data->jenv)->SetObjectArrayElement(jtypes, i, str);
  }
  jint jinterfaceMask = (jint)interfaces;

  // create java endpoint
  const jclass cls_OCEndpoint = (data->jenv)->FindClass("org/iotivity/OCEndpoint");
  assert(cls_OCEndpoint);
  const jmethodID mid_OCEndpoint_init = (data->jenv)->GetMethodID(cls_OCEndpoint, "<init>", "(JZ)V");
  assert(mid_OCEndpoint_init);
  jobject jendpoint = (data->jenv)->NewObject(cls_OCEndpoint, mid_OCEndpoint_init, (jlong)endpoint, false);

  jint jresourcePropertiesMask = (jint)bm;
  const jclass callbackInterfaceClass = (data->jenv)->FindClass("org/iotivity/OCDiscoveryHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(callbackInterfaceClass,
          "handler",
          "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ILorg/iotivity/OCEndpoint;ILjava/lang/Object;)Lorg/iotivity/OCDiscoveryFlags;");
  assert(mid_handler);
  jobject jDiscoveryFlag = (data->jenv)->CallObjectMethod(data->jcb_obj, mid_handler, janchor, juri,
                                                         jtypes, jinterfaceMask, jendpoint,
                                                         jresourcePropertiesMask, data->juser_data);
  jclass cls_DiscoveryFlags = (data->jenv)->GetObjectClass(jDiscoveryFlag);
  assert(cls_DiscoveryFlags);
  const jmethodID mid_OCDiscoveryFlags_swigValue = (data->jenv)->GetMethodID(cls_DiscoveryFlags, "swigValue", "()I");
  assert(mid_OCDiscoveryFlags_swigValue);
  jint return_value = (data->jenv)->CallIntMethod(jDiscoveryFlag, mid_OCDiscoveryFlags_swigValue);

  ReleaseJNIEnv(getEnvResult);

  return (oc_discovery_flags_t) return_value;
}
%}
%typemap(jni)    oc_discovery_handler_t handler "jobject";
%typemap(jtype)  oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(jstype) oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(javain) oc_discovery_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_discovery_handler_t handler, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_oc_discovery_handler_callback;
  $2 = user_data;
}
%ignore oc_do_ip_discovery;
%rename(doIPDiscovery) jni_oc_do_ip_discovery0;
%inline %{
bool jni_oc_do_ip_discovery0(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_discovery(rt, handler, jcb);
}
%}
%rename(doIPDiscovery) jni_oc_do_ip_discovery1;
%inline %{
bool jni_oc_do_ip_discovery1(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb, void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_ip_discovery(rt, handler, jcb);
}
%}
%ignore oc_do_ip_discovery_at_endpoint;
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint0;
%inline %{
bool jni_oc_do_ip_discovery_at_endpoint0(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, jcb);
}
%}
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint1;
%inline %{
bool jni_oc_do_ip_discovery_at_endpoint1(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint, void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, jcb);
}
%}

/* Code and typemaps for mapping the oc_do_get, oc_do_delete, oc_init_put, oc_init_post, oc_do_observe,
 * and oc_do_ip_multicast to the java OCResponseHandler */
%{
void jni_oc_response_handler(oc_client_response_t *response) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)response->user_data;

  jint getEnvResult = 0;
  data->jenv = GetJNIEnv(&getEnvResult);
  assert(data->jenv);

  const jclass cls_OCClientResponce = (data->jenv)->FindClass("org/iotivity/OCClientResponse");
  assert(cls_OCClientResponce);
  const jmethodID mid_OCClientResponce_init = (data->jenv)->GetMethodID(cls_OCClientResponce, "<init>", "(JZ)V");
  assert(mid_OCClientResponce_init);
  jobject jresponse = (data->jenv)->NewObject(cls_OCClientResponce, mid_OCClientResponce_init, (jlong)response, false);

  const jclass cls_OCResponseHandler = (data->jenv)->FindClass("org/iotivity/OCResponseHandler");
  assert(cls_OCResponseHandler);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(cls_OCResponseHandler,
                                                         "handler",
                                                         "(Lorg/iotivity/OCClientResponse;)V");
  assert(mid_handler);
  (data->jenv)->CallVoidMethod(data->jcb_obj, mid_handler, jresponse);


  ReleaseJNIEnv(getEnvResult);
}
%}
%typemap(jni)    oc_response_handler_t handler "jobject";
%typemap(jtype)  oc_response_handler_t handler "OCResponseHandler";
%typemap(jstype) oc_response_handler_t handler "OCResponseHandler";
%typemap(javain) oc_response_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_response_handler_t handler, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_oc_response_handler;
  $2 = user_data;
}
%ignore oc_do_get;
%rename(doGet) jni_oc_do_get0;
%inline %{
bool jni_oc_do_get0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_get(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(doGet) jni_oc_do_get1;
%inline %{
bool jni_oc_do_get1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_get(uri, endpoint, query, handler, qos, jcb);
}
%}

%ignore oc_do_delete;
%rename(doDelete) jni_oc_do_delete0;
%inline %{
bool jni_oc_do_delete0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos){
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_delete(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(doDelete) jni_oc_do_delete1;
%inline %{
bool jni_oc_do_delete1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos, void *user_data){
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_delete(uri, endpoint, query, handler, qos, jcb);
}
%}

%ignore oc_init_put;
%rename(initPut) jni_oc_init_put0;
%inline %{
bool jni_oc_init_put0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_init_put(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(initPut) jni_oc_init_put1;
%inline %{
bool jni_oc_init_put1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_put(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(doPut) oc_do_put;
%ignore oc_init_post;
%rename(initPost) jni_oc_init_post0;
%inline %{
bool jni_oc_init_post0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_init_post(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(initPost) jni_oc_init_post1;
%inline %{
bool jni_oc_init_post1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_post(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(doPost) oc_do_post;
%ignore oc_do_observe;
%rename(doObserve) jni_oc_do_observe0;
%inline %{
bool jni_oc_do_observe0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_observe(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(doObserve) jni_oc_do_observe1;
%inline %{
bool jni_oc_do_observe1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_observe(uri, endpoint, query, handler, qos, jcb);
}
%}
%rename(stopObserve) oc_stop_observe;
%ignore oc_do_ip_multicast;
%rename(doIPMulticast) jni_oc_do_ip_multicast0;
%inline %{
bool jni_oc_do_ip_multicast0(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_multicast(uri, query, handler, jcb);
}
%}
%rename(doIPMulticast) jni_oc_do_ip_multicast1;
%inline %{
bool jni_oc_do_ip_multicast1(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb, void *user_data){
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_ip_multicast(uri, query, handler, jcb);
}
%}

%rename(stopMulticast) oc_stop_multicast;
%rename(freeServerEndpoints) oc_free_server_endpoints;
%rename(closeSession) oc_close_session;

// common operations
/* Code and typemaps for mapping the oc_set_delayed_callback to the java OCTriggerHandler */
%{
oc_event_callback_retval_t jni_oc_trigger_handler(void* cb_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)cb_data;

  const jclass cls_OCTriggerHandler = (data->jenv)->FindClass("org/iotivity/OCTriggerHandler");
  assert(cls_OCTriggerHandler);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(cls_OCTriggerHandler,
                                                         "handler",
                                                         "(Ljava/lang/Object;)Lorg/iotivity/OCEventCallbackResult;");
  assert(mid_handler);
  jobject jEventCallbackRet = (data->jenv)->CallObjectMethod(data->jcb_obj, mid_handler, data->juser_data);

  jclass cls_OCEventCallbackResult = (data->jenv)->GetObjectClass(jEventCallbackRet);
  assert(cls_OCEventCallbackResult);
  const jmethodID mid_OCEventCallbackResult_swigValue = (data->jenv)->GetMethodID(cls_OCEventCallbackResult, "swigValue", "()I");
  assert(mid_OCEventCallbackResult_swigValue);
  jint return_value = (data->jenv)->CallIntMethod(jEventCallbackRet, mid_OCEventCallbackResult_swigValue);
  return (oc_event_callback_retval_t) return_value;
}
%}
%typemap(jni)    oc_trigger_t callback "jobject";
%typemap(jtype)  oc_trigger_t callback "OCTriggerHandler";
%typemap(jstype) oc_trigger_t callback "OCTriggerHandler";
%typemap(javain) oc_trigger_t callback "$javainput";
%typemap(in,numinputs=1) (oc_trigger_t callback, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  oc_list_add(jni_callbacks, user_data);
  $1 = jni_oc_trigger_handler;
  $2 = user_data;
}
%ignore oc_set_delayed_callback;
%rename(setDelayedHandler) jni_oc_set_delayed_callback0;
%inline %{
void jni_oc_set_delayed_callback0(oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  oc_set_delayed_callback(jcb, callback, seconds);
}
%}
%rename(setDelayedHandler) jni_oc_set_delayed_callback1;
%inline %{
void jni_oc_set_delayed_callback1(void *user_data, oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  oc_set_delayed_callback(jcb, callback, seconds);
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
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jni_callback_data *item = (jni_callback_data *)oc_list_head(jni_callbacks);
  while (item) {
    if (item->jenv->IsSameObject(callback, item->jcb_obj)) {
      oc_remove_delayed_callback(item, jni_oc_trigger_handler);
      item->jenv->DeleteGlobalRef(item->jcb_obj);
      item->jenv->DeleteGlobalRef(item->juser_data);
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

/*******************Begin cbor.h******************************/
/* CborEncoder from cbor.h  needed to process oc_rep.h*/
struct CborEncoder
{
/*    union {
        uint8_t *ptr;
        ptrdiff_t bytes_needed;
    } data;
    const uint8_t *end;
    size_t remaining;
    int flags;*/
};
/*******************End cbor.h********************************/
/*******************Begin oc_rep.h****************************/
%rename(OCRepresentation) oc_rep_s;
%rename(OCType) oc_rep_value_type_t;
%rename(OCValue) oc_rep_value;
%rename(Double) double_p;
%rename(Bool) boolean;
%rename(objectArray) object_array;
%ignore g_encoder;
%ignore root_map;
%ignore links_array;
%ignore g_err;

%ignore oc_rep_new;
%{
uint8_t *g_new_rep_buffer = NULL;
struct oc_memb g_rep_objects;
%}
%inline %{
void repDeleteBuffer() {
  free(g_new_rep_buffer);
  g_new_rep_buffer = NULL;
}
void repNewBuffer(int size) {
  if (g_new_rep_buffer) {
    repDeleteBuffer();
  }
  g_new_rep_buffer = (uint8_t *)malloc(size);
  oc_rep_new(g_new_rep_buffer, size);
  g_rep_objects = { sizeof(oc_rep_t), 0, 0, 0 ,0 };
  oc_rep_set_pool(&g_rep_objects);
}
%}

%ignore oc_rep_get_encoded_payload_size;
%ignore oc_rep_get_encoder_buf;
%rename (repSetDouble) jni_rep_set_double;
%inline %{
/* Alt implementation of oc_rep_set_double macro*/
void jni_rep_set_double(CborEncoder * object, const char* key, double value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_double(object, value);
}
%}

%rename (repSetInt) jni_rep_set_int;
%inline %{
/* Alt implementation of oc_rep_set_int macro */
void jni_rep_set_int(CborEncoder * object, const char* key, int value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_int(object, value);
}
%}

%rename (repSetUnsignedInt) jni_rep_set_uint;
%inline %{
/* Alt implementation of oc_rep_set_uint macro */
void jni_rep_set_uint(CborEncoder * object, const char* key, unsigned int value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_uint(object, value);
}
%}

%rename (repSetBoolean) jni_rep_set_boolean;
%inline %{
/* Alt implementation of oc_rep_set_boolean macro */
void jni_rep_set_boolean(CborEncoder * object, const char* key, bool value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_boolean(object, value);
}
%}

%rename (repSetTextString) jni_rep_set_text_string;
%inline %{
/* Alt implementation of oc_rep_set_text_string macro */ 
void jni_rep_set_text_string(CborEncoder * object, const char* key, const char* value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_text_string(object, value, strlen(value));
}
%}

%typemap(in)     (const unsigned char * BYTE, size_t LENGTH) {
/* Functions from jni.h */
$1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
$2 = (size_t) JCALL1(GetArrayLength,       jenv, $input);
}
%typemap(jni)    (const unsigned char * BYTE, size_t LENGTH) "jbyteArray"
%typemap(jtype)  (const unsigned char * BYTE, size_t LENGTH) "byte[]"
%typemap(jstype) (const unsigned char * BYTE, size_t LENGTH) "byte[]"
%typemap(javain) (const unsigned char * BYTE, size_t LENGTH) "$javainput"

/* Specify signature of method to handle */
%apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *value, size_t length) };
%rename (repSetByteString) jni_rep_set_byte_string;
%inline %{
/* Alt implementation of oc_rep_set_byte_string macro */
void jni_rep_set_byte_string(CborEncoder * object, const char* key, const unsigned char *value, size_t length) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_byte_string(object, value, length);
}
%}

%rename (repBeginArray) jni_rep_start_array;
%inline %{
/* Alt implementation of oc_rep_start_array macro */
CborEncoder * jni_rep_start_array(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  CborEncoder *cbor_encoder_array = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_array(parent, cbor_encoder_array, CborIndefiniteLength);
  return cbor_encoder_array;
}
%}

%rename (repEndArray) jni_rep_end_array;
%inline %{
/* Alt implementation of oc_rep_end_array macro */
void jni_rep_end_array(CborEncoder *parent, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encoder_close_container(parent, arrayObject);
  free(arrayObject);
  arrayObject = NULL;
}
%}

%rename (repBeginLinksArray) jni_rep_start_links_array;
%inline %{
/* Alt implementation of oc_rep_start_links_array macro */
CborEncoder * jni_rep_start_links_array() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength);
  return &links_array;
}
%}

%rename (repEndLinksArray) jni_rep_end_links_array;
%inline %{
/* Alt implementation of oc_rep_end_links_array macro */
void jni_rep_end_links_array() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  oc_rep_end_links_array();
}
%}

%rename(repBeginRootObject) jni_start_root_object;
%inline %{
/* Alt implementation of oc_rep_start_root_object macro */
CborEncoder * jni_start_root_object() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength);
  return &root_map;
}
%}

%rename(repEndRootObject) jni_rep_end_root_object;
%inline %{
void jni_rep_end_root_object() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  oc_rep_end_root_object();
}
%}

%rename(repAddByteString) jni_rep_add_byte_string;
%inline %{
/* Alt implementation of oc_rep_add_byte_string macro */
void jni_rep_add_byte_string(CborEncoder *arrayObject, const unsigned char* value, const size_t length) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  if (value != NULL) {
    g_err |= cbor_encode_byte_string(arrayObject, value, length);
  }
}
%}

%rename(repAddTextString) jni_rep_add_text_string;
%inline %{
/* Alt implementation of oc_rep_add_text_string macro */
void jni_rep_add_text_string(CborEncoder *arrayObject, const char* value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  if (value != NULL) {
    g_err |= cbor_encode_text_string(arrayObject, value, strlen(value));
  }
}
%}

%rename(repAddDouble) jni_rep_add_double;
%inline %{
/* Alt implementation of oc_rep_add_double macro */
void jni_rep_add_double(CborEncoder *arrayObject, const double value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_double(arrayObject, value);
}
%}

%rename(repAddInt) jni_rep_add_int;
%inline %{
/* Alt implementation of oc_rep_add_int macro */
void jni_rep_add_int(CborEncoder *arrayObject, const int value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_int(arrayObject, value);
}
%}

%rename(repAddBoolean) jni_rep_add_boolean;
%inline %{
/* Alt implementation of oc_rep_add_boolean macro */
void jni_rep_add_boolean(CborEncoder *arrayObject, const bool value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_boolean(arrayObject, value);
}
%}

%rename(repSetKey) jni_rep_set_key;
%inline %{
/* Alt implementation of oc_rep_set_key macro */
void jni_rep_set_key(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
}
%}

%rename(repOpenArray) jni_rep_set_array;
%inline %{
/* Alt implementation of oc_rep_set_array macro */
CborEncoder * jni_rep_set_array(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return jni_rep_start_array(parent);
}
%}

%rename(repCloseArray) jni_rep_close_array;
%inline %{
/* Alt implementation of oc_rep_close_array macro */
void jni_rep_close_array(CborEncoder *object, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jni_rep_end_array(object, arrayObject);
}
%}

%rename (repBeginObject) jni_rep_start_object;
%inline %{
/* Alt implementation of oc_rep_start_object macro */
CborEncoder * jni_rep_start_object(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  CborEncoder *cbor_encoder_map = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_map(parent, cbor_encoder_map, CborIndefiniteLength);
  return cbor_encoder_map;
}
%}

%rename (repEndObject) jni_rep_end_object;
%inline %{
/* Alt implementation of oc_rep_end_object macro */
void jni_rep_end_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encoder_close_container(parent, object);
  free(object);
  object = NULL;
}
%}

%rename (repObjectArrayBeginItem) jni_rep_object_array_start_item;
%inline %{
/* Alt implementation of oc_rep_object_array_start_item macro */
CborEncoder * jni_rep_object_array_start_item(CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return jni_rep_start_object(arrayObject);
}
%}

%rename (repObjectArrayEndItem) jni_rep_object_array_end_item;
%inline %{
/* Alt implementation of oc_rep_object_array_end_item macro */
void jni_rep_object_array_end_item(CborEncoder *parentArrayObject, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jni_rep_end_object(parentArrayObject, arrayObject);
}
%}

%rename(repOpenObject) jni_rep_set_object;
%inline %{
/* Alt implementation of oc_rep_set_object macro */
CborEncoder * jni_rep_set_object(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return jni_rep_start_object(parent);
}
%}

%rename(repCloseObject) jni_rep_close_object;
%inline %{
/* Alt implementation of oc_rep_close_object macro */
void jni_rep_close_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jni_rep_end_object(parent, object);
}
%}

%typemap(jni) (int *values, int length) "jintArray"
%typemap(jtype) (int *values, int length) "int[]"
%typemap(jstype) (int *values, int length) "int[]"
%typemap(javain) (int *values, int length) "$javainput"
%typemap(javadirectorin) (int *values, int length) "$javainput"
%typemap(javadirectorout) (int *values, int length) "$javacall"

%typemap(in) (int *values, int length) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  jint *jvalues = JCALL2(GetIntArrayElements, jenv, $input, 0);
  jsize jlength = JCALL1(GetArrayLength, jenv, $input);

  $1 = (int *)jvalues;
  $2 = jlength;
}
%rename(repSetIntArray) jni_rep_set_int_array;
%inline %{
/* Alt implementation of oc_rep_set_int_array macro */
void jni_rep_set_int_array(CborEncoder *object, const char* key, int *values, int length) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_int(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%typemap(jni) (bool *values, int length) "jbooleanArray"
%typemap(jtype) (bool *values, int length) "boolean[]"
%typemap(jstype) (bool *values, int length) "boolean[]"
%typemap(javain) (bool *values, int length) "$javainput"
%typemap(javadirectorin) (bool *values, int length) "$javainput"
%typemap(javadirectorout) (bool *values, int length) "$javacall"

%typemap(in) (bool *values, int length) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  jboolean *jvalues = JCALL2(GetBooleanArrayElements, jenv, $input, 0);
  jsize jlength = JCALL1(GetArrayLength, jenv, $input);

  $1 = (bool *)jvalues;
  $2 = jlength;
}
%rename(repSetBooleanArray) jni_rep_set_bool_array;
%inline %{
/* Alt implementation of oc_rep_set_bool_array macro */
void jni_rep_set_bool_array(CborEncoder *object, const char* key, bool *values, int length) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_boolean(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%typemap(jni) (double *values, int length) "jdoubleArray "
%typemap(jtype) (double *values, int length) "double[]"
%typemap(jstype) (double *values, int length) "double[]"
%typemap(javain) (double *values, int length) "$javainput"
%typemap(javadirectorin) (double *values, int length) "$javainput"
%typemap(javadirectorout) (double *values, int length) "$javacall"

%typemap(in) (double *values, int length) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  jdouble *jvalues = JCALL2(GetDoubleArrayElements, jenv, $input, 0);
  jsize jlength = JCALL1(GetArrayLength, jenv, $input);

  $1 = (double *)jvalues;
  $2 = jlength;
}
%rename(repSetDoubleArray) jni_rep_set_double_array;
%inline %{
/* Alt implementation of oc_rep_set_double_array macro */
void jni_rep_set_double_array(CborEncoder *object, const char* key, double *values, int length) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_floating_point(&value_array, CborDoubleType, &values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%rename(repSetStringArray) jni_rep_rep_set_string_array;
%inline %{
/* Alt implementation of oc_rep_set_string_array macro */
void jni_rep_rep_set_string_array(CborEncoder *object, const char* key, oc_string_array_t values) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, CborIndefiniteLength);
  int i;
    for (i = 0; i < (int)oc_string_array_get_allocated_size(values); i++) {
      if (oc_string_array_get_item_size(values, i) > 0) {
        g_err |= cbor_encode_text_string(&value_array, oc_string_array_get_item(values, i),
                                         oc_string_array_get_item_size(values, i));
      }
    }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%rename(repGetOCRepresentaionFromRootObject) jni_rep_get_rep_from_root_object;
%newobject jni_rep_get_rep_from_root_object;
%inline %{
/*
 * Java only helper function to convert the root CborEncoder object to an oc_rep_t this is needed
 * to enable encode/decode unit testing. This function is not expected to be used in typical
 * use case. It should only be called after calling oc_rep_end_root_object.
 */
oc_rep_t * jni_rep_get_rep_from_root_object() {
  oc_rep_t * rep = (oc_rep_t *)malloc(sizeof(oc_rep_t));
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  oc_parse_rep(payload, payload_len, &rep);
  return rep;
}
%}
%ignore oc_rep_get_cbor_errno;
%rename(repGetCborErrno) jni_rep_get_cbor_errno;
%inline %{
int jni_rep_get_cbor_errno() {
  return (int)oc_rep_get_cbor_errno();
}
%}
%ignore oc_rep_set_pool;
%ignore oc_parse_rep;
%ignore oc_free_rep;

%typemap(in, numinputs=0, noblock=1) bool *jni_rep_get_error_flag {
  bool temp_jni_rep_get_error_flag;
  $1 = &temp_jni_rep_get_error_flag;
}

%typemap(jstype) int jni_rep_get_int "Integer"
%typemap(jtype) int jni_rep_get_int "Integer"
%typemap(jni) int jni_rep_get_int "jobject"
%typemap(javaout) int jni_rep_get_int {
  return $jnicall;
}
%typemap(out, noblock=1) int jni_rep_get_int {
  if(temp_jni_rep_get_error_flag) {
    const jclass cls_Integer = JCALL1(FindClass, jenv, "java/lang/Integer");
    assert(cls_Integer);
    const jmethodID mid_Integer_init = JCALL3(GetMethodID, jenv, cls_Integer, "<init>", "(I)V");
    assert(mid_Integer_init);
    $result = JCALL3(NewObject, jenv, cls_Integer, mid_Integer_init, $1);
  } else {
    $result = NULL;
  }
}

%ignore oc_rep_get_int;
%rename(repGetInt) jni_rep_get_int;
%inline %{
int jni_rep_get_int(oc_rep_t *rep, const char *key, bool *jni_rep_get_error_flag) {
  int retValue;
  *jni_rep_get_error_flag = oc_rep_get_int(rep, key, &retValue);
  return retValue;
}
%}

%typemap(jstype) bool jni_rep_get_bool "Boolean"
%typemap(jtype) bool jni_rep_get_bool "Boolean"
%typemap(jni) bool jni_rep_get_bool "jobject"
%typemap(javaout) bool jni_rep_get_bool {
  return $jnicall;
}
%typemap(out, noblock=1) bool jni_rep_get_bool {
  if(temp_jni_rep_get_error_flag) {
    const jclass cls_Boolean = JCALL1(FindClass, jenv, "java/lang/Boolean");
    assert(cls_Boolean);
    const jmethodID mid_Boolean_init = JCALL3(GetMethodID, jenv, cls_Boolean, "<init>", "(Z)V");
    assert(mid_Boolean_init);
    $result = JCALL3(NewObject, jenv, cls_Boolean, mid_Boolean_init, $1);
  } else {
    $result = NULL;
  }
}

%ignore oc_rep_get_bool;
%rename(repGetBoolean) jni_rep_get_bool;
%inline %{
bool jni_rep_get_bool(oc_rep_t *rep, const char *key, bool *jni_rep_get_error_flag) {
  bool retValue;
  *jni_rep_get_error_flag = oc_rep_get_bool(rep, key, &retValue);
  return retValue;
}
%}

%typemap(jstype) double jni_rep_get_double "Double"
%typemap(jtype) double jni_rep_get_double "Double"
%typemap(jni) double jni_rep_get_double "jobject"
%typemap(javaout) double jni_rep_get_double {
  return $jnicall;
}
%typemap(out, noblock=1) double jni_rep_get_double {
  if(temp_jni_rep_get_error_flag) {
    const jclass cls_Double = JCALL1(FindClass, jenv, "java/lang/Double");
    assert(cls_Double);
    const jmethodID mid_Double_init = JCALL3(GetMethodID, jenv, cls_Double, "<init>", "(D)V");
    assert(mid_Double_init);
    $result = JCALL3(NewObject, jenv, cls_Double, mid_Double_init, $1);
  } else {
    $result = NULL;
  }
}

%ignore oc_rep_get_double;
%rename(repGetDouble) jni_rep_get_double;
%inline %{
double jni_rep_get_double(oc_rep_t *rep, const char *key, bool *jni_rep_get_error_flag) {
  double retValue;
  *jni_rep_get_error_flag = oc_rep_get_double(rep, key, &retValue);
  return retValue;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *byte_string_size {
  size_t temp_byte_string_size;
  $1 = &temp_byte_string_size;
}
%typemap(jstype) const char * jni_rep_get_byte_string "byte[]"
%typemap(jtype) const char * jni_rep_get_byte_string "byte[]"
%typemap(jni) const char * jni_rep_get_byte_string "jbyteArray"
%typemap(javaout) const char * jni_rep_get_byte_string {
  return $jnicall;
}
%typemap(out) const char * jni_rep_get_byte_string {
  if($1 != NULL) {
    $result = JCALL1(NewByteArray, jenv, (jsize)temp_byte_string_size);
    JCALL4(SetByteArrayRegion, jenv, $result, 0, (jsize)temp_byte_string_size, (const jbyte *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_byte_string;
%rename(repGetByteString) jni_rep_get_byte_string;
%inline %{
const char * jni_rep_get_byte_string(oc_rep_t *rep, const char *key, size_t *byte_string_size) {
  char * c_byte_string = NULL;
  if (oc_rep_get_byte_string(rep, key, &c_byte_string, byte_string_size)) {
    return c_byte_string;
  }
  return NULL;
}
%}

%ignore oc_rep_get_string;
%rename(repGetString) jni_rep_get_string;
%inline %{
char * jni_rep_get_string(oc_rep_t *rep, const char *key) {
  char * retValue;
  size_t size;
  if(oc_rep_get_string(rep, key, &retValue, &size)) {
    return retValue;
  } else {
    return NULL;
  }
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *int_array_size {
  size_t temp_int_array_size;
  $1 = &temp_int_array_size;
}
%typemap(jstype) const int* jni_rep_get_int_array "int[]"
%typemap(jtype) const int* jni_rep_get_int_array "int[]"
%typemap(jni) const int* jni_rep_get_int_array "jintArray"
%typemap(javaout) const int* jni_rep_get_int_array {
  return $jnicall;
}
%typemap(out) const int* jni_rep_get_int_array {
  if($1 != NULL) {
    $result = JCALL1(NewIntArray, jenv, (jsize)temp_int_array_size);
    JCALL4(SetIntArrayRegion, jenv, $result, 0, (jsize)temp_int_array_size, (const jint *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_int_array;
%rename(repGetIntArray) jni_rep_get_int_array;
%inline %{
const int* jni_rep_get_int_array(oc_rep_t *rep, const char *key, size_t *int_array_size) {
  int *c_int_array;
  if (oc_rep_get_int_array(rep, key, &c_int_array, int_array_size)) {
    return c_int_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *bool_array_size {
  size_t temp_bool_array_size;
  $1 = &temp_bool_array_size;
}
%typemap(jstype) const bool* jni_rep_get_bool_array "boolean[]"
%typemap(jtype) const bool* jni_rep_get_bool_array "boolean[]"
%typemap(jni) const bool* jni_rep_get_bool_array "jbooleanArray"
%typemap(javaout) const bool* jni_rep_get_bool_array {
  return $jnicall;
}
%typemap(out) const bool* jni_rep_get_bool_array {
  if($1 != NULL) {
    $result = JCALL1(NewBooleanArray, jenv, (jsize)temp_bool_array_size);
    JCALL4(SetBooleanArrayRegion, jenv, $result, 0, (jsize)temp_bool_array_size, (const jboolean *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_bool_array;
%rename(repGetBooleanArray) jni_rep_get_bool_array;
%inline %{
const bool* jni_rep_get_bool_array(oc_rep_t *rep, const char *key, size_t *bool_array_size) {
  bool *c_bool_array;
  if (oc_rep_get_bool_array(rep, key, &c_bool_array, bool_array_size)) {
    return c_bool_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *double_array_size {
  size_t temp_double_array_size;
  $1 = &temp_double_array_size;
}
%typemap(jstype) const double* jni_rep_get_double_array "double[]"
%typemap(jtype) const double* jni_rep_get_double_array "double[]"
%typemap(jni) const double* jni_rep_get_double_array "jdoubleArray"
%typemap(javaout) const double* jni_rep_get_double_array {
  return $jnicall;
}
%typemap(out) const double* jni_rep_get_double_array {
  if($1 != NULL) {
    $result = JCALL1(NewDoubleArray, jenv, (jsize)temp_double_array_size);
    JCALL4(SetDoubleArrayRegion, jenv, $result, 0, (jsize)temp_double_array_size, (const jdouble *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_double_array;
%rename(repGetDoubleArray) jni_rep_get_double_array;
%inline %{
const double* jni_rep_get_double_array(oc_rep_t *rep, const char *key, size_t *double_array_size) {
  double *c_double_array;
  if (oc_rep_get_double_array(rep, key, &c_double_array, double_array_size)) {
    return c_double_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *byte_string_array_size {
  size_t temp_byte_string_array_size;
  $1 = &temp_byte_string_array_size;
}
%typemap(jstype) const oc_string_array_t * jni_rep_get_byte_string_array "byte[][]"
%typemap(jtype) const oc_string_array_t * jni_rep_get_byte_string_array "byte[][]"
%typemap(jni) const oc_string_array_t * jni_rep_get_byte_string_array "jobjectArray"
%typemap(javaout) const oc_string_array_t * jni_rep_get_byte_string_array {
  return $jnicall;
}
%typemap(out) const oc_string_array_t * jni_rep_get_byte_string_array {
  if($1 != NULL) {
    jbyteArray temp_byte_string;
    const jclass clazz = JCALL1(FindClass, jenv, "[B");
    $result = JCALL3(NewObjectArray, jenv, (jsize)temp_byte_string_array_size, clazz, 0);
    /* exception checking omitted */
    for (size_t i=0; i<temp_byte_string_array_size; i++) {
      jsize jbyte_array_size = oc_byte_string_array_get_item_size(*$1, i);
      temp_byte_string = JCALL1(NewByteArray, jenv, jbyte_array_size);
      JCALL4(SetByteArrayRegion, jenv, temp_byte_string, 0, jbyte_array_size,
             (const jbyte *)oc_byte_string_array_get_item(*$1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, (jsize)i, temp_byte_string);
      JCALL1(DeleteLocalRef, jenv, temp_byte_string);
    }
    /* free the oc_string_array_t that was allocated in the jni_rep_get_byte_string_array function */
    free($1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_byte_string_array;
%rename(repGetByteStringArray) jni_rep_get_byte_string_array;
%inline %{
const oc_string_array_t * jni_rep_get_byte_string_array(oc_rep_t *rep, const char *key, size_t *byte_string_array_size) {
  oc_string_array_t * c_byte_string_array = (oc_string_array_t *)malloc(sizeof(oc_string_array_t));
  if (oc_rep_get_byte_string_array(rep, key, c_byte_string_array, byte_string_array_size)) {
    return c_byte_string_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *string_array_size {
  size_t temp_string_array_size;
  $1 = &temp_string_array_size;
}
%typemap(jstype) const oc_string_array_t * jni_rep_get_string_array "String[]"
%typemap(jtype) const oc_string_array_t * jni_rep_get_string_array "String[]"
%typemap(jni) const oc_string_array_t * jni_rep_get_string_array "jobjectArray"
%typemap(javaout) const oc_string_array_t * jni_rep_get_string_array {
  return $jnicall;
}
%typemap(out) const oc_string_array_t * jni_rep_get_string_array {
  if($1 != NULL) {
    jstring temp_string;
    const jclass clazz = JCALL1(FindClass, jenv, "java/lang/String");
    $result = JCALL3(NewObjectArray, jenv, (jsize)temp_string_array_size, clazz, 0);
    /* exception checking omitted */
    for (size_t i=0; i<temp_string_array_size; i++) {
      temp_string = JCALL1(NewStringUTF, jenv, oc_string_array_get_item(*$1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, (jsize)i, temp_string);
      JCALL1(DeleteLocalRef, jenv, temp_string);
    }
    /* free the oc_string_array_t that was allocated in the jni_rep_get_string_array function */
    free($1);
    //JCALL4(SetDoubleArrayRegion, jenv, $result, 0, (jsize)temp_string_array_size, (const jdouble *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_string_array;
%rename(repGetStringArray) jni_rep_get_string_array;
%inline %{
const oc_string_array_t * jni_rep_get_string_array(oc_rep_t *rep, const char *key, size_t *string_array_size) {
  oc_string_array_t * c_string_array = (oc_string_array_t *)malloc(sizeof(oc_string_array_t));
  if (oc_rep_get_string_array(rep, key, c_string_array, string_array_size)) {
    return c_string_array;
  }
  return NULL;
}
%}

%ignore oc_rep_get_object;
%rename(repGetObject) jni_rep_get_object;
%inline %{
oc_rep_t * jni_rep_get_object(oc_rep_t* rep, const char *key) {
  oc_rep_t *value;
  if(oc_rep_get_object(rep, key, &value)) {
    return value;
  }
  return NULL;
}
%}
%ignore oc_rep_get_object_array;
%rename(repGetObjectArray) jni_rep_get_object_array;
%inline %{
oc_rep_t * jni_rep_get_object_array(oc_rep_t* rep, const char *key) {
  oc_rep_t *value;
  if(oc_rep_get_object_array(rep, key, &value)) {
    return value;
  }
  return NULL;
}
%}
%rename (getRepError) jni_get_rep_error;
%inline %{
int jni_get_rep_error() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return g_err;
}
%}

// Expose oc_array_t this will be exposed as a class that has no usage without helper functions
%rename (OCArray) oc_array_t;
typedef struct oc_array_t {};

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_int_array_len {
  size_t temp_oc_array_int_array_len;
  $1 = &temp_oc_array_int_array_len;
}
%typemap(jstype)  const int * ocArrayToIntArray "int[]"
%typemap(jtype)   const int * ocArrayToIntArray "int[]"
%typemap(jni)     const int * ocArrayToIntArray "jintArray"
%typemap(javaout) const int * ocArrayToIntArray {
  return $jnicall;
}
%typemap(out) const int * ocArrayToIntArray {
  if($1 != NULL) {
    $result = JCALL1(NewIntArray, jenv, (jsize)temp_oc_array_int_array_len);
    JCALL4(SetIntArrayRegion, jenv, $result, 0, (jsize)temp_oc_array_int_array_len, (const jint *)$1);
  } else {
    $result = NULL;
  }
}
%inline %{
const int * ocArrayToIntArray(oc_array_t array, size_t *oc_array_int_array_len) {
  *oc_array_int_array_len = (size_t)oc_int_array_size(array);
  return oc_int_array(array);
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_bool_array_len {
  size_t temp_oc_array_bool_array_len;
  $1 = &temp_oc_array_bool_array_len;
}
%typemap(jstype) const bool* ocArrayToBooleanArray "boolean[]"
%typemap(jtype) const bool* ocArrayToBooleanArray "boolean[]"
%typemap(jni) const bool* ocArrayToBooleanArray "jbooleanArray"
%typemap(javaout) const bool* ocArrayToBooleanArray {
  return $jnicall;
}
%typemap(out) const bool* ocArrayToBooleanArray {
  if($1 != NULL) {
    $result = JCALL1(NewBooleanArray, jenv, (jsize)temp_oc_array_bool_array_len);
    JCALL4(SetBooleanArrayRegion, jenv, $result, 0, (jsize)temp_oc_array_bool_array_len, (const jboolean *)$1);
  } else {
    $result = NULL;
  }
}
%inline %{
const bool* ocArrayToBooleanArray(oc_array_t array, size_t *oc_array_bool_array_len) {
  *oc_array_bool_array_len = (size_t)oc_bool_array_size(array);
  return oc_bool_array(array);
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_double_array_len {
  size_t temp_oc_array_double_array_len;
  $1 = &temp_oc_array_double_array_len;
}
%typemap(jstype)  const double* ocArrayToDoubleArray "double[]"
%typemap(jtype)   const double* ocArrayToDoubleArray "double[]"
%typemap(jni)     const double* ocArrayToDoubleArray "jdoubleArray"
%typemap(javaout) const double* ocArrayToDoubleArray {
  return $jnicall;
}
%typemap(out) const double* ocArrayToDoubleArray {
  if($1 != NULL) {
    $result = JCALL1(NewDoubleArray, jenv, (jsize)temp_oc_array_double_array_len);
    JCALL4(SetDoubleArrayRegion, jenv, $result, 0, (jsize)temp_oc_array_double_array_len, (const jdouble *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_double_array;
%rename(repGetDoubleArray) jni_rep_get_double_array;
%inline %{
const double* ocArrayToDoubleArray(oc_array_t array, size_t *oc_array_double_array_len) {
  *oc_array_double_array_len = (size_t)oc_double_array_size(array);
  return oc_double_array(array);
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_text_string_array_len {
  size_t temp_oc_array_text_string_array_len;
  $1 = &temp_oc_array_text_string_array_len;
}
%typemap(jstype)  const oc_string_array_t * ocArrayToStringArray "String[]"
%typemap(jtype)   const oc_string_array_t * ocArrayToStringArray "String[]"
%typemap(jni)     const oc_string_array_t * ocArrayToStringArray "jobjectArray"
%typemap(javaout) const oc_string_array_t * ocArrayToStringArray {
  return $jnicall;
}
%typemap(out) const oc_string_array_t * ocArrayToStringArray {
  if($1 != NULL) {
    jstring temp_string;
    const jclass clazz = JCALL1(FindClass, jenv, "java/lang/String");
    $result = JCALL3(NewObjectArray, jenv, (jsize)temp_oc_array_text_string_array_len, clazz, 0);
    /* exception checking omitted */
    for (size_t i=0; i<temp_oc_array_text_string_array_len; i++) {
      temp_string = JCALL1(NewStringUTF, jenv, oc_string_array_get_item(*$1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, (jsize)i, temp_string);
      JCALL1(DeleteLocalRef, jenv, temp_string);
    }
  } else {
    $result = NULL;
  }
}
%inline %{
const oc_string_array_t * ocArrayToStringArray(oc_array_t *array, size_t *oc_array_text_string_array_len) {
  *oc_array_text_string_array_len = (size_t)oc_string_array_get_allocated_size(*array);
  return (oc_string_array_t *)array;
}
%}

%include "oc_rep.h"
/*******************End oc_rep.h****************************/
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
/**************************************************************
Add OCCollection and OCList to the output
***************************************************************/

//replace all instances of oc_link_s with oc_link_t since parser
// seems to have a problem with typedef that tells the code they
// are both the same
%rename(OCLink) oc_link_t;
%ignore oc_link_s;
typedef struct
{
  struct oc_link_t *next;
  oc_resource_t *resource;
  oc_string_t ins;
  oc_string_array_t rel;
}oc_link_t;

// replace all instance os oc_collection_s with oc_collection_t
%rename(OCCollection) oc_collection_t;
%ignore oc_collection_s;
typedef struct
{
  struct oc_collection_t *next;
  size_t device;
  oc_string_t name;
  oc_string_t uri;
  oc_string_array_t types;
  oc_interface_mask_t interfaces;
  oc_interface_mask_t default_interface;
  oc_resource_properties_t properties;
  oc_request_handler_t get_handler;
  oc_request_handler_t put_handler;
  oc_request_handler_t post_handler;
  oc_request_handler_t delete_handler;
  OC_LIST_STRUCT(links);
}oc_collection_t;

/*******************Begin oc_collection.h*******************/
%rename(handleCollectionRequest) oc_handle_collection_request;
%rename(newCollection) oc_collection_alloc;
%rename(freeCollection) oc_collection_free;
%rename(getCollectionByUri) oc_get_collection_by_uri;
%rename(collectionGetAll) oc_collection_get_all;
%rename(getLinkByUri) oc_get_link_by_uri;
%rename(checkIfCollection) oc_check_if_collection;
%rename(collectionAdd) oc_collection_add;
%include "oc_collection.h"
/*******************End oc_collection.h*********************/
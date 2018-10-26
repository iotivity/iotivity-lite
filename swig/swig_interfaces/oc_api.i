/* File oc_api.i */
%module OCMain
%include "carrays.i"
%include "arrays_java.i"
%include "stdint.i"
%include <oc_ri.i>
%include "typemaps.i"
%include "iotivity.swg"

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
#include <vector>
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
std::vector <jni_callback_data*> jni_callbacks_vector;
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
/* Callback handlers for oc_main_init */
static JavaVM *jvm;
static jobject jinit_obj;
static jclass cls_OCMainInitHandler;

int oc_handler_init_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  JNIEnv *jenv = 0;
  int getEnvResult = 0;
  int attachCurrentThreadResult = 0;
  getEnvResult = jvm->GetEnv((void**)&jenv, JNI_VERSION_1_6);
  if (JNI_EDETACHED == getEnvResult) {
#ifdef __ANDROID__
      attachCurrentThreadResult = jvm->AttachCurrentThread(&jenv, NULL);
#else
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
#endif
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_initialize = jenv->GetMethodID(cls_OCMainInitHandler, "initialize", "()I");
  assert(mid_initialize);
  jint ret_value = jenv->CallIntMethod(jinit_obj, mid_initialize);
  if (JNI_EDETACHED == getEnvResult) {
      jvm->DetachCurrentThread();
  }
  return (int)ret_value;
}

void oc_handler_signal_event_loop_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  JNIEnv *jenv = 0;
  int getEnvResult = 0;
  int attachCurrentThreadResult = 0;
  getEnvResult = jvm->GetEnv((void**)&jenv, JNI_VERSION_1_6);
  if (JNI_EDETACHED == getEnvResult) {
#ifdef __ANDROID__
      attachCurrentThreadResult = jvm->AttachCurrentThread(&jenv, NULL);
#else
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
#endif
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_signalEventLoop = jenv->GetMethodID(cls_OCMainInitHandler, "signalEventLoop", "()V");
  assert(mid_signalEventLoop);
  jenv->CallVoidMethod(jinit_obj, mid_signalEventLoop);
  if (JNI_EDETACHED == getEnvResult) {
      jvm->DetachCurrentThread();
  }
}

void oc_handler_register_resource_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  JNIEnv *jenv = 0;
  int getEnvResult = 0;
  int attachCurrentThreadResult = 0;
  getEnvResult = jvm->GetEnv((void**)&jenv, JNI_VERSION_1_6);
  if (JNI_EDETACHED == getEnvResult) {
#ifdef __ANDROID__
      attachCurrentThreadResult = jvm->AttachCurrentThread(&jenv, NULL);
#else
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
#endif
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_registerResources = jenv->GetMethodID(cls_OCMainInitHandler, "registerResources", "()V");
  assert(mid_registerResources);
  jenv->CallVoidMethod(jinit_obj, mid_registerResources);
  if (JNI_EDETACHED == getEnvResult) {
      jvm->DetachCurrentThread();
  }
}

void oc_handler_requests_entry_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  JNIEnv *jenv = 0;
  int getEnvResult = 0;
  int attachCurrentThreadResult = 0;
  getEnvResult = jvm->GetEnv((void**)&jenv, JNI_VERSION_1_6);
  if (JNI_EDETACHED == getEnvResult) {
#ifdef __ANDROID__
      attachCurrentThreadResult = jvm->AttachCurrentThread(&jenv, NULL);
#else
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
#endif
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_requestEntry_method = jenv->GetMethodID(cls_OCMainInitHandler, "requestEntry", "()V");
  assert(mid_requestEntry_method);
  jenv->CallVoidMethod(jinit_obj, mid_requestEntry_method);
  if (JNI_EDETACHED == getEnvResult) {
      jvm->DetachCurrentThread();
  }
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
/* typedef needed for oc_main_pool */
typedef uint64_t oc_clock_time_t;
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

int jni_oc_add_device0(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return oc_add_device(uri, rt, name, spec_version, data_model_version, NULL, NULL);
}

void jni_oc_resource_make_public(oc_resource_t *resource) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
#ifdef OC_SECURITY
  oc_resource_make_public(resource);
#endif /* OC_SECURITY */
}

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
%typemap(jni)    oc_add_device_cb_t add_device_cb "jobject";
%typemap(jtype)  oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(jstype) oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(javain) oc_add_device_cb_t add_device_cb "$javainput";
%typemap(in,numinputs=1) (oc_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_add_device_callback;
  $2 = user_data;
}
%ignore oc_add_device;
%rename(addDevice) jni_oc_add_device0;
int jni_oc_add_device0(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version);
%rename(addDevice) jni_oc_add_device1;
int jni_oc_add_device1(const char *uri, const char *rt, const char *name,
                  const char *spec_version, const char *data_model_version,
                  oc_add_device_cb_t add_device_cb, jni_callback_data *jcb,
                  void *user_data);

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

int jni_oc_init_platform0(const char *mfg_name) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return oc_init_platform(mfg_name, NULL, NULL);
}

int jni_oc_init_platform1(const char *mfg_name, oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb, void *user_data) {
 OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_platform(mfg_name, init_platform_cb, jcb);
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
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_init_platform_callback;
  $2 = user_data;
}
%ignore oc_init_platform;
/* the oc_init_platform without the callback or data pointer */
%rename(initPlatform) jni_oc_init_platform0;
int jni_oc_init_platform0(const char *mfg_name);
%rename(initPlatform) jni_oc_init_platform1;
int jni_oc_init_platform1(const char *mfg_name, oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb, void *user_data);
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
  const jclass callbackInterfaceClass = (data->jenv)->FindClass("org/iotivity/OCRequestHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = (data->jenv)->GetMethodID(callbackInterfaceClass, "handler", "(Lorg/iotivity/OCRequest;ILjava/lang/Object;)V");
  assert(mid_handler);

  const jclass cls_OCRequest = (data->jenv)->FindClass("org/iotivity/OCRequest");
  assert(cls_OCRequest);
  const jmethodID mid_OCRequest_init = (data->jenv)->GetMethodID(cls_OCRequest, "<init>", "(JZ)V");
  assert(mid_OCRequest_init);
  (data->jenv)->CallVoidMethod(data->jcb_obj, mid_handler, (data->jenv)->NewObject(cls_OCRequest, mid_OCRequest_init, (jlong)request, false), (jint)interfaces, data->juser_data);
}

void jni_oc_resource_set_request_handler0(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_resource_set_request_handler(resource, method, callback, jcb);
}

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
%typemap(jni)    oc_request_callback_t callback "jobject";
%typemap(jtype)  oc_request_callback_t callback "OCRequestHandler";
%typemap(jstype) oc_request_callback_t callback "OCRequestHandler";
%typemap(javain) oc_request_callback_t callback "$javainput";
%typemap(in,numinputs=1) (oc_request_callback_t callback, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->jenv = jenv;
  user_data->jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_request_callback;
  $2 = user_data;
}
%ignore oc_resource_set_request_handler;
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler0;
void jni_oc_resource_set_request_handler0(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb);
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler1;
void jni_oc_resource_set_request_handler1(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb,
                                          void *user_data);
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

%rename(initQueryIterator) oc_init_query_iterator;
%rename(iterateQuery) oc_iterate_query;
%rename(iterateQueryGetValues) oc_iterate_query_get_values;
%rename(getQueryValue) oc_get_query_value;
%rename(sendResponse) oc_send_response;
%rename(ignoreRequest) oc_ignore_request;
%rename(indicateSeparateResponse) oc_indicate_separate_response;
%rename(setSeparateResponseBuffer) oc_set_separate_response_buffer;
%rename(sendSeparateResponse) oc_send_separate_response;
%rename(notifyObservers) oc_notify_observers;

// client side
/* Code and typemaps for mapping the oc_do_ip_discovery and oc_do_ip_discovery_at_endpoint to the java OCDiscoveryHandler */
%{
bool jni_oc_do_ip_discovery0(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_discovery(rt, handler, jcb);
}

bool jni_oc_do_ip_discovery1(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb, void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_ip_discovery(rt, handler, jcb);
}

bool jni_oc_do_ip_discovery_at_endpoint0(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, jcb);
}

bool jni_oc_do_ip_discovery_at_endpoint1(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint, void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_ip_discovery_at_endpoint(rt, handler, endpoint, jcb);
}

oc_discovery_flags_t jni_oc_discovery_handler_callback(const char *anchor,
                                                        const char *uri,
                                                        oc_string_array_t types,
                                                        oc_interface_mask_t interfaces,
                                                        oc_endpoint_t *endpoint,
                                                        oc_resource_properties_t bm,
                                                        void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;

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
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_discovery_handler_callback;
  $2 = user_data;
}
%ignore oc_do_ip_discovery;
%rename(doIPDiscovery) jni_oc_do_ip_discovery0;
bool jni_oc_do_ip_discovery0(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb);
%rename(doIPDiscovery) jni_oc_do_ip_discovery1;
bool jni_oc_do_ip_discovery1(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb, void *user_data);
%ignore oc_do_ip_discovery_at_endpoint;
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint0;
bool jni_oc_do_ip_discovery_at_endpoint0(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint);
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint1;
bool jni_oc_do_ip_discovery_at_endpoint1(const char *rt,
                                        oc_discovery_handler_t handler, jni_callback_data *jcb,
                                        oc_endpoint_t *endpoint, void *user_data);

/* Code and typemaps for mapping the oc_do_get, oc_do_delete, oc_init_put, oc_init_post, oc_do_observe,
 * and oc_do_ip_multicast to the java OCResponseHandler */
%{
void jni_oc_response_handler(oc_client_response_t *response) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)response->user_data;
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
}

bool jni_oc_do_get0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_get(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_get1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_get(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_delete0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos){
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_delete(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_delete1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos, void *user_data){
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_delete(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_init_put0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_init_put(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_init_put1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_put(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_init_post0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_init_post(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_init_post1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_post(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_observe0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_observe(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_observe1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_observe(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_ip_multicast0(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_multicast(uri, query, handler, jcb);
}

bool jni_oc_do_ip_multicast1(const char *uri, const char *query,
                        oc_response_handler_t handler, jni_callback_data *jcb, void *user_data){
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_do_ip_multicast(uri, query, handler, jcb);
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
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_response_handler;
  $2 = user_data;
}
%ignore oc_do_get;
%rename(doGet) jni_oc_do_get0;
bool jni_oc_do_get0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos);
%rename(doGet) jni_oc_do_get1;
bool jni_oc_do_get1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos, void *user_data);
%ignore oc_do_delete;
%rename(doDelete) jni_oc_do_delete0;
bool jni_oc_do_delete0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos);
%rename(doDelete) jni_oc_do_delete1;
bool jni_oc_do_delete1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos, void *user_data);

%ignore oc_init_put;
%rename(initPut) jni_oc_init_put0;
bool jni_oc_init_put0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos);
%rename(initPut) jni_oc_init_put1;
bool jni_oc_init_put1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos, void *user_data);
%rename(doPut) oc_do_put;
%ignore oc_init_post;
%rename(initPost) jni_oc_init_post0;
bool jni_oc_init_post0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos);
%rename(initPost) jni_oc_init_post1;
bool jni_oc_init_post1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos, void *user_data);
%rename(doPost) oc_do_post;
%ignore oc_do_observe;
%rename(doObserve) jni_oc_do_observe0;
bool jni_oc_do_observe0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos);
%rename(doObserve) jni_oc_do_observe1;
bool jni_oc_do_observe1(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos, void *user_data);
%rename(stopObserve) oc_stop_observe;
%ignore oc_do_ip_multicast;
%rename(doIPMulticast) jni_oc_do_ip_multicast0;
bool jni_oc_do_ip_multicast0(const char *uri, const char *query,
                             oc_response_handler_t handler, jni_callback_data *jcb);
%rename(doIPMulticast) jni_oc_do_ip_multicast1;
bool jni_oc_do_ip_multicast1(const char *uri, const char *query,
                             oc_response_handler_t handler, jni_callback_data *jcb, void *user_data);

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

void jni_oc_set_delayed_callback0(oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  oc_set_delayed_callback(jcb, callback, seconds);
}

void jni_oc_set_delayed_callback1(void *user_data, oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  oc_set_delayed_callback(jcb, callback, seconds);
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
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_trigger_handler;
  $2 = user_data;
}
%ignore oc_set_delayed_callback;
%rename(setDelayedHandler) jni_oc_set_delayed_callback0;
void jni_oc_set_delayed_callback0(oc_trigger_t callback, jni_callback_data *jcb,
                                  uint16_t seconds);
%rename(setDelayedHandler) jni_oc_set_delayed_callback1;
void jni_oc_set_delayed_callback1(void *user_data, oc_trigger_t callback, jni_callback_data *jcb,
                                 uint16_t seconds);

/*
 * Version of oc_remove_delayed_callback that also removes java GlobalRefs and frees memory
 * associated with the now removed java callback handler
 */
%{
void jni_oc_remove_delayed_callback(jobject callback) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  auto it = jni_callbacks_vector.begin();
  for (it = jni_callbacks_vector.begin(); it != jni_callbacks_vector.end(); ++it) {
    if ((*it)->jenv->IsSameObject(callback, (*it)->jcb_obj)) {
      oc_remove_delayed_callback(*it, jni_oc_trigger_handler);
      (*it)->jenv->DeleteGlobalRef((*it)->jcb_obj);
      (*it)->jenv->DeleteGlobalRef((*it)->juser_data);
      break;
    }
  }
  if (it != jni_callbacks_vector.end()) {
    free(*it);
    jni_callbacks_vector.erase(it);
    //Prevent the jni_callback_vector from using un-needed memory.
    jni_callbacks_vector.shrink_to_fit();
  }
}
%}
// TODO consider renaming the `jobject callback` to be less generic
%typemap(jtype)  jobject callback "OCTriggerHandler";
%typemap(jstype) jobject callback "OCTriggerHandler";
%ignore oc_remove_delayed_callback;
%rename(removeDelayedHandler) jni_oc_remove_delayed_callback;
void jni_oc_remove_delayed_callback(jobject callback);
%include "oc_api.h"

/*******************Begin cbor.h******************************/
/* CborEncoder from cbor.h  needed to process oc_rep.h*/
struct CborEncoder
{
    union {
        uint8_t *ptr;
        ptrdiff_t bytes_needed;
    } data;
    const uint8_t *end;
    size_t remaining;
    int flags;
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
%ignore oc_rep_finalize;
%rename (repSetDouble) jni_rep_set_double;
%inline %{
/* Alt implementation of oc_rep_set_double macro*/
void jni_rep_set_double(CborEncoder * object, const char* key, bool value) {
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

%rename (repSetByteString) jni_rep_set_byte_string;
%inline %{
/* Alt implementation of oc_rep_set_byte_string macro */
void jni_rep_set_byte_string(CborEncoder * object, const char* key, const unsigned char* value, size_t length) {
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


// TODO revisit this will add an array object to the parent object under key value. The CborEncoder*
// returned is the array object. The `object` parameter may make more since to be named `parent`.
%rename(repSetArray) jni_rep_set_array;
%inline %{
/* Alt implementation of oc_rep_set_array macro */
CborEncoder * jni_rep_set_array(CborEncoder *object, const char* key) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  return jni_rep_start_array(object);
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

%rename(repSetObject) jni_rep_set_object;
%inline %{
/* Alt implementation of oc_rep_set_object macro */
CborEncoder * jni_rep_set_object(CborEncoder *object, const char* key) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  return jni_rep_start_object(object);
}
%}

%rename(repCloseObject) jni_rep_close_object;
%inline %{
/* Alt implementation of oc_rep_close_object macro */
void jni_rep_close_object(CborEncoder *object, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jni_rep_end_object(object, arrayObject);
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

%rename(repSetBoolArray) jni_rep_set_bool_array;
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

%ignore oc_rep_get_cbor_errno;
%ignore oc_rep_set_pool;
%ignore oc_parse_rep;
%ignore oc_free_rep;
/*
%ignore oc_rep_get_int;
%ignore oc_rep_get_bool;
%ignore oc_rep_get_double;
%ignore oc_rep_get_byte_string;
%ignore oc_rep_get_string;
%ignore oc_rep_get_int_array;
%ignore oc_rep_get_bool_array;
%ignore oc_rep_get_double_array;
%ignore oc_rep_get_byte_string_array;
%ignore oc_rep_get_string_array;
%ignore oc_rep_get_object;
%ignore oc_rep_get_object_array;
*/

%apply int *OUTPUT { int *value }
%rename(repGetInt) oc_rep_get_int;
%apply bool *OUTPUT { bool *value }
%rename(repGetBool) oc_rep_get_bool;
%apply double *OUTPUT { double *value }
%rename(repGetDouble) oc_rep_get_double;
//%apply(char **STRING, size_t *LENGTH) { (char **key, size_t *value) };
%rename(repGetByteString) oc_rep_get_byte_string;
%typemap(jni) (char **value, size_t *size) "jobjectArray"
%typemap(jtype) (char **value, size_t *size) "String[]"
%typemap(jstype) (char **value, size_t *size) "String[]"
%typemap(javain) (char **value, size_t *size) "$javainput"
%typemap(javadirectorin) (char **value, size_t *size) "$javainput"
%typemap(javadirectorout) (char **value, size_t *size) "$javacall"

%typemap(in) (char **value, size_t *size) ($*1_ltype temp_value, $*2_ltype temp_size) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  if (JCALL1(GetArrayLength, jenv, $input) == 0) {
    SWIG_JavaThrowException(jenv, SWIG_JavaIndexOutOfBoundsException, "Array must contain at least 1 element");
    return $null;
  }
  temp_value = ($*1_ltype)0;
  $1 = &temp_value;
  $2 = &temp_size;
}

%typemap(freearg) (char **value, size_t *size) ""


/* TODO figureout a way to free the string that is returned in the array
%typemap(freearg) (char **value, size_t *size) {
  if ($1 && $1->ptr) {
    jstring jvalue = (jstring)JCALL2(GetObjectArrayElement, jenv, $input, 0);
    JCALL2(ReleaseStringUTFChars, jenv, jvalue, temp_value$argnum);
  }
}
*/

%typemap(argout) (char **value, size_t *size) {
  temp_value$argnum = *$1;
  jstring jvalue = JCALL1(NewStringUTF, jenv, temp_value$argnum);
  JCALL3(SetObjectArrayElement, jenv, $input, 0, jvalue);
}
%rename(repGetString) oc_rep_get_string;

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
//%rename(repGetIntArray) oc_rep_get_int_array;
%rename(repGetBoolArray) oc_rep_get_bool_array;
%rename(repGetDoubleArray) oc_rep_get_double_array;
%rename(repGetByteStringArray) oc_rep_get_byte_string_array;
%rename(repGetStringArray) oc_rep_get_string_array;
%rename(repGetObject) oc_rep_get_object;
%rename(repGetObjectArray) oc_rep_get_object_array;
%{
int jni_get_rep_error() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return g_err;
}
%}
%rename (getRepError) jni_get_rep_error;
int jni_get_rep_error();
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
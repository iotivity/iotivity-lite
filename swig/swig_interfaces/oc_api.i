/* File oc_api.i */
%module OCMain
%include <oc_clock.i>
%include "arrays_java.i"
%include "stdint.i"
%include <oc_ri.i>
%include "iotivity.swg"

%{
#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include <vector>
#include <assert.h>

struct jni_callback_data {
  JNIEnv *env;
  jobject obj;
  jobject juser_data;
};


std::vector <jni_callback_data*> jni_callbacks_vector;

/* Callback handlers for oc_main_init */
static JavaVM *jvm;
static jobject init_obj;
static jclass cls_OCMainInitHandler;

static struct jni_callback_data oc_con_write_cb_data;

int oc_handler_init_callback(void)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  JNIEnv *jenv = 0;
  int getEnvResult = 0;
  int attachCurrentThreadResult = 0;
  getEnvResult = jvm->GetEnv((void**)&jenv, JNI_VERSION_1_6);
  if (JNI_EDETACHED == getEnvResult) {
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_initilize = jenv->GetMethodID(cls_OCMainInitHandler, "initilize", "()I");
  assert(mid_initilize);
  jint ret_value = jenv->CallIntMethod(init_obj, mid_initilize);
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
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_signalEventLoop = jenv->GetMethodID(cls_OCMainInitHandler, "signalEventLoop", "()V");
  assert(mid_signalEventLoop);
  jenv->CallIntMethod(init_obj, mid_signalEventLoop);
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
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_registerResources = jenv->GetMethodID(cls_OCMainInitHandler, "registerResources", "()V");
  assert(mid_registerResources);
  jenv->CallVoidMethod(init_obj, mid_registerResources);
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
      attachCurrentThreadResult = jvm->AttachCurrentThread((void**)&jenv, NULL);
      assert(JNI_OK == attachCurrentThreadResult);
  }
  assert(jenv);
  assert(cls_OCMainInitHandler);
  const jmethodID mid_requestEntry_method = jenv->GetMethodID(cls_OCMainInitHandler, "requestEntry", "()V");
  assert(mid_requestEntry_method);
  jenv->CallVoidMethod(init_obj, mid_requestEntry_method);
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

void jni_oc_resource_set_request_handler0(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb) 
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_resource_set_request_handler(resource, method, callback, jcb);
}
                                          
void jni_oc_resource_set_request_handler(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb,
                                          void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_resource_set_request_handler(resource, method, callback, jcb);
}
    
void jni_oc_request_callback(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;
  const jclass callbackInterfaceClass = (data->env)->FindClass("org/iotivity/OCRequestHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = (data->env)->GetMethodID(callbackInterfaceClass, "handler", "(Lorg/iotivity/OCRequest;ILjava/lang/Object;)V");
  assert(mid_handler);

  const jclass cls_OCRequest = (data->env)->FindClass("org/iotivity/OCRequest");
  assert(cls_OCRequest);
  const jmethodID mid_OCRequest_init = (data->env)->GetMethodID(cls_OCRequest, "<init>", "(JZ)V");
  assert(mid_OCRequest_init);
  (data->env)->CallVoidMethod(data->obj, mid_handler, (data->env)->NewObject(cls_OCRequest, mid_OCRequest_init, (jlong)request, false), (jint)interfaces, data->juser_data);
}

bool jni_oc_do_ip_discovery0(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_ip_discovery(rt, handler, jcb);
}

bool jni_oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb, void *user_data)
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

bool jni_oc_do_ip_discovery_at_endpoint(const char *rt,
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

  jstring janchor = (data->env)->NewStringUTF(anchor);
  jstring juri = (data->env)->NewStringUTF(uri);
  jobjectArray jtypes = (data->env)->NewObjectArray((jsize)oc_string_array_get_allocated_size(types),
                                                    (data->env)->FindClass("java/lang/String"),0);
  for (jsize i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    jstring str = (data->env)->NewStringUTF(oc_string_array_get_item(types, i));
    (data->env)->SetObjectArrayElement(jtypes, i, str);
  }
  jint jinterfaceMask = (jint)interfaces;

  // create java endpoint
  const jclass cls_OCEndpoint = (data->env)->FindClass("org/iotivity/OCEndpoint");
  assert(cls_OCEndpoint);
  const jmethodID mid_OCEndpoint_init = (data->env)->GetMethodID(cls_OCEndpoint, "<init>", "(JZ)V");
  assert(mid_OCEndpoint_init);
  jobject jendpoint = (data->env)->NewObject(cls_OCEndpoint, mid_OCEndpoint_init, (jlong)endpoint, false);

  jint jresourcePropertiesMask = (jint)bm;
  const jclass callbackInterfaceClass = (data->env)->FindClass("org/iotivity/OCDiscoveryHandler");
  assert(callbackInterfaceClass);
  const jmethodID mid_handler = (data->env)->GetMethodID(callbackInterfaceClass,
          "handler",
          "(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;ILorg/iotivity/OCEndpoint;ILjava/lang/Object;)Lorg/iotivity/OCDiscoveryFlags;");
  assert(mid_handler);
  jobject jDiscoveryFlag = (data->env)->CallObjectMethod(data->obj, mid_handler, janchor, juri,
                                                         jtypes, jinterfaceMask, jendpoint,
                                                         jresourcePropertiesMask, data->juser_data);
  jclass cls_DiscoveryFlags = (data->env)->GetObjectClass(jDiscoveryFlag);
  assert(cls_DiscoveryFlags);
  const jmethodID mid_OCDiscoveryFlags_swigValue = (data->env)->GetMethodID(cls_DiscoveryFlags, "swigValue", "()I");
  assert(mid_OCDiscoveryFlags_swigValue);
  jint return_value = (data->env)->CallIntMethod(jDiscoveryFlag, mid_OCDiscoveryFlags_swigValue);
  return (oc_discovery_flags_t) return_value;
}

bool jni_oc_do_get0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  return oc_do_get(uri, endpoint, query, handler, qos, jcb);
}

bool jni_oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
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

bool jni_oc_init_put(const char *uri, oc_endpoint_t *endpoint, const char *query,
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

bool jni_oc_init_post(const char *uri, oc_endpoint_t *endpoint, const char *query,
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

bool jni_oc_do_observe(const char *uri, oc_endpoint_t *endpoint, const char *query,
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

void jni_oc_response_handler(oc_client_response_t *response) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)response->user_data;
  const jclass cls_OCClientResponce = (data->env)->FindClass("org/iotivity/OCClientResponse");
  assert(cls_OCClientResponce);
  const jmethodID mid_OCClientResponce_init = (data->env)->GetMethodID(cls_OCClientResponce, "<init>", "(JZ)V");
  assert(mid_OCClientResponce_init);
  jobject jresponse = (data->env)->NewObject(cls_OCClientResponce, mid_OCClientResponce_init, (jlong)response, false);

  const jclass cls_OCResponseHandler = (data->env)->FindClass("org/iotivity/OCResponseHandler");
  assert(cls_OCResponseHandler);
  const jmethodID mid_handler = (data->env)->GetMethodID(cls_OCResponseHandler,
                                                         "handler",
                                                         "(Lorg/iotivity/OCClientResponse;)V");
  assert(mid_handler);
  (data->env)->CallObjectMethod(data->obj, mid_handler, jresponse);
}

void jni_oc_set_delayed_callback0(oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = NULL;
  oc_set_delayed_callback(jcb, callback, seconds);
}

void jni_oc_set_delayed_callback(void *user_data, oc_trigger_t callback, jni_callback_data *jcb, uint16_t seconds) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  oc_set_delayed_callback(jcb, callback, seconds);
}

oc_event_callback_retval_t jni_oc_trigger_handler(void* cb_data) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)cb_data;

  const jclass cls_OCTriggerHandler = (data->env)->FindClass("org/iotivity/OCTriggerHandler");
  assert(cls_OCTriggerHandler);
  const jmethodID mid_handler = (data->env)->GetMethodID(cls_OCTriggerHandler,
                                                         "handler",
                                                         "(Ljava/lang/Object;)Lorg/iotivity/OCEventCallbackResult;");
  assert(mid_handler);
  jobject jEventCallbackRet = (data->env)->CallObjectMethod(data->obj, mid_handler, data->juser_data);
  
  jclass cls_OCEventCallbackResult = (data->env)->GetObjectClass(jEventCallbackRet);
  assert(cls_OCEventCallbackResult);
  const jmethodID mid_OCEventCallbackResult_swigValue = (data->env)->GetMethodID(cls_OCEventCallbackResult, "swigValue", "()I");
  assert(mid_OCEventCallbackResult_swigValue);
  jint return_value = (data->env)->CallIntMethod(jEventCallbackRet, mid_OCEventCallbackResult_swigValue);
  return (oc_event_callback_retval_t) return_value;
}

void jni_oc_remove_delayed_callback(jobject callback) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  auto it = jni_callbacks_vector.begin();
  for (it = jni_callbacks_vector.begin(); it != jni_callbacks_vector.end(); ++it) {
    if ((*it)->env->IsSameObject(callback, (*it)->obj)) {
      oc_remove_delayed_callback(*it, jni_oc_trigger_handler);
      (*it)->env->DeleteGlobalRef((*it)->obj);
      (*it)->env->DeleteGlobalRef((*it)->juser_data);
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

int jni_oc_init_platform0(const char *mfg_name) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return oc_init_platform(mfg_name, NULL, NULL);
}

int jni_oc_init_platform1(const char *mfg_name, oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb, void *user_data) {
 OC_DBG("JNI: %s\n", __FUNCTION__);
  jcb->juser_data = *(jobject*)user_data;
  return oc_init_platform(mfg_name, init_platform_cb, jcb);
}

void jni_oc_init_platform_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;

  const jclass cls_OCInitPlatformHandler = (data->env)->FindClass("org/iotivity/OCInitPlatformHandler");
  assert(cls_OCInitPlatformHandler);
  const jmethodID mid_handler = (data->env)->GetMethodID(cls_OCInitPlatformHandler,
                                                         "handler",
                                                         "(Ljava/lang/Object;)V");
  assert(mid_handler);
  (data->env)->CallObjectMethod(data->obj, mid_handler, data->juser_data);
}

int jni_oc_add_device0(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return oc_add_device(uri, rt, name, spec_version, data_model_version, NULL, NULL);
}

void jni_oc_resource_make_public() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
#ifdef OC_SECURITY
  oc_resource_make_public(res);
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

void jni_oc_add_device_callback(void *user_data)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  struct jni_callback_data *data = (jni_callback_data *)user_data;

  const jclass cls_OCAddDeviceHandler = (data->env)->FindClass("org/iotivity/OCAddDeviceHandler");
  assert(cls_OCAddDeviceHandler);
  const jmethodID mid_handler = (data->env)->GetMethodID(cls_OCAddDeviceHandler,
                                                         "handler",
                                                         "(Ljava/lang/Object;)V");
  assert(mid_handler);
  (data->env)->CallObjectMethod(data->obj, mid_handler, data->juser_data);
}

void jni_oc_con_callback(size_t device_index, oc_rep_t *rep)
{
  OC_DBG("JNI: %s\n", __FUNCTION__);
  const jclass cls_OCConWriteHandler = (oc_con_write_cb_data.env)->FindClass("org/iotivity/OCConWriteHandler");
  assert(cls_OCConWriteHandler);
  const jmethodID mid_handler = (oc_con_write_cb_data.env)->GetMethodID(cls_OCConWriteHandler, "handler", "(JLorg/iotivity/OCRepresentation;)V");
  assert(mid_handler);

  const jclass cls_OCRepresentation = (oc_con_write_cb_data.env)->FindClass("org/iotivity/OCRepresentation");
  assert(cls_OCRepresentation);
  const jmethodID mid_OCRepresentation_init = (oc_con_write_cb_data.env)->GetMethodID(cls_OCRepresentation, "<init>", "(JZ)V");
  assert(mid_OCRepresentation_init);
  (oc_con_write_cb_data.env)->CallVoidMethod(oc_con_write_cb_data.obj, mid_handler, (jlong)device_index,
                                            (oc_con_write_cb_data.env)->NewObject(cls_OCRepresentation, mid_OCRepresentation_init, (jlong)rep, false));
}

/* from oc_rep.h */
void rep_start_root_object() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  oc_rep_start_root_object();
}

void rep_end_root_object() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  oc_rep_end_root_object();
}

int jni_get_rep_error() {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  return g_err;
}

void jni_rep_set_double(const char* key, double value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
  g_err |= cbor_encode_double(&root_map, value); 
}

void jni_rep_set_int(const char* key, int value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
  g_err |= cbor_encode_int(&root_map, value);
}

void jni_rep_set_uint(const char* key, unsigned int value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
  g_err |= cbor_encode_uint(&root_map, value);
}

void jni_rep_set_boolean(const char* key, bool value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
  g_err |= cbor_encode_boolean(&root_map, value);
}

void jni_rep_set_text_string(const char* key, const char* value) {
  OC_DBG("JNI: %s\n", __FUNCTION__);
  g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
  g_err |= cbor_encode_text_string(&root_map, value, strlen(value));
}

%}

%typemap(jni)    oc_init_platform_cb_t init_platform_cb "jobject";
%typemap(jtype)  oc_init_platform_cb_t init_platform_cb "OCInitPlatformHandler";
%typemap(jstype) oc_init_platform_cb_t init_platform_cb "OCInitPlatformHandler";
%typemap(javain) oc_init_platform_cb_t init_platform_cb "$javainput";

%typemap(in,numinputs=1) (oc_init_platform_cb_t init_platform_cb, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->env = jenv;
  user_data->obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_init_platform_callback;
  $2 = user_data;
}

%typemap(jni)    oc_add_device_cb_t add_device_cb "jobject";
%typemap(jtype)  oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(jstype) oc_add_device_cb_t add_device_cb "OCAddDeviceHandler";
%typemap(javain) oc_add_device_cb_t add_device_cb "$javainput";
%typemap(in,numinputs=1) (oc_add_device_cb_t add_device_cb, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->env = jenv;
  user_data->obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_add_device_callback;
  $2 = user_data;
}

%typemap(jni)    const oc_handler_t *handler "jobject";
%typemap(jtype)  const oc_handler_t *handler "OCMainInitHandler";
%typemap(jstype) const oc_handler_t *handler "OCMainInitHandler";
%typemap(javain) const oc_handler_t *handler "$javainput";
%typemap(in)     const oc_handler_t *handler {
  JCALL1(GetJavaVM, jenv, &jvm);
  init_obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  $1 = &jni_handler;

  const jclass callback_interface = jenv->FindClass("org/iotivity/OCMainInitHandler");
  assert(callback_interface);
  cls_OCMainInitHandler = static_cast<jclass>(jenv->NewGlobalRef(callback_interface));
}

%typemap(jni)    oc_request_callback_t callback "jobject";
%typemap(jtype)  oc_request_callback_t callback "OCRequestHandler";
%typemap(jstype) oc_request_callback_t callback "OCRequestHandler";
%typemap(javain) oc_request_callback_t callback "$javainput";
%typemap(in,numinputs=1) (oc_request_callback_t callback, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->env = jenv;
  user_data->obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_request_callback;
  $2 = user_data;
}

%typemap(jni)    oc_discovery_handler_t handler "jobject";
%typemap(jtype)  oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(jstype) oc_discovery_handler_t handler "OCDiscoveryHandler";
%typemap(javain) oc_discovery_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_discovery_handler_t handler, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->env = jenv;
  user_data->obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_discovery_handler_callback;
  $2 = user_data;
}

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

%typemap(jni)    oc_response_handler_t handler "jobject";
%typemap(jtype)  oc_response_handler_t handler "OCResponseHandler";
%typemap(jstype) oc_response_handler_t handler "OCResponseHandler";
%typemap(javain) oc_response_handler_t handler "$javainput";
%typemap(in,numinputs=1) (oc_response_handler_t handler, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->env = jenv;
  user_data->obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_response_handler;
  $2 = user_data;
}

%typemap(jni)    oc_trigger_t callback "jobject";
%typemap(jtype)  oc_trigger_t callback "OCTriggerHandler";
%typemap(jstype) oc_trigger_t callback "OCTriggerHandler";
%typemap(javain) oc_trigger_t callback "$javainput";
%typemap(in,numinputs=1) (oc_trigger_t callback, jni_callback_data *jcb) {
  struct jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  user_data->env = jenv;
  user_data->obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  jni_callbacks_vector.push_back(user_data);
  $1 = jni_oc_trigger_handler;
  $2 = user_data;
}

%typemap(jtype)  jobject callback "OCTriggerHandler";
%typemap(jstype) jobject callback "OCTriggerHandler";

%typemap(jni)    oc_con_write_cb_t callback "jobject";
%typemap(jtype)  oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(jstype) oc_con_write_cb_t callback "OCConWriteHandler";
%typemap(javain) oc_con_write_cb_t callback "$javainput";
%typemap(in,numinputs=1) (oc_con_write_cb_t callback) {
  if(!JCALL2(IsSameObject, jenv, oc_con_write_cb_data.obj, NULL)) {
    //Delete the old callback obj if this method is called multiple times
    JCALL1(DeleteGlobalRef, jenv, oc_con_write_cb_data.obj);
  }
  oc_con_write_cb_data.env = jenv;
  oc_con_write_cb_data.obj = JCALL1(NewGlobalRef, jenv, $input);
  JCALL1(DeleteLocalRef, jenv, $input);
  if(JCALL2(IsSameObject, jenv, $input, NULL))
  {
    $1 = NULL;
  } else {
    $1 = jni_oc_con_callback;
  }
}

%ignore oc_handler_t;
%rename(mainInit) oc_main_init;
%rename(mainPoll) oc_main_poll;
%rename(mainShutdown) oc_main_shutdown;
%ignore oc_add_device;
%rename(addDevice) jni_oc_add_device0;
int jni_oc_add_device0(const char *uri, const char *rt, const char *name,
                       const char *spec_version, const char *data_model_version);
%rename(addDevice) jni_oc_add_device1;
int jni_oc_add_device1(const char *uri, const char *rt, const char *name,
                  const char *spec_version, const char *data_model_version,
                  oc_add_device_cb_t add_device_cb, jni_callback_data *jcb,
                  void *user_data);
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
%ignore oc_resource_set_request_handler;
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler0;
void jni_oc_resource_set_request_handler0(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb);
%rename(resourceSetRequestHandler) jni_oc_resource_set_request_handler;
void jni_oc_resource_set_request_handler(oc_resource_t *resource,
                                          oc_method_t method,
                                          oc_request_callback_t callback, jni_callback_data *jcb,
                                          void *user_data);
%rename(addResource) oc_add_resource;
%rename(deleteResource) oc_delete_resource;
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
%ignore oc_do_ip_discovery;
%rename(doIPDiscovery) jni_oc_do_ip_discovery0;
bool jni_oc_do_ip_discovery0(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb);
%rename(doIPDiscovery) jni_oc_do_ip_discovery;
bool jni_oc_do_ip_discovery(const char *rt, oc_discovery_handler_t handler, jni_callback_data *jcb, void *user_data);
%ignore oc_do_ip_discovery_at_endpoint;
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint0;
bool jni_oc_do_ip_discovery_at_endpoint0(const char *rt,
                                         oc_discovery_handler_t handler, jni_callback_data *jcb,
                                         oc_endpoint_t *endpoint);
%rename(doIPDiscoveryAtEndpoint) jni_oc_do_ip_discovery_at_endpoint;
bool jni_oc_do_ip_discovery_at_endpoint(const char *rt, 
                                        oc_discovery_handler_t handler, jni_callback_data *jcb,
                                        oc_endpoint_t *endpoint, void *user_data);
%ignore oc_do_get;
%rename(doGet) jni_oc_do_get0;
bool jni_oc_do_get0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, jni_callback_data *jcb,
                   oc_qos_t qos);
%rename(doGet) jni_oc_do_get;
bool jni_oc_do_get(const char *uri, oc_endpoint_t *endpoint, const char *query,
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
%rename(initPut) jni_oc_init_put;
bool jni_oc_init_put(const char *uri, oc_endpoint_t *endpoint, const char *query,
                     oc_response_handler_t handler, jni_callback_data *jcb,
                     oc_qos_t qos, void *user_data);
%rename(doPut) oc_do_put;
%ignore oc_init_post;
%rename(initPost) jni_oc_init_post0;
bool jni_oc_init_post0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos);
%rename(initPost) jni_oc_init_post;
bool jni_oc_init_post(const char *uri, oc_endpoint_t *endpoint, const char *query,
                      oc_response_handler_t handler, jni_callback_data *jcb,
                      oc_qos_t qos, void *user_data);
%rename(doPost) oc_do_post;
%ignore oc_do_observe;
%rename(doObserve) jni_oc_do_observe0;
bool jni_oc_do_observe0(const char *uri, oc_endpoint_t *endpoint, const char *query,
                       oc_response_handler_t handler, jni_callback_data *jcb,
                       oc_qos_t qos);
%rename(doObserve) jni_oc_do_observe;
bool jni_oc_do_observe(const char *uri, oc_endpoint_t *endpoint, const char *query,
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
%ignore oc_set_delayed_callback;
%rename(setDelayedHandler) jni_oc_set_delayed_callback0;
void jni_oc_set_delayed_callback0(oc_trigger_t callback, jni_callback_data *jcb,
                                  uint16_t seconds);
%rename(setDelayedHandler) jni_oc_set_delayed_callback;
void jni_oc_set_delayed_callback(void *user_data, oc_trigger_t callback, jni_callback_data *jcb,
                                 uint16_t seconds);
%ignore oc_remove_delayed_callback;
%rename(removeDelayedHandler) jni_oc_remove_delayed_callback;
void jni_oc_remove_delayed_callback(jobject callback);
%include "oc_api.h"

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
%ignore oc_rep_get_cbor_errno;
%ignore oc_rep_set_pool;
%ignore oc_parse_rep;
%ignore oc_free_rep;
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
%include "oc_rep.h"

%rename(OCEndpoint) oc_endpoint_t;
// transport flags are pulled from hand generated class as `int` not `enum`
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
// TODO figure out why this apply is not working.
// %apply oc_string_t *OUTPUT { oc_string_t *endpoint_str };
%rename(endpointToString) oc_endpoint_to_string;
%rename(stringToEndpoint) oc_string_to_endpoint;
%rename(ipv6EndpointIsLinkLocal) oc_ipv6_endpoint_is_link_local;
%rename(endpointCompare) oc_endpoint_compare;
%rename(endpointCompareAddress) oc_endpoint_compare_address;
%include "oc_endpoint.h"

%rename(OCQos) oc_qos_t;
%rename(OCClientResponse) oc_client_response_t;
%rename(OCDiscoveryFlags) oc_discovery_flags_t;
%ignore oc_client_handler_s;
%ignore oc_client_handler_t;
%ignore oc_response_handler_t;
%ignore oc_discovery_handler_t;
%rename (OCClientCallback) oc_client_cb_s;
%ignore handler;
%ignore oc_ri_process_discovery_payload;
%include "oc_client_state.h"

%rename(repStartRootObject) rep_start_root_object;
void rep_start_root_object();

%rename(repEndRootObject) rep_end_root_object;
void rep_end_root_object();

%rename (getRepError) jni_get_rep_error;
int jni_get_rep_error();

%rename (repSetInt) jni_rep_set_int;
void jni_rep_set_int(const char* key, int value);

%rename (repSetBoolean) jni_rep_set_boolean;
void jni_rep_set_boolean(const char* key, bool value);

%rename (repSetTextString) jni_rep_set_text_string;
void jni_rep_set_text_string(const char* key, const char* value);

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

%rename(handleCollectionRequest) oc_handle_collection_request;
%rename(newCollection) oc_collection_alloc;
%rename(getCollectionByUri) oc_get_collection_by_uri;
%rename(collectionGetAll) oc_collection_get_all;
%rename(getLinkByUri) oc_get_link_by_uri;
%rename(checkIfCollection) oc_check_if_collection;
%rename(collectionAdd) oc_collection_add;
%include "oc_collection.h"
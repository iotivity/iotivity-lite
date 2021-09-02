/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_IOTIVITY_LITE_H
#define OC_IOTIVITY_LITE_H

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <pthread.h>
#else
#error "Unsupported OS"
#endif
#include "oc_client_state.h"
#include "util/oc_list.h"
#include <jni.h>

#if defined(_WIN32)
HANDLE jni_poll_event_thread;
CRITICAL_SECTION jni_sync_lock;
CONDITION_VARIABLE jni_cv;
CRITICAL_SECTION jni_cs;

int jni_quit;

/* OS specific definition for lock/unlock */
#define jni_mutex_lock(m) EnterCriticalSection(&m)
#define jni_mutex_unlock(m) LeaveCriticalSection(&m)

#elif defined(__linux__)
pthread_t jni_poll_event_thread __attribute__((unused));
pthread_mutex_t jni_sync_lock __attribute__((unused));
pthread_mutexattr_t jni_sync_lock_attr __attribute__((unused));
pthread_cond_t jni_cv __attribute__((unused));
pthread_mutex_t jni_cs __attribute__((unused));

int jni_quit __attribute__((unused));

/* OS specific definition for lock/unlock */
#define jni_mutex_lock(m) pthread_mutex_lock(&m)
#define jni_mutex_unlock(m) pthread_mutex_unlock(&m)
#endif

typedef enum {
  OC_CALLBACK_VALID_UNKNOWN,
  OC_CALLBACK_VALID_FOR_A_SINGLE_CALL,
  OC_CALLBACK_VALID_TILL_SHUTDOWN,
  OC_CALLBACK_VALID_TILL_SET_FACTORY_PRESETS_CB,
  OC_CALLBACK_VALID_TILL_SET_RANDOM_PIN_CB,
  OC_CALLBACK_VALID_TILL_SET_CON_WRITE_CB,
  OC_CALLBACK_VALID_TILL_DELETE_RESOURCE,
  OC_CALLBACK_VALID_TILL_REMOVE_DELAYED_CALLBACK,
  OC_CALLBACK_VALID_TILL_CLOUD_MANAGER_STOP,
  OC_CALLBACK_VALID_TILL_REMOVE_OWNERSHIP_STATUS
} jni_callback_valid_t;

/*
 * JNI function calls require different calling conventions for C and C++. These
 * JCALL macros are used so that the same typemaps can be used for generating
 * code for both C and C++. These macros are originally from the SWIG
 * javahead.swg. They placed here because the SWIG preprocessor does not expand
 * macros that are within the SWIG header code insertion blocks.
 */
#ifdef __cplusplus
#define JCALL0(func, jenv) jenv->func()
#define JCALL1(func, jenv, ar1) jenv->func(ar1)
#define JCALL2(func, jenv, ar1, ar2) jenv->func(ar1, ar2)
#define JCALL3(func, jenv, ar1, ar2, ar3) jenv->func(ar1, ar2, ar3)
#define JCALL4(func, jenv, ar1, ar2, ar3, ar4) jenv->func(ar1, ar2, ar3, ar4)
#define JCALL5(func, jenv, ar1, ar2, ar3, ar4, ar5)                            \
  jenv->func(ar1, ar2, ar3, ar4, ar5)
#define JCALL6(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6)                       \
  jenv->func(ar1, ar2, ar3, ar4, ar5, ar6)
#define JCALL7(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7)                  \
  jenv->func(ar1, ar2, ar3, ar4, ar5, ar6, ar7)
#define JCALL8(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8)             \
  jenv->func(ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8)
#define JCALL9(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9)        \
  jenv->func(ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9)
#else
#define JCALL0(func, jenv) (*jenv)->func(jenv)
#define JCALL1(func, jenv, ar1) (*jenv)->func(jenv, ar1)
#define JCALL2(func, jenv, ar1, ar2) (*jenv)->func(jenv, ar1, ar2)
#define JCALL3(func, jenv, ar1, ar2, ar3) (*jenv)->func(jenv, ar1, ar2, ar3)
#define JCALL4(func, jenv, ar1, ar2, ar3, ar4)                                 \
  (*jenv)->func(jenv, ar1, ar2, ar3, ar4)
#define JCALL5(func, jenv, ar1, ar2, ar3, ar4, ar5)                            \
  (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5)
#define JCALL6(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6)                       \
  (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6)
#define JCALL7(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7)                  \
  (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7)
#define JCALL8(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8)             \
  (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8)
#define JCALL9(func, jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9)        \
  (*jenv)->func(jenv, ar1, ar2, ar3, ar4, ar5, ar6, ar7, ar8, ar9)
#endif

/*
 * org/iotivity classes are pre-loaded as part of the JNI_OnLoad event.
 *
 * This is important for any code originating from the native code. If that
 * code is not running in a thread started by the JavaVM then the jni code
 * can not obtain a pointer to JavaVM or the JNIEnv. It can be really hard to
 * find bugs that result from a thread not being started by the JavaVM.
 * For this reason we pre-load most Java classes that are called from the jni
 * code.
 */
jclass cls_ArrayList;
jclass cls_OCMainInitHandler;
jclass cls_OCAddDeviceHandler;
jclass cls_OCClientResponse;
jclass cls_OCCloudContext;
jclass cls_OCConWriteHandler;
jclass cls_OCDiscoveryHandler;
jclass cls_OCDiscoveryAllHandler;
jclass cls_OCFactoryPresetsHandler;
jclass cls_OCGetPropertiesHandler;
jclass cls_OCInitPlatformHandler;
jclass cls_OCOwnershipStatusHandler;
jclass cls_OCQueryValue;
jclass cls_OCRandomPinHandler;
jclass cls_OCRepresentation;
jclass cls_OCRequest;
jclass cls_OCRequestHandler;
jclass cls_OCResponseHandler;
jclass cls_OCResource;
jclass cls_OCSetPropertiesHandler;
jclass cls_OCSoftwareUpdateHandler;
jclass cls_OCTriggerHandler;

jclass cls_OCCoreAddDeviceHandler;
jclass cls_OCCoreInitPlatformHandler;
jclass cls_OCCreds;
jclass cls_OCEndpoint;
jclass cls_OCUuid;
jclass cls_OCObtAclHandler;
jclass cls_OCObtCredsHandler;
jclass cls_OCObtDiscoveryHandler;
jclass cls_OCObtDeviceStatusHandler;
jclass cls_OCObtStatusHandler;
jclass cls_OCCloudHandler;
jclass cls_OCSecurityAcl;

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
typedef struct jni_callback_data_s
{
  struct jni_callback_data_s *next;
  JNIEnv *jenv;
  jobject jcb_obj;
  jni_callback_valid_t cb_valid;
} jni_callback_data;

jni_callback_data *jni_list_get_head();
void jni_list_add(jni_callback_data *item);
void jni_list_remove(jni_callback_data *item);
void jni_list_clear();
jni_callback_data *jni_list_get_item_by_java_callback(jobject callback);
jni_callback_data *jni_list_get_item_by_callback_valid(
  jni_callback_valid_t cb_valid);

JavaVM *get_jvm();

JNIEnv *get_jni_env(jint *getEnvResult);

void release_jni_env(jint getEnvResult);

/*
 * oc_discovery_all_handler responsible for calling the java
 * OCDiscoveryAllHandler
 */
oc_discovery_flags_t jni_oc_discovery_all_handler_callback(
  const char *anchor, const char *uri, oc_string_array_t types,
  oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
  oc_resource_properties_t bm, bool more, void *user_data);

#endif /* OC_IOTIVITY_LITE_H */

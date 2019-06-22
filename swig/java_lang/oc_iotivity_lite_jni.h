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
#include "util/oc_list.h"
#include <jni.h>

#if defined (_WIN32)
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
  OC_SINGLE_CALL,
  OC_START_CLOUD_MANAGER
} jni_callback_id_t;

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
typedef struct jni_callback_data_s {
  struct jni_callback_data_s *next;
  JNIEnv *jenv;
  jobject jcb_obj;
  jni_callback_id_t cb_id;
} jni_callback_data;

/*
 * Container used to hold all `jni_callback_data` that is
 * allocated dynamically. This can be used to find the
 * memory allocated for the `jni_callback_data` if the callback
 * is removed or unregistered. This can all so be used to clean
 * up the allocated memory when shutting down the stack.
 */
OC_LIST(jni_callbacks);

static void jni_list_add(oc_list_t list, void *item) {
    OC_DBG("JNI: - lock %s\n", __func__);
    jni_mutex_lock(jni_sync_lock);
    oc_list_add(list, item);
    jni_mutex_unlock(jni_sync_lock);
    OC_DBG("JNI: - unlock %s\n", __func__);
}

#define JNI_CURRENT_VERSION JNI_VERSION_1_6

static JavaVM *jvm;

static JNIEnv* GetJNIEnv(jint* getEnvResult)
{
    JNIEnv *env = NULL;
    *getEnvResult = JCALL2(GetEnv, jvm, (void**)&env, JNI_CURRENT_VERSION);
    switch (*getEnvResult)
    {
        case JNI_OK:
            return env;
        case JNI_EDETACHED:
#    ifdef __ANDROID__
            if(JCALL2(AttachCurrentThread, jvm, &env, NULL) < 0)
#    else
            if(JCALL2(AttachCurrentThread, jvm, (void**)&env, NULL) < 0)
#    endif
            {
                OC_DBG("Failed to get the environment");
                return NULL;
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
            return NULL;
    }
    return NULL;
}

static void ReleaseJNIEnv(jint getEnvResult) {
    if (JNI_EDETACHED == getEnvResult) {
        JCALL0(DetachCurrentThread, jvm);
    }
}

#endif /* OC_IOTIVITY_LITE_H */

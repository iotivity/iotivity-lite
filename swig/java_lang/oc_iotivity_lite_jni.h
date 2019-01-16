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
} jni_callback_data;

/*
 * Container used to hold all `jni_callback_data` that is
 * allocated dynamically. This can be used to find the
 * memory allocated for the `jni_callback_data` if the callback
 * is removed or unregistered. This can all so be used to clean
 * up the allocated memory when shutting down the stack.
 */
OC_LIST(jni_callbacks);

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
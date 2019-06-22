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

#include "oc_iotivity_lite_jni.h"
#include "port/oc_log.h"
#include "port/oc_storage.h"
#include <assert.h>
#include <stdlib.h>

#define JNI_CURRENT_VERSION JNI_VERSION_1_6

static JavaVM *jvm;

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
    OC_DBG("JNI: %s\n", __func__);
    OC_DBG("JNI: %s - Setting global JavaVM variable", __func__);
    jvm = vm;

    JNIEnv *jenv = NULL;
    jint getEnvResult = 0;
    jenv = get_jni_env(&getEnvResult);

    assert(jenv);
    if (jenv == NULL) {
        return -1;
    }

    // initialize jni_sync_lock
#if defined(_WIN32)
    InitializeCriticalSection(&jni_cs);
    InitializeConditionVariable(&jni_cv);
    InitializeCriticalSection(&jni_sync_lock);
#elif defined(__linux__)
    pthread_mutexattr_init(&jni_sync_lock_attr);
    pthread_mutexattr_settype(
      &jni_sync_lock_attr,
      PTHREAD_MUTEX_ERRORCHECK); // was PTHREAD_MUTEX_RECURSIVE
    pthread_mutex_init(&jni_sync_lock, &jni_sync_lock_attr);
#endif

    jclass ocAddDeviceHandlerClass =
      JCALL1(FindClass, jenv, "org/iotivity/OCAddDeviceHandler");
    assert(ocAddDeviceHandlerClass);
    cls_OCAddDeviceHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocAddDeviceHandlerClass));
    JCALL1(DeleteLocalRef, jenv, ocAddDeviceHandlerClass);

    jclass ocClientResponseClass = JCALL1(FindClass, jenv, "org/iotivity/OCClientResponse");
    assert(ocClientResponseClass);
    cls_OCClientResponse = (jclass)(JCALL1(NewGlobalRef, jenv, ocClientResponseClass));
    JCALL1(DeleteLocalRef, jenv, ocClientResponseClass);

    jclass ocCloudContextClass =
      JCALL1(FindClass, jenv, "org/iotivity/OCCloudContext");
    assert(ocCloudContextClass);
    cls_OCCloudContext = (jclass)(JCALL1(NewGlobalRef, jenv, ocCloudContextClass));
    JCALL1(DeleteLocalRef, jenv, ocCloudContextClass);

    jclass ocCoreAddDeviceHandlerClass =
      JCALL1(FindClass, jenv, "org/iotivity/OCCoreAddDeviceHandler");
    assert(ocCoreAddDeviceHandlerClass);
    cls_OCCoreAddDeviceHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocCoreAddDeviceHandlerClass));
    JCALL1(DeleteLocalRef, jenv, ocCoreAddDeviceHandlerClass);

    jclass ocCoreInitPlatformHandlerClass = JCALL1(FindClass, jenv, "org/iotivity/OCCoreInitPlatformHandler");
    assert(ocCoreInitPlatformHandlerClass);
    cls_OCCoreInitPlatformHandler = (jclass)(JCALL1(NewGlobalRef, jenv, ocCoreInitPlatformHandlerClass));
    JCALL1(DeleteLocalRef, jenv, ocCoreInitPlatformHandlerClass);

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

    jclass ocObtDeviceStatusHandlerClass =
      JCALL1(FindClass, jenv, "org/iotivity/OCObtDeviceStatusHandler");
    assert(ocObtDeviceStatusHandlerClass);
    cls_OCObtDeviceStatusHandler =
      (jclass)(JCALL1(NewGlobalRef, jenv, ocObtDeviceStatusHandlerClass));
    JCALL1(DeleteLocalRef, jenv, ocObtDeviceStatusHandlerClass);

    jclass ocObtStatusHandlerClass =
      JCALL1(FindClass, jenv, "org/iotivity/OCObtStatusHandler");
    assert(ocObtStatusHandlerClass);
    cls_OCObtStatusHandler =
      (jclass)(JCALL1(NewGlobalRef, jenv, ocObtStatusHandlerClass));
    JCALL1(DeleteLocalRef, jenv, ocObtStatusHandlerClass);

    jclass ocCloudHandlerClass =
      JCALL1(FindClass, jenv, "org/iotivity/OCCloudHandler");
    assert(ocCloudHandlerClass);
    cls_OCCloudHandler =
      (jclass)(JCALL1(NewGlobalRef, jenv, ocCloudHandlerClass));
    JCALL1(DeleteLocalRef, jenv, ocCloudHandlerClass);

    jclass utilArrayListClass = JCALL1(FindClass, jenv, "java/util/ArrayList");
    assert(utilArrayListClass);
    cls_ArrayList = (jclass)(JCALL1(NewGlobalRef, jenv, utilArrayListClass));
    JCALL1(DeleteLocalRef, jenv, utilArrayListClass);

#ifdef __ANDROID__
    // Get the Android Context
    const jclass activityThreadClass =
      JCALL1(FindClass, jenv, "android/app/ActivityThread");
    const jmethodID currentActivityThreadMethod =
      JCALL3(GetStaticMethodID, jenv, activityThreadClass,
             "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject activityThread =
      JCALL2(CallStaticObjectMethod, jenv, activityThreadClass,
             currentActivityThreadMethod);

    const jmethodID getApplicationMethod =
      JCALL3(GetMethodID, jenv, activityThreadClass, "getApplication",
             "()Landroid/app/Application;");
    jobject context =
      JCALL2(CallObjectMethod, jenv, activityThread, getApplicationMethod);
    JCALL1(DeleteLocalRef, jenv, activityThreadClass);
    JCALL1(DeleteLocalRef, jenv, activityThread);

    // Get the FilesDir
    const jclass activityClass =
      JCALL1(FindClass, jenv, "android/app/Activity");
    const jmethodID getFileDirsMethod = JCALL3(
      GetMethodID, jenv, activityClass, "getFilesDir", "()Ljava/io/File;");
    jobject filesDir =
      JCALL2(CallObjectMethod, jenv, context, getFileDirsMethod);
    JCALL1(DeleteLocalRef, jenv, activityClass);
    JCALL1(DeleteLocalRef, jenv, context);

    // Create a file object for the credentials directory
    const jclass fileClass = JCALL1(FindClass, jenv, "java/io/File");
    const jmethodID fileCtorMethod =
      JCALL3(GetMethodID, jenv, fileClass, "<init>",
             "(Ljava/io/File;Ljava/lang/String;)V");
    jstring credentials = JCALL1(NewStringUTF, jenv, "credentials");
    jobject credsDir =
      JCALL4(NewObject, jenv, fileClass, fileCtorMethod, filesDir, credentials);
    JCALL1(DeleteLocalRef, jenv, filesDir);
    JCALL1(DeleteLocalRef, jenv, credentials);

    // Test if the credentials directory already exists
    const jmethodID fileExistsMethod =
      JCALL3(GetMethodID, jenv, fileClass, "exists", "()Z");
    jboolean exists =
      JCALL2(CallBooleanMethod, jenv, credsDir, fileExistsMethod);

    if (!exists) {
      // Create credentials directory
      const jmethodID mkdirMethod =
        JCALL3(GetMethodID, jenv, fileClass, "mkdir", "()Z");
      jboolean mkDirCreated =
        JCALL2(CallBooleanMethod, jenv, credsDir, mkdirMethod);
      if (!mkDirCreated) {
        OC_DBG("Failed to create credentials directory");
        return -1;
      }
    }

    // Get the credentials directory absolute path as a C string
    const jmethodID getAbsPathMethod = JCALL3(
            GetMethodID, jenv, fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jstring credsDirPath =
            JCALL2(CallObjectMethod, jenv, credsDir, getAbsPathMethod);
    const char *path = JCALL2(GetStringUTFChars, jenv, credsDirPath, 0);
    OC_DBG("JNI: %s, %s\n", __func__, path);
    JCALL1(DeleteLocalRef, jenv, fileClass);
    JCALL1(DeleteLocalRef, jenv, credsDir);

    // Initialize credential storage
#ifdef OC_SECURITY
    OC_DBG("JNI: %s with path %s\n", __func__, path);
    oc_storage_config(path);
#else
    OC_DBG(
            "JNI: OC_SECURITY disabled ignore call to oc_storage_config with path %s\n",
            path);
#endif /* OC_SECURITY */

    // Cleanup
    JCALL2(ReleaseStringUTFChars, jenv, credsDirPath, path);
    JCALL1(DeleteLocalRef, jenv, credsDirPath);
#endif

    release_jni_env(getEnvResult);

    return JNI_CURRENT_VERSION;
}

JavaVM *
get_jvm()
{
    return jvm;
}

/*
 * Container used to hold all `jni_callback_data` that is
 * allocated dynamically. This can be used to find the
 * memory allocated for the `jni_callback_data` if the callback
 * is removed or unregistered. This can all so be used to clean
 * up the allocated memory when shutting down the stack.
 */
OC_LIST(jni_callbacks);

jni_callback_data *
jni_list_get_head()
{
    return (jni_callback_data *)oc_list_head(jni_callbacks);
}

void
jni_list_add(jni_callback_data *item)
{
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_list_add(jni_callbacks, item);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
}

void
jni_list_remove(jni_callback_data *item)
{
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  if (item) {
    JCALL1(DeleteGlobalRef, item->jenv, item->jcb_obj);
    oc_list_remove(jni_callbacks, item);
    free(item);
    item = NULL;
  }
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
}

jni_callback_data *
jni_list_get_item_by_java_callback(jobject callback)
{
    OC_DBG("JNI: - lock %s\n", __func__);
    jni_mutex_lock(jni_sync_lock);
    jni_callback_data *item = jni_list_get_head();
    while (item) {
        if (JCALL2(IsSameObject, (item->jenv), callback, item->jcb_obj)) {
            break;
        }
        item = (jni_callback_data *)oc_list_item_next(item);
    }
    jni_mutex_unlock(jni_sync_lock);
    OC_DBG("JNI: - unlock %s\n", __func__);
    return item;
}

jni_callback_data *
jni_list_get_item_by_callback_valid(jni_callback_valid_t cb_valid)
{
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  OC_DBG("JNI: 0\n");
  jni_callback_data *item = jni_list_get_head();
  OC_DBG("JNI: 1 - %p\n", item);
  while (item) {
    OC_DBG("JNI: 2 - %p\n", item);
    if ((item->cb_valid) == cb_valid) {
      OC_DBG("JNI: 3 - %p\n", item);
      break;
    }
    item = (jni_callback_data *)oc_list_item_next(item);
  }
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
  OC_DBG("JNI: 4 - %p\n", item);
  return item;
}

JNIEnv *
get_jni_env(jint *getEnvResult)
{
    JNIEnv *env = NULL;
    *getEnvResult = JCALL2(GetEnv, jvm, (void **)&env, JNI_CURRENT_VERSION);
    switch (*getEnvResult) {
    case JNI_OK:
        return env;
    case JNI_EDETACHED:
#ifdef __ANDROID__
        if (JCALL2(AttachCurrentThread, jvm, &env, NULL) < 0)
#else
            if (JCALL2(AttachCurrentThread, jvm, (void **)&env, NULL) < 0)
#endif
            {
                OC_DBG("Failed to get the environment");
                return NULL;
            } else {
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

void
release_jni_env(jint getEnvResult)
{
    if (JNI_EDETACHED == getEnvResult) {
        JCALL0(DetachCurrentThread, jvm);
    }
}

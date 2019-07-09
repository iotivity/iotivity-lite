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

#define JNI_CURRENT_VERSION JNI_VERSION_1_6

static JavaVM *jvm;

#include "oc_iotivity_lite_jni.h"

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
  OC_DBG("JNI: %s - Setting global JavaVM variable", __func__);
  jvm = vm;
#ifdef __ANDROID__
  OC_DBG("JNI: %s\n", __func__);
  JNIEnv *jenv = NULL;
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);

  assert(jenv);
  if (jenv == NULL) {
    return -1;
  }

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
  const jclass activityClass = JCALL1(FindClass, jenv, "android/app/Activity");
  const jmethodID getFileDirsMethod =
    JCALL3(GetMethodID, jenv, activityClass, "getFilesDir", "()Ljava/io/File;");
  jobject filesDir = JCALL2(CallObjectMethod, jenv, context, getFileDirsMethod);
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
  jboolean exists = JCALL2(CallBooleanMethod, jenv, credsDir, fileExistsMethod);

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
  jni_storage_config(path);

  // Cleanup
  JCALL2(ReleaseStringUTFChars, jenv, credsDirPath, path);
  JCALL1(DeleteLocalRef, jenv, credsDirPath);

  release_jni_env(getEnvResult);
#endif

  return JNI_CURRENT_VERSION;
}

JavaVM *
get_jvm()
{
  return jvm;
}

void
jni_list_add(oc_list_t list, void *item)
{
  OC_DBG("JNI: - lock %s\n", __func__);
  jni_mutex_lock(jni_sync_lock);
  oc_list_add(list, item);
  jni_mutex_unlock(jni_sync_lock);
  OC_DBG("JNI: - unlock %s\n", __func__);
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

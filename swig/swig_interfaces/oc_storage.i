/* File oc_storage.i */
%module OCStorage
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
#include "port/oc_storage.h"
#include "port/oc_log.h"
#include <assert.h>

#ifdef __ANDROID__

#include "oc_iotivity_lite_jni.h"

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved)
{
    OC_DBG("JNI: %s\n", __func__);
    JNIEnv *jenv = NULL;
    jint getEnvResult = JCALL2(GetEnv, vm, (void**)&jenv, JNI_CURRENT_VERSION);
    OC_DBG("JNI: %s, %d, %p\n", __func__, getEnvResult, jenv);

    if (getEnvResult == JNI_EDETACHED)
    {
#ifdef __ANDROID__
        if(JCALL2(AttachCurrentThread, vm, &jenv, NULL) < 0)
#else
        if(JCALL2(AttachCurrentThread, vm, (void**)&jenv, NULL) < 0)
#endif
        {
            OC_DBG("Failed to get the environment");
            return -1;
        }
    }

    assert(jenv);

    // Get the Android Context
    const jclass activityThreadClass = JCALL1(FindClass, jenv, "android/app/ActivityThread");
    const jmethodID currentActivityThreadMethod = JCALL3(GetStaticMethodID, jenv, activityThreadClass, "currentActivityThread", "()Landroid/app/ActivityThread;");
    jobject activityThread = JCALL2(CallStaticObjectMethod, jenv, activityThreadClass, currentActivityThreadMethod);

    const jmethodID getApplicationMethod = JCALL3(GetMethodID, jenv, activityThreadClass, "getApplication", "()Landroid/app/Application;");
    jobject context = JCALL2(CallObjectMethod, jenv, activityThread, getApplicationMethod);
    JCALL1(DeleteLocalRef, jenv, activityThreadClass);
    JCALL1(DeleteLocalRef, jenv, activityThread);

    // Get the FilesDir
    const jclass activityClass = JCALL1(FindClass, jenv, "android/app/Activity");
    const jmethodID getFileDirsMethod = JCALL3(GetMethodID, jenv, activityClass, "getFilesDir", "()Ljava/io/File;");
    jobject filesDir = JCALL2(CallObjectMethod, jenv, context, getFileDirsMethod);
    JCALL1(DeleteLocalRef, jenv, activityClass);
    JCALL1(DeleteLocalRef, jenv, context);

    // Create a file object for the credentials directory
    const jclass fileClass = JCALL1(FindClass, jenv, "java/io/File");
    const jmethodID fileCtorMethod = JCALL3(GetMethodID, jenv, fileClass, "<init>", "(Ljava/io/File;Ljava/lang/String;)V");
    jstring credentials = JCALL1(NewStringUTF, jenv, "credentials");
    jobject credsDir = JCALL4(NewObject, jenv, fileClass, fileCtorMethod, filesDir, credentials);
    JCALL1(DeleteLocalRef, jenv, filesDir);
    JCALL1(DeleteLocalRef, jenv, credentials);

    // Test if the credentials directory already exists
    const jmethodID fileExistsMethod = JCALL3(GetMethodID, jenv, fileClass, "exists", "()Z");
    jboolean exists = JCALL2(CallBooleanMethod, jenv, credsDir, fileExistsMethod);

    if (!exists)
    {
        // Create credentials directory
        const jmethodID mkdirMethod = JCALL3(GetMethodID, jenv, fileClass, "mkdir", "()Z");
        jboolean mkDirCreated = JCALL2(CallBooleanMethod, jenv, credsDir, mkdirMethod);
        if (!mkDirCreated)
        {
            OC_DBG("Failed to create credentials directory");
            return -1;
        }
    }

    // Get the credentials directory absolute path as a C string
    const jmethodID getAbsPathMethod = JCALL3(GetMethodID, jenv, fileClass, "getAbsolutePath", "()Ljava/lang/String;");
    jstring credsDirPath = JCALL2(CallObjectMethod, jenv, credsDir, getAbsPathMethod);
    const char *path = JCALL2(GetStringUTFChars, jenv, credsDirPath, 0);
    OC_DBG("JNI: %s, %s\n", __func__, path);
    JCALL1(DeleteLocalRef, jenv, fileClass);
    JCALL1(DeleteLocalRef, jenv, credsDir);

    // Initialize credential storage
    jni_storage_config(path);

    // Cleanup
    JCALL2(ReleaseStringUTFChars, jenv, credsDirPath, path);
    JCALL1(DeleteLocalRef, jenv, credsDirPath);

    if (JNI_EDETACHED == getEnvResult) {
        JCALL0(DetachCurrentThread, vm);
        OC_DBG("JNI: Detach");
    }

    return JNI_VERSION_1_6;
}
#endif

%}

#if defined(SWIGJAVA) 

%typemap(in)     (uint8_t *BYTE, size_t LENGTH) {  
$1 = (uint8_t*) JCALL2(GetByteArrayElements, jenv, $input, 0); 
$2 = (size_t)    JCALL1(GetArrayLength,       jenv, $input); 
} 
%typemap(jni)    (uint8_t *BYTE, size_t LENGTH) "jbyteArray" 
%typemap(jtype)  (uint8_t *BYTE, size_t LENGTH) "byte[]" 
%typemap(jstype) (uint8_t *BYTE, size_t LENGTH) "byte[]" 
%typemap(javain) (uint8_t *BYTE, size_t LENGTH) "$javainput" 

/* Specify signature of method to handle */ 
%apply (uint8_t *BYTE, size_t LENGTH)   { (uint8_t *buf, size_t size) }; 

#else 
%apply (uint8_t *BYTE, size_t LENGTH) { (uint8_t *buf, size_t size) }; 
#endif 

%rename (storageConfig) jni_storage_config;
%inline %{
int jni_storage_config(const char *store) {
#ifdef OC_SECURITY
    OC_DBG("JNI: %s with path %s\n", __func__, store);
    return oc_storage_config(store);
#else
    OC_DBG("JNI: OC_SECURITY disabled ignoring %s with path %s\n", __func__, store);
    return 0;
#endif /* OC_SECURITY */
}
%}
/*
%rename (storageRead) oc_storage_read;
long oc_storage_read(const char *store, uint8_t *buf, size_t size);

%rename (storageWrite) oc_storage_write;
long oc_storage_write(const char *store, uint8_t *buf, size_t size);
*/
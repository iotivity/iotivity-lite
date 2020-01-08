/* File oc_swupdate.i */
%module OCSoftwareUpdate
%include "typemaps.i"
%include "stdint.i"
%include "iotivity.swg"
%include "enums.swg"
%javaconst(1);

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
#include "oc_swupdate.h"
#include "oc_iotivity_lite_jni.h"

static jni_callback_data jni_swupdate_callback_data;
%}

typedef int64_t oc_clock_time_t;

%rename(OCSoftwareUpdateResult) oc_swupdate_result_t;

%ignore oc_swupdate_notify_new_version_available;
%rename(notifyNewVersionAvailable) jni_swupdate_notify_new_version_available;
%inline %{
void jni_swupdate_notify_new_version_available(size_t device,
                                              const char *version,
                                              oc_swupdate_result_t result)
{
#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_notify_new_version_available(device, version, result);
#endif
}
%}

%ignore oc_swupdate_notify_downloaded;
%rename(notifyDownload) jni_swupdate_notify_downloaded;
%inline %{
void jni_swupdate_notify_downloaded(size_t device, const char *version,
                                   oc_swupdate_result_t result)
{
#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_notify_downloaded(device, version, result);
#endif
}
%}

%ignore oc_swupdate_notify_upgrading;
%rename(notifyUpgrading) jni_swupdate_notify_upgrading;
%inline %{
void jni_swupdate_notify_upgrading(size_t device,
                                   const char *version,
                                   oc_clock_time_t timestamp,
                                   oc_swupdate_result_t result)
{
#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_notify_upgrading(device, version, timestamp, result);
#endif
}
%}

%ignore oc_swupdate_notify_done;
%rename(notifyDone) jni_swupdate_notify_done;
%inline %{
void jni_swupdate_notify_done(size_t device, oc_swupdate_result_t result)
{
#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_notify_done(device, result);
#endif
}
%}

%{
int jni_validate_purl(const char *url)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);
  assert(jenv);

  assert(cls_OCSoftwareUpdateHandler);
  const jmethodID mid_validate_purl = JCALL3(GetMethodID,
                                       jenv,
                                       cls_OCSoftwareUpdateHandler,
                                       "validatePURL",
                                       "(Ljava/lang/String;)I");
  assert(mid_validate_purl);
  jstring jurl = JCALL1(NewStringUTF, jenv, (const char *)url);
  jint return_value = JCALL3(CallIntMethod, jenv,
                             jni_swupdate_callback_data.jcb_obj,
                             mid_validate_purl,
                             jurl);

  release_jni_env(getEnvResult);
  return (int) return_value;
}

int jni_check_new_version(size_t device, const char *url, const char *version)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);
  assert(jenv);

  assert(cls_OCSoftwareUpdateHandler);
  const jmethodID mid_check_new_version = JCALL3(GetMethodID,
                                       jenv,
                                       cls_OCSoftwareUpdateHandler,
                                       "checkNewVersion",
                                       "(JLjava/lang/String;Ljava/lang/String;)I");
  assert(mid_check_new_version);
  jstring jurl = JCALL1(NewStringUTF, jenv, url);
  jstring jversion = JCALL1(NewStringUTF, jenv, version);
  jint return_value = JCALL5(CallIntMethod, jenv,
                             jni_swupdate_callback_data.jcb_obj,
                             mid_check_new_version,
                             (jlong) device,
                             jurl,
                             jversion);

  release_jni_env(getEnvResult);
  return (int) return_value;
}

int jni_download_update(size_t device, const char *url)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);
  assert(jenv);

  assert(cls_OCSoftwareUpdateHandler);
  const jmethodID mid_download_update = JCALL3(GetMethodID,
                                       jenv,
                                       cls_OCSoftwareUpdateHandler,
                                       "downloadUpdate",
                                       "(JLjava/lang/String;)I");
  assert(mid_download_update);
  jstring jurl = JCALL1(NewStringUTF, jenv, url);
  jint return_value = JCALL4(CallIntMethod, jenv,
                             jni_swupdate_callback_data.jcb_obj,
                             mid_download_update,
                             (jlong) device,
                             jurl);

  release_jni_env(getEnvResult);
  return (int) return_value;
}

int jni_perform_upgrade(size_t device, const char *url)
{
  OC_DBG("JNI: %s\n", __func__);
  jint getEnvResult = 0;
  JNIEnv *jenv = get_jni_env(&getEnvResult);
  assert(jenv);

  assert(cls_OCSoftwareUpdateHandler);
  const jmethodID mid_perform_upgrade = JCALL3(GetMethodID,
                                       jenv,
                                       cls_OCSoftwareUpdateHandler,
                                       "performUpgrade",
                                       "(JLjava/lang/String;)I");
  assert(mid_perform_upgrade);
  jstring jurl = JCALL1(NewStringUTF, jenv, url);
  jint return_value = JCALL4(CallIntMethod, jenv,
                             jni_swupdate_callback_data.jcb_obj,
                             mid_perform_upgrade,
                             (jlong) device,
                             jurl);

  release_jni_env(getEnvResult);
  return (int) return_value;
}

static oc_swupdate_cb_t jni_swupdate_handler = {
    jni_validate_purl,      // validate persistant url
    jni_check_new_version,  // check new version
    jni_download_update,    // download update
    jni_perform_upgrade     // perform upgrade
    };
%}

%ignore oc_swupdate_cb_t;
%typemap(jni)    const oc_swupdate_cb_t *swupdateImpl "jobject";
%typemap(jtype)  const oc_swupdate_cb_t *swupdateImpl "OCSoftwareUpdateHandler";
%typemap(jstype) const oc_swupdate_cb_t *swupdateImpl "OCSoftwareUpdateHandler";
%typemap(javain) const oc_swupdate_cb_t *swupdateImpl "$javainput";
%typemap(in)     const oc_swupdate_cb_t *swupdateImpl {
  jni_callback_data *user_data = (jni_callback_data *)malloc(sizeof *user_data);
  jni_swupdate_callback_data.jenv = jenv;
  jni_swupdate_callback_data.jcb_obj = JCALL1(NewGlobalRef, jenv, $input);
  jni_swupdate_callback_data.cb_valid = OC_CALLBACK_VALID_TILL_SHUTDOWN;
  $1 = &jni_swupdate_handler;
}

%ignore oc_swupdate_set_impl;
%rename(setImpl) jni_swupdate_set_impl;
%inline %{
void jni_swupdate_set_impl(const oc_swupdate_cb_t *swupdateImpl)
{
#ifdef OC_SOFTWARE_UPDATE
  oc_swupdate_set_impl(swupdateImpl);
#endif
}
%}


%include oc_swupdate.h
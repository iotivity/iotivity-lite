/* File oc_swupdate.i */
%module OCSoftwareUpdate
%include "typemaps.i"
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

%}

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

%ignore oc_swupdate_set_impl;
%rename(setImpl) jni_swupdate_set_impl;
%inline %{
void jni_swupdate_set_impl(const oc_swupdate_cb_t *swupdate_impl)
{
#ifdef OC_SOFTWARE_UPDATE
  jni_swupdate_set_impl(swupdate_impl);
#endif
}
%}


%include oc_swupdate.h
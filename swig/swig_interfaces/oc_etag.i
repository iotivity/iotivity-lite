/* File oc_etag.i */
%module OCTagUtil

%import "oc_ri.i"

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
#include "oc_etag.h"
#include "oc_ri.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"
%}

%ignore oc_resource_update_etag;
%rename(resourceUpdateETag) jni_resource_update_etag;
%inline %{
void jni_resource_update_etag(oc_resource_t *resource) {
  OC_DBG("JNI: %s\n", __func__);
#ifdef OC_HAS_FEATURE_ETAG
  oc_resource_update_etag(resource);
#else /* !OC_HAS_FEATURE_ETAG */
  (void)resource;
#endif /* OC_HAS_FEATURE_ETAG */
}
%}

%ignore oc_etag_dump;
%rename(Dump) jni_etag_dump;
%inline %{
void jni_etag_dump(void) {
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_HAS_FEATURE_ETAG) && defined(OC_STORAGE)
  oc_etag_dump();
#endif /* OC_HAS_FEATURE_ETAG && OC_STORAGE */
}
%}

%ignore oc_etag_load_and_clear;
%rename(LoadAndClear) jni_etag_load_and_clear;
%inline %{
void jni_etag_load_and_clear(void) {
  OC_DBG("JNI: %s\n", __func__);
#if defined(OC_HAS_FEATURE_ETAG) && defined(OC_STORAGE)
  oc_etag_load_and_clear();
#endif /* OC_HAS_FEATURE_ETAG && OC_STORAGE */
}
%}

#define OC_API
#define OC_NONNULL(...)
%include oc_etag.h

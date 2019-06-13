/* file oc_core_res.i */
%module OCSessionEvents

%include "enums.swg"

%import "oc_endpoint.i"

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
#include "oc_log.h"
#include "oc_session_events.h"
%}

%rename (OCSessionState) oc_session_state_t;
%ignore oc_session_event_cb;
%ignore oc_session_events;

%ignore oc_session_start_event;
%rename (startEvent) jni_session_start_event;
%inline %{
void jni_session_start_event(oc_endpoint_t *endpoint)
{
#ifdef OC_TCP
  oc_session_start_event(endpoint);
#else /* OC_TCP */
  OC_DBG("JNI: %s - Must build with OC_TCP defined to use this function.\n", __func__);
#endif /* !OC_TCP */
}
%}

%ignore oc_session_end_event;
%rename (endEvent) jni_session_end_event;
%inline %{
void jni_session_end_event(oc_endpoint_t *endpoint)
{
#ifdef OC_TCP
  oc_session_end_event(endpoint);
#else /* OC_TCP */
  OC_DBG("JNI: %s - Must build with OC_TCP defined to use this function.\n", __func__);
#endif /* !OC_TCP */
}
%}

%ignore oc_session_events_set_event_delay;
%rename (setEventDelay) jni_session_events_set_event_delay;
%inline %{
void jni_session_events_set_event_delay(int secs)
{
#ifdef OC_TCP
  oc_session_events_set_event_delay(secs);
#else /* OC_TCP */
  OC_DBG("JNI: %s - Must build with OC_TCP defined to use this function.\n", __func__);
#endif /* !OC_TCP */
}
%}
%include "oc_session_events.h"
/* file oc_session_events.i */
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
#include "oc_session_events.h"
#include "port/oc_log_internal.h"
%}

%rename (OCSessionState) oc_session_state_t;
%ignore oc_session_event_cb;
%ignore oc_session_events;

%ignore oc_session_events_set_event_delay;
%rename (setEventDelay) jni_session_events_set_event_delay;
%inline %{
void jni_session_events_set_event_delay(int secs)
{
#ifdef OC_TCP
  oc_session_events_set_event_delay(secs);
#else /* OC_TCP */
  OC_DBG("JNI: %s - Must build with OC_TCP defined to use this function.\n", __func__);
  (void)secs;
#endif /* !OC_TCP */
}
%}
#define OC_API
#define OC_DEPRECATED(...)
%include "oc_session_events.h"

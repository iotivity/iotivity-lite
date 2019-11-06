/* File oc_connectivity.i */
%module OCConnectivity
%include "stdint.i"
%include "enums.swg"
%javaconst(1);

%import "oc_endpoint.i"

#define OC_DYNAMIC_ALLOCATION

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
#include "port/oc_connectivity.h"
%}

%ignore oc_message_s;
%ignore oc_send_buffer;
%rename(init) oc_connectivity_init;
%rename(shutdown) oc_connectivity_shutdown;
%ignore oc_send_discovery_request;
%ignore oc_connectivity_end_session;
%ignore oc_dns_lookup;
%ignore oc_connectivity_get_endpoints;
%ignore handle_network_interface_event_callback;
%ignore handle_session_event_callback;
%ignore tcp_csm_state_t;
%ignore oc_tcp_get_csm_state;
%ignore oc_tcp_update_csm_state;

%include "port/oc_connectivity.h"
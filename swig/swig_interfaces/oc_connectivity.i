/* File oc_connectivity.i */
%module OCConnectivity
%include "stdint.i"
%include "enums.swg"
%javaconst(1);

%import "oc_endpoint.i"

%include "oc_config.h"

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

%ignore oc_send_buffer;
%rename(init) oc_connectivity_init;
%rename(shutdown) oc_connectivity_shutdown;
%ignore oc_send_discovery_request;
%rename(endSession) oc_connectivity_end_session;
/* oc_dns_lookup currently not being exposed */
//%apply oc_string_t *OUTPUT { oc_string_t *addr };
//%rename(dnsLookup) oc_dns_lookup;
%ignore oc_dns_lookup;
%rename(getEndpoints) oc_connectivity_get_endpoints;
%ignore handle_network_interface_event_callback;
%ignore handle_session_event_callback;
%rename(TcpCsmState) tcp_csm_state_t;
%rename(tcpGetCsmState) oc_tcp_get_csm_state;
%rename(tcpUpdateCsmState) oc_tcp_update_csm_state;

%include "port/oc_connectivity.h"
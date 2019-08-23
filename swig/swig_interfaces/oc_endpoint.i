/* File oc_endpoint.i */
%module OCEndpointUtil

%include "stdint.i"
%include "arrays_java.i"
%include "iotivity.swg"

%import "oc_uuid.i"

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
#include "oc_endpoint.h"
#include "oc_iotivity_lite_jni.h"
%}

/*******************Begin oc_endpoint.h*********************/
%extend oc_endpoint_t {
  oc_endpoint_t() {
    OC_DBG("JNI: %s\n", __func__);
    return oc_new_endpoint();
  }

  ~oc_endpoint_t() {
   OC_DBG("JNI: %s\n", __func__);
   oc_free_endpoint($self);
   $self = NULL;
  }
}
%rename(OCEndpoint) oc_endpoint_t;
// must use the oc_endpoint_set_di function to set di.
%immutable oc_endpoint_t::di;
// transport flags are pulled from hand generated class as `int` not `enum`
%ignore transport_flags;
//%rename (OCTransportFlags) transport_flags;
%rename(DevAddr) dev_addr;
//if uncommented the following apply lines will cause the output to be byte[] vs short[]
//%apply signed char[ANY] { uint8_t address[4] };
//%apply signed char[ANY] { uint8_t address[16] };
%rename(OCIPv6Addr) oc_ipv6_addr_t;
%rename(OCIPv4Addr) oc_ipv4_addr_t;
%rename(OCLEAddr) oc_le_addr_t;
%rename(addrLocal) addr_local;
%rename(OCFVersion) ocf_version_t;
%rename(interfaceIndex) interface_index;
// look into exposing oc_make_ipv4_endpoint and oc_make_ipv6_endpoint
// new and free endpoint are exposed using the %extend oc_endpoint_t above.
%ignore oc_new_endpoint;
%ignore oc_free_endpoint;
%rename(setDi) oc_endpoint_set_di;
%ignore oc_endpoint_to_string;

%typemap(jni)    jobject toString "jobject";
%typemap(jtype)  jobject toString "String";
%typemap(jstype) jobject toString "String";
%typemap(javain) jobject toString "$javainput";
%pragma(java) jniclassimports="import java.lang.String;"
%native (toString) jobject toString(oc_endpoint_t *endpoint);
%{
#ifdef __cplusplus
extern "C"
#endif
SWIGEXPORT jobject JNICALL Java_org_iotivity_OCEndpointUtilJNI_toString(JNIEnv *jenv,
                                                                      jclass jcls,
                                                                      jlong jendpoint,
                                                                      jobject jendpoint_)
{
  jobject jresult = 0;
  oc_endpoint_t *endpoint = (oc_endpoint_t *)0;
  jobject result;

  (void)jenv;
  (void)jcls;
  (void)jendpoint_;
  endpoint = *(oc_endpoint_t **)&jendpoint;

  oc_string_t ep;
  int r = oc_endpoint_to_string(endpoint, &ep);
  if(r < 0) {
    return NULL;
  }

  result = JCALL1(NewStringUTF, jenv, oc_string(ep));
  oc_free_string(&ep);

  jresult = result;
  return jresult;
}
%}


%apply oc_string_t *INPUT { oc_string_t *endpoint_str };
%apply oc_string_t *OUTPUT { oc_string_t *uri };
/* TODO check the string_to_endpoint function output */
%rename(stringToEndpoint) oc_string_to_endpoint;
%rename(ipv6EndpointIsLinkLocal) oc_ipv6_endpoint_is_link_local;
%rename(compare) oc_endpoint_compare;
%rename(compareAddress) oc_endpoint_compare_address;
%rename(setLocalAddress) oc_endpoint_set_local_address;
%include "oc_endpoint.h"
/*******************End oc_endpoint.h***********************/
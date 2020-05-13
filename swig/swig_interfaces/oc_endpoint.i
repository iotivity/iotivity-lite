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
%javaexception("OCEndpointParseException") oc_endpoint_t(oc_string_t *endpoint_str) {
  if (!jarg1) {
    jclass cls_OCEndpointParseException = JCALL1(FindClass, jenv, "org/iotivity/OCEndpointParseException");
    assert(cls_OCEndpointParseException);
    JCALL2(ThrowNew, jenv, cls_OCEndpointParseException, "The (null) string cannot be parsed.");
    return $null;
  }
  $action
  if(!result) {
    OC_DBG("JNI: String can not be parsed.");
    jclass cls_OCEndpointParseException = JCALL1(FindClass, jenv, "org/iotivity/OCEndpointParseException");
    assert(cls_OCEndpointParseException);
    oc_string_t exception_message_part1;
    oc_concat_strings(&exception_message_part1, "The \"", oc_string(*arg1));
    oc_string_t exception_message;
    oc_concat_strings(&exception_message, oc_string(exception_message_part1), "\" string cannot be parsed.");
    JCALL2(ThrowNew, jenv, cls_OCEndpointParseException, ((char *)oc_string(exception_message)));
    oc_free_string(&exception_message_part1);
    oc_free_string(&exception_message);
  }
}
%newobject copy;

%extend oc_endpoint_t {
  oc_endpoint_t() {
    OC_DBG("JNI: %s\n", __func__);
    return oc_new_endpoint();
  }

  // Due to bug in oc_string_to_endpoint we must pass in uri even though we are not using the uri
  oc_endpoint_t(oc_string_t *endpoint_str) {
    OC_DBG("JNI: %s\n", __func__);
    oc_endpoint_t *ep = oc_new_endpoint();
    oc_string_t uri;
    memset(&uri, 0, sizeof(oc_string_t));
    if(oc_string_to_endpoint(endpoint_str, ep, &uri) < 0) {
      OC_DBG("JNI: oc_string_to_endpoint failed to parse %s\n", oc_string(*endpoint_str));
      oc_free_endpoint(ep);
      oc_free_string(&uri);
      return NULL;
    }
    oc_free_string(&uri);
    return ep;
  }

  ~oc_endpoint_t() {
   OC_DBG("JNI: %s\n", __func__);
   oc_free_endpoint($self);
   $self = NULL;
  }

  void setDi(oc_uuid_t *di) {
    oc_endpoint_set_di($self, di);
  }

  oc_string_t toString() {
    oc_string_t ep;
    memset(&ep, 0, sizeof(oc_string_t));
    int r = oc_endpoint_to_string($self, &ep);
    if(r < 0) {
      oc_free_string(&ep);
      return ep;
    }
    return ep;
  }

  jboolean isIPv6LinkLocal() {
    return (oc_ipv6_endpoint_is_link_local($self) == 0) ? JNI_TRUE : JNI_FALSE;
  }

  jboolean compare(const oc_endpoint_t *ep2) {
    return (oc_endpoint_compare($self, ep2) == 0) ? JNI_TRUE : JNI_FALSE;
  }

  jboolean compareAddress(const oc_endpoint_t *ep2) {
    return (oc_endpoint_compare_address($self, ep2) == 0) ? JNI_TRUE : JNI_FALSE;
  }

  void setLocalAddress(int interfaceIndex) {
    oc_endpoint_set_local_address($self, interfaceIndex);
  }

  oc_endpoint_t *copy()
  {
    oc_endpoint_t *destination = oc_new_endpoint();
    oc_endpoint_copy(destination, $self);
    return destination;
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
%rename(newEndpoint) oc_new_endpoint;
%ignore oc_free_endpoint;
// tell swig to use our JNI code not to generate its own.
%native (freeEndpoint) void freeEndpoint(oc_endpoint_t *endpoint);
%{
void jni_free_endpoint(oc_endpoint_t *endpoint) {
  oc_free_endpoint(endpoint);
  endpoint = NULL;
}
%}
%{
/*
 * Hand rolled JNI code. Is here to prevent double freeing of memory.
 * If `freeEndpoint` is called then the developer is explicitly taking ownership
 * of the `OCEndpoint`.  If `swigCMemOwn` is `true` it must be changed to false
 * to prevent the Java GC from trying to free the same block of memory a second
 * time.
 *
 * Since this is freeing memory we also set the swigCPtr to null to instantly
 * cause code failures should the developer try and use the Java OCEndpoint that
 * they just freed. In JUnit value of the `swigCPtr` can be checked to verify the
 * operation of this code. We can not check `swigCMemOwn` directly because it is
 * a private member variable with not get method to access it.
 */
SWIGEXPORT void JNICALL Java_org_iotivity_OCEndpointUtilJNI_freeEndpoint(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  OC_DBG("JNI: %s\n", __func__);
  oc_endpoint_t *arg1 = NULL;

  (void) jcls;
  jboolean jswigCMemOwn = false;
  jfieldID swigCMemOwn_fid = (*jenv)->GetFieldID(jenv, cls_OCEndpoint, "swigCMemOwn", "Z");
  if (swigCMemOwn_fid != 0) {
    jswigCMemOwn = (*jenv)->GetBooleanField(jenv, jarg1_, swigCMemOwn_fid);
    if (jswigCMemOwn) {
      (*jenv)->SetBooleanField(jenv, jarg1_, swigCMemOwn_fid, false);
    }
  }

  arg1 = (oc_endpoint_t *)jarg1;
  jni_free_endpoint(arg1);

  jfieldID swigCPtr_fid = (*jenv)->GetFieldID(jenv, cls_OCEndpoint, "swigCPtr", "J");
  if (swigCPtr_fid != 0) {
    (*jenv)->SetLongField(jenv, jarg1_, swigCPtr_fid, 0);
  }
}
%}
%ignore oc_endpoint_set_di;
%exception oc_endpoint_set_di {
  /* The `oc_endpoint_t *endpoint` parameter is jarg1, the name is generated by SWIG. */

  if(!jarg1) {
    OC_DBG("JNI: OCEndpoint cannot be null.\n");
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "OCEndpoint cannot be null.");
    return;
  }
  /* The `oc_uuid_t *di` parameter is jarg2, the name is generated by SWIG. */
  if(!jarg2) {
    OC_DBG("JNI: OCUuid cannot be null.\n");
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException,  "OCUuid cannot be null.");
    return;
  }
  $action
}
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

%javaexception("OCEndpointParseException") jni_string_to_endpoint {
  if (!jarg1) {
    jclass cls_OCEndpointParseException = JCALL1(FindClass, jenv, "org/iotivity/OCEndpointParseException");
    assert(cls_OCEndpointParseException);
    JCALL2(ThrowNew, jenv, cls_OCEndpointParseException, "The (null) string cannot be parsed.");
    return $null;
  }
  $action
  if(!result) {
    OC_DBG("JNI: String can not be parsed.");
    jclass cls_OCEndpointParseException = JCALL1(FindClass, jenv, "org/iotivity/OCEndpointParseException");
    assert(cls_OCEndpointParseException);
    oc_string_t exception_message_part1;
    oc_concat_strings(&exception_message_part1, "The \"", oc_string(*arg1));
    oc_string_t exception_message;
    oc_concat_strings(&exception_message, oc_string(exception_message_part1), "\" string cannot be parsed.");
    JCALL2(ThrowNew, jenv, cls_OCEndpointParseException, ((char *)oc_string(exception_message)));
    oc_free_string(&exception_message_part1);
    oc_free_string(&exception_message);
  }
}
/* TODO figure out a clean way to return the uri param not as an array value */
%ignore oc_string_to_endpoint;
%newobject jni_string_to_endpoint;
%rename(stringToEndpoint) jni_string_to_endpoint;
%inline %{
oc_endpoint_t * jni_string_to_endpoint(oc_string_t *endpoint_str, oc_string_t *uri) {
  OC_DBG("JNI: %s\n", __func__);
  oc_endpoint_t *ep = oc_new_endpoint();
  if(oc_string_to_endpoint(endpoint_str, ep, uri) < 0) {
    OC_DBG("JNI: oc_string_to_endpoint failed to parse %s\n", oc_string(*endpoint_str));
    oc_free_endpoint(ep);
    return NULL;
  }
  return ep;
}
%}

%javaexception("OCEndpointParseException") jni_string_to_endpoint_a {
  if (!jarg1) {
    jclass cls_OCEndpointParseException = JCALL1(FindClass, jenv, "org/iotivity/OCEndpointParseException");
    assert(cls_OCEndpointParseException);
    JCALL2(ThrowNew, jenv, cls_OCEndpointParseException, "The (null) string cannot be parsed.");
    return $null;
  }
  $action
  if(!result) {
    OC_DBG("JNI: String can not be parsed.");
    jclass cls_OCEndpointParseException = JCALL1(FindClass, jenv, "org/iotivity/OCEndpointParseException");
    assert(cls_OCEndpointParseException);
    oc_string_t exception_message_part1;
    oc_concat_strings(&exception_message_part1, "The \"", oc_string(*arg1));
    oc_string_t exception_message;
    oc_concat_strings(&exception_message, oc_string(exception_message_part1), "\" string cannot be parsed.");
    JCALL2(ThrowNew, jenv, cls_OCEndpointParseException, ((char *)oc_string(exception_message)));
    oc_free_string(&exception_message_part1);
    oc_free_string(&exception_message);
  }
}
%newobject jni_string_to_endpoint_a;
%rename(stringToEndpoint) jni_string_to_endpoint_a;
%inline %{
oc_endpoint_t * jni_string_to_endpoint_a(oc_string_t *endpoint_str) {
  OC_DBG("JNI: %s\n", __func__);
  oc_endpoint_t *ep = oc_new_endpoint();
  if(oc_string_to_endpoint(endpoint_str, ep, NULL) < 0) {
    OC_DBG("JNI: oc_string_to_endpoint failed to parse %s\n", oc_string(*endpoint_str));
    oc_free_endpoint(ep);
    return NULL;
  }
  return ep;
}
%}

%ignore oc_endpoint_string_parse_path;
%newobject jni_endpoint_string_parse_path;
%rename (endpointStringParsePath) jni_endpoint_string_parse_path;
%inline %{
/*
 * Convert the input parameter to a return parameter
 */
char *jni_endpoint_string_parse_path(oc_string_t *endpoint_str)
{
  oc_string_t path;
  if (oc_endpoint_string_parse_path(endpoint_str, &path) == 0 ){
    char * ret_path = (char *)malloc((path.size) * sizeof(char));
    strcpy(ret_path, oc_string(path));
    return ret_path;
  }
  return NULL;
}
%}

%rename(ipv6EndpointIsLinkLocal) oc_ipv6_endpoint_is_link_local;
%rename(compare) oc_endpoint_compare;
%rename(compareAddress) oc_endpoint_compare_address;
%rename(setLocalAddress) oc_endpoint_set_local_address;

%ignore oc_endpoint_copy;
%newobject jni_endpoint_copy;
%rename (copy) jni_endpoint_copy;
%inline %{
oc_endpoint_t *jni_endpoint_copy(oc_endpoint_t *source)
{
  oc_endpoint_t *destination = oc_new_endpoint();
  oc_endpoint_copy(destination, source);
  return destination;
}
%}

%ignore oc_endpoint_list_copy;
%newobject jni_endpoint_list_copy;
%rename (listCopy) jni_endpoint_list_copy;
%inline %{
oc_endpoint_t *jni_endpoint_list_copy(oc_endpoint_t *source)
{
  oc_endpoint_t *destination = oc_new_endpoint();
  oc_endpoint_list_copy(&destination, source);
  return destination;
}
%}

%include "oc_endpoint.h"
/*******************End oc_endpoint.h***********************/
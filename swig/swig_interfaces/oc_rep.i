/* File oc_rep.i */
%module OCRep

%include "enums.swg"
%javaconst(1);
%include "stdint.i"
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
#include "oc_iotivity_lite_jni.h"

#include "oc_api.h"
#include "oc_rep.h"
#include "oc_collection.h"
#include "oc_helpers.h"
#include "port/oc_log.h"
#include <assert.h>


%}

/*******************Begin cbor.h******************************/
/* CborEncoder from cbor.h  needed to process oc_rep.h*/
struct CborEncoder
{
/*    union {
        uint8_t *ptr;
        ptrdiff_t bytes_needed;
    } data;
    const uint8_t *end;
    size_t remaining;
    int flags;*/
};
/*******************End cbor.h********************************/
/*******************Begin oc_rep.h****************************/
%rename(OCRepresentation) oc_rep_s;
%rename(OCType) oc_rep_value_type_t;
%rename(OCValue) oc_rep_value;
%rename(Double) double_p;
%rename(Bool) boolean;
%rename(objectArray) object_array;
%ignore g_encoder;
%ignore root_map;
%ignore links_array;
%ignore g_err;

%ignore oc_rep_new;
%{
uint8_t *g_new_rep_buffer = NULL;
struct oc_memb g_rep_objects;
%}
%inline %{
void deleteBuffer() {
  free(g_new_rep_buffer);
  g_new_rep_buffer = NULL;
}
void newBuffer(int size) {
  if (g_new_rep_buffer) {
    deleteBuffer();
  }
  g_new_rep_buffer = (uint8_t *)malloc(size);
  oc_rep_new(g_new_rep_buffer, size);
  g_rep_objects.size = sizeof(oc_rep_t);
  g_rep_objects.num = 0;
  g_rep_objects.count = NULL;
  g_rep_objects.mem = NULL;
  g_rep_objects.buffers_avail_cb = NULL;
  oc_rep_set_pool(&g_rep_objects);
}
%}

%ignore oc_rep_get_encoded_payload_size;
%ignore oc_rep_get_encoder_buf;
%rename (setDouble) jni_rep_set_double;
%inline %{
/* Alt implementation of oc_rep_set_double macro*/
void jni_rep_set_double(CborEncoder * object, const char* key, double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_double(object, value);
}
%}

%rename (setLong) jni_rep_set_long;
%inline %{
/* Alt implementation of oc_rep_set_int macro */
void jni_rep_set_long(CborEncoder * object, const char* key, int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_int(object, value);
}
%}

%rename (setUnsignedInt) jni_rep_set_uint;
%inline %{
/* Alt implementation of oc_rep_set_uint macro */
void jni_rep_set_uint(CborEncoder * object, const char* key, unsigned int value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_uint(object, value);
}
%}

%rename (setBoolean) jni_rep_set_boolean;
%inline %{
/* Alt implementation of oc_rep_set_boolean macro */
void jni_rep_set_boolean(CborEncoder * object, const char* key, bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_boolean(object, value);
}
%}

%rename (setTextString) jni_rep_set_text_string;
%inline %{
/* Alt implementation of oc_rep_set_text_string macro */
void jni_rep_set_text_string(CborEncoder * object, const char* key, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_text_string(object, value, strlen(value));
}
%}

%typemap(in)     (const unsigned char * BYTE, size_t LENGTH) {
/* Functions from jni.h */
$1 = (unsigned char *) JCALL2(GetByteArrayElements, jenv, $input, 0);
$2 = (size_t) JCALL1(GetArrayLength,       jenv, $input);
}
%typemap(jni)    (const unsigned char * BYTE, size_t LENGTH) "jbyteArray"
%typemap(jtype)  (const unsigned char * BYTE, size_t LENGTH) "byte[]"
%typemap(jstype) (const unsigned char * BYTE, size_t LENGTH) "byte[]"
%typemap(javain) (const unsigned char * BYTE, size_t LENGTH) "$javainput"

/* Specify signature of method to handle */
%apply (const unsigned char * BYTE, size_t LENGTH)   { (const unsigned char *value, size_t length) };
%rename (setByteString) jni_rep_set_byte_string;
%inline %{
/* Alt implementation of oc_rep_set_byte_string macro */
void jni_rep_set_byte_string(CborEncoder * object, const char* key, const unsigned char *value, size_t length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_byte_string(object, value, length);
}
%}

%rename (beginArray) jni_rep_start_array;
%inline %{
/* Alt implementation of oc_rep_start_array macro */
CborEncoder * jni_rep_start_array(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __func__);
  CborEncoder *cbor_encoder_array = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_array(parent, cbor_encoder_array, CborIndefiniteLength);
  return cbor_encoder_array;
}
%}

%rename (endArray) jni_rep_end_array;
%inline %{
/* Alt implementation of oc_rep_end_array macro */
void jni_rep_end_array(CborEncoder *parent, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_close_container(parent, arrayObject);
  free(arrayObject);
  arrayObject = NULL;
}
%}

%rename (beginLinksArray) jni_rep_start_links_array;
%inline %{
/* Alt implementation of oc_rep_start_links_array macro */
CborEncoder * jni_rep_start_links_array() {
  OC_DBG("JNI: %s\n", __func__);
  cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength);
  return &links_array;
}
%}

%rename (endLinksArray) jni_rep_end_links_array;
%inline %{
/* Alt implementation of oc_rep_end_links_array macro */
void jni_rep_end_links_array() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_links_array();
}
%}

%rename(beginRootObject) jni_start_root_object;
%inline %{
/* Alt implementation of oc_rep_start_root_object macro */
CborEncoder * jni_start_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength);
  return &root_map;
}
%}

%rename(endRootObject) jni_rep_end_root_object;
%inline %{
void jni_rep_end_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_root_object();
}
%}

%rename(addByteString) jni_rep_add_byte_string;
%inline %{
/* Alt implementation of oc_rep_add_byte_string macro */
void jni_rep_add_byte_string(CborEncoder *arrayObject, const unsigned char* value, const size_t length) {
  OC_DBG("JNI: %s\n", __func__);
  if (value != NULL) {
    g_err |= cbor_encode_byte_string(arrayObject, value, length);
  }
}
%}

%rename(addTextString) jni_rep_add_text_string;
%inline %{
/* Alt implementation of oc_rep_add_text_string macro */
void jni_rep_add_text_string(CborEncoder *arrayObject, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  if (value != NULL) {
    g_err |= cbor_encode_text_string(arrayObject, value, strlen(value));
  }
}
%}

%rename(addDouble) jni_rep_add_double;
%inline %{
/* Alt implementation of oc_rep_add_double macro */
void jni_rep_add_double(CborEncoder *arrayObject, const double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_double(arrayObject, value);
}
%}

%rename(addInt) jni_rep_add_int;
%inline %{
/* Alt implementation of oc_rep_add_int macro */
void jni_rep_add_int(CborEncoder *arrayObject, const int value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_int(arrayObject, value);
}
%}

%rename(addBoolean) jni_rep_add_boolean;
%inline %{
/* Alt implementation of oc_rep_add_boolean macro */
void jni_rep_add_boolean(CborEncoder *arrayObject, const bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_boolean(arrayObject, value);
}
%}

%rename(setKey) jni_rep_set_key;
%inline %{
/* Alt implementation of oc_rep_set_key macro */
void jni_rep_set_key(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
}
%}

%rename(openArray) jni_rep_set_array;
%inline %{
/* Alt implementation of oc_rep_set_array macro */
CborEncoder * jni_rep_set_array(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return jni_rep_start_array(parent);
}
%}

%rename(closeArray) jni_rep_close_array;
%inline %{
/* Alt implementation of oc_rep_close_array macro */
void jni_rep_close_array(CborEncoder *object, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  jni_rep_end_array(object, arrayObject);
}
%}

%rename (beginObject) jni_rep_start_object;
%inline %{
/* Alt implementation of oc_rep_start_object macro */
CborEncoder * jni_rep_start_object(CborEncoder *parent) {
  OC_DBG("JNI: %s\n", __func__);
  CborEncoder *cbor_encoder_map = (CborEncoder *)malloc(sizeof(struct CborEncoder));
  g_err |= cbor_encoder_create_map(parent, cbor_encoder_map, CborIndefiniteLength);
  return cbor_encoder_map;
}
%}

%rename (endObject) jni_rep_end_object;
%inline %{
/* Alt implementation of oc_rep_end_object macro */
void jni_rep_end_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_close_container(parent, object);
  free(object);
  object = NULL;
}
%}

%rename (objectArrayBeginItem) jni_rep_object_array_start_item;
%inline %{
/* Alt implementation of oc_rep_object_array_start_item macro */
CborEncoder * jni_rep_object_array_start_item(CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  return jni_rep_start_object(arrayObject);
}
%}

%rename (objectArrayEndItem) jni_rep_object_array_end_item;
%inline %{
/* Alt implementation of oc_rep_object_array_end_item macro */
void jni_rep_object_array_end_item(CborEncoder *parentArrayObject, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  jni_rep_end_object(parentArrayObject, arrayObject);
}
%}

%rename(openObject) jni_rep_set_object;
%inline %{
/* Alt implementation of oc_rep_set_object macro */
CborEncoder * jni_rep_set_object(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return jni_rep_start_object(parent);
}
%}

%rename(closeObject) jni_rep_close_object;
%inline %{
/* Alt implementation of oc_rep_close_object macro */
void jni_rep_close_object(CborEncoder *parent, CborEncoder *object) {
  OC_DBG("JNI: %s\n", __func__);
  jni_rep_end_object(parent, object);
}
%}

%typemap(jni) (int64_t *values, int length) "jlongArray"
%typemap(jtype) (int64_t *values, int length) "long[]"
%typemap(jstype) (int64_t *values, int length) "long[]"
%typemap(javain) (int64_t *values, int length) "$javainput"
%typemap(javadirectorin) (int64_t *values, int length) "$javainput"
%typemap(javadirectorout) (int64_t *values, int length) "$javacall"

%typemap(in) (int64_t *values, int length) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  jlong *jvalues = JCALL2(GetLongArrayElements, jenv, $input, 0);
  jsize jlength = JCALL1(GetArrayLength, jenv, $input);

  $1 = (int64_t *)jvalues;
  $2 = jlength;
}
%rename(setLongArray) jni_rep_set_long_array;
%inline %{
/* Alt implementation of oc_rep_set_int_array macro */
void jni_rep_set_long_array(CborEncoder *object, const char* key, int64_t *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_int(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%typemap(jni) (bool *values, int length) "jbooleanArray"
%typemap(jtype) (bool *values, int length) "boolean[]"
%typemap(jstype) (bool *values, int length) "boolean[]"
%typemap(javain) (bool *values, int length) "$javainput"
%typemap(javadirectorin) (bool *values, int length) "$javainput"
%typemap(javadirectorout) (bool *values, int length) "$javacall"

%typemap(in) (bool *values, int length) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  jboolean *jvalues = JCALL2(GetBooleanArrayElements, jenv, $input, 0);
  jsize jlength = JCALL1(GetArrayLength, jenv, $input);

  $1 = (bool *)jvalues;
  $2 = jlength;
}
%rename(setBooleanArray) jni_rep_set_bool_array;
%inline %{
/* Alt implementation of oc_rep_set_bool_array macro */
void jni_rep_set_bool_array(CborEncoder *object, const char* key, bool *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_boolean(&value_array, values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%typemap(jni) (double *values, int length) "jdoubleArray "
%typemap(jtype) (double *values, int length) "double[]"
%typemap(jstype) (double *values, int length) "double[]"
%typemap(javain) (double *values, int length) "$javainput"
%typemap(javadirectorin) (double *values, int length) "$javainput"
%typemap(javadirectorout) (double *values, int length) "$javacall"

%typemap(in) (double *values, int length) {
  if (!$input) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "array null");
    return $null;
  }
  jdouble *jvalues = JCALL2(GetDoubleArrayElements, jenv, $input, 0);
  jsize jlength = JCALL1(GetArrayLength, jenv, $input);

  $1 = (double *)jvalues;
  $2 = jlength;
}
%rename(setDoubleArray) jni_rep_set_double_array;
%inline %{
/* Alt implementation of oc_rep_set_double_array macro */
void jni_rep_set_double_array(CborEncoder *object, const char* key, double *values, int length) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, length);
  int i;
  for (i = 0; i < length; i++) {
    g_err |= cbor_encode_floating_point(&value_array, CborDoubleType, &values[i]);
  }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%rename(setStringArray) jni_rep_rep_set_string_array;
%inline %{
/* Alt implementation of oc_rep_set_string_array macro */
void jni_rep_rep_set_string_array(CborEncoder *object, const char* key, oc_string_array_t values) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  CborEncoder value_array;
  g_err |= cbor_encoder_create_array(object, &value_array, CborIndefiniteLength);
  int i;
    for (i = 0; i < (int)oc_string_array_get_allocated_size(values); i++) {
      if (oc_string_array_get_item_size(values, i) > 0) {
        g_err |= cbor_encode_text_string(&value_array, oc_string_array_get_item(values, i),
                                         oc_string_array_get_item_size(values, i));
      }
    }
  g_err |= cbor_encoder_close_container(object, &value_array);
}
%}

%rename(getOCRepresentaionFromRootObject) jni_rep_get_rep_from_root_object;
%newobject jni_rep_get_rep_from_root_object;
%inline %{
/*
 * Java only helper function to convert the root CborEncoder object to an oc_rep_t this is needed
 * to enable encode/decode unit testing. This function is not expected to be used in typical
 * use case. It should only be called after calling oc_rep_end_root_object.
 */
oc_rep_t * jni_rep_get_rep_from_root_object() {
  oc_rep_t * rep = (oc_rep_t *)malloc(sizeof(oc_rep_t));
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  oc_parse_rep(payload, payload_len, &rep);
  return rep;
}
%}
%ignore oc_rep_get_cbor_errno;
%rename(getCborErrno) jni_rep_get_cbor_errno;
%inline %{
int jni_rep_get_cbor_errno() {
  return (int)oc_rep_get_cbor_errno();
}
%}
%ignore oc_rep_set_pool;
%ignore oc_parse_rep;
%ignore oc_free_rep;

%typemap(in, numinputs=0, noblock=1) bool *jni_rep_get_error_flag {
  bool temp_jni_rep_get_error_flag;
  $1 = &temp_jni_rep_get_error_flag;
}

%typemap(jstype) int64_t jni_rep_get_long "Long"
%typemap(jtype) int64_t jni_rep_get_long "Long"
%typemap(jni) int64_t jni_rep_get_long "jobject"
%typemap(javaout) int64_t jni_rep_get_long {
  return $jnicall;
}
%typemap(out, noblock=1) int64_t jni_rep_get_long {
  if(temp_jni_rep_get_error_flag) {
    const jclass cls_Integer = JCALL1(FindClass, jenv, "java/lang/Long");
    assert(cls_Integer);
    const jmethodID mid_Integer_init = JCALL3(GetMethodID, jenv, cls_Integer, "<init>", "(J)V");
    assert(mid_Integer_init);
    $result = JCALL3(NewObject, jenv, cls_Integer, mid_Integer_init, $1);
  } else {
    $result = NULL;
  }
}

%ignore oc_rep_get_int;
%rename(getLong) jni_rep_get_long;
%inline %{
int64_t jni_rep_get_long(oc_rep_t *rep, const char *key, bool *jni_rep_get_error_flag) {
  int64_t retValue;
  *jni_rep_get_error_flag = oc_rep_get_int(rep, key, &retValue);
  return retValue;
}
%}

%typemap(jstype) bool jni_rep_get_bool "Boolean"
%typemap(jtype) bool jni_rep_get_bool "Boolean"
%typemap(jni) bool jni_rep_get_bool "jobject"
%typemap(javaout) bool jni_rep_get_bool {
  return $jnicall;
}
%typemap(out, noblock=1) bool jni_rep_get_bool {
  if(temp_jni_rep_get_error_flag) {
    const jclass cls_Boolean = JCALL1(FindClass, jenv, "java/lang/Boolean");
    assert(cls_Boolean);
    const jmethodID mid_Boolean_init = JCALL3(GetMethodID, jenv, cls_Boolean, "<init>", "(Z)V");
    assert(mid_Boolean_init);
    $result = JCALL3(NewObject, jenv, cls_Boolean, mid_Boolean_init, $1);
  } else {
    $result = NULL;
  }
}

%ignore oc_rep_get_bool;
%rename(getBoolean) jni_rep_get_bool;
%inline %{
bool jni_rep_get_bool(oc_rep_t *rep, const char *key, bool *jni_rep_get_error_flag) {
  bool retValue;
  *jni_rep_get_error_flag = oc_rep_get_bool(rep, key, &retValue);
  return retValue;
}
%}

%typemap(jstype) double jni_rep_get_double "Double"
%typemap(jtype) double jni_rep_get_double "Double"
%typemap(jni) double jni_rep_get_double "jobject"
%typemap(javaout) double jni_rep_get_double {
  return $jnicall;
}
%typemap(out, noblock=1) double jni_rep_get_double {
  if(temp_jni_rep_get_error_flag) {
    const jclass cls_Double = JCALL1(FindClass, jenv, "java/lang/Double");
    assert(cls_Double);
    const jmethodID mid_Double_init = JCALL3(GetMethodID, jenv, cls_Double, "<init>", "(D)V");
    assert(mid_Double_init);
    $result = JCALL3(NewObject, jenv, cls_Double, mid_Double_init, $1);
  } else {
    $result = NULL;
  }
}

%ignore oc_rep_get_double;
%rename(getDouble) jni_rep_get_double;
%inline %{
double jni_rep_get_double(oc_rep_t *rep, const char *key, bool *jni_rep_get_error_flag) {
  double retValue;
  *jni_rep_get_error_flag = oc_rep_get_double(rep, key, &retValue);
  return retValue;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *byte_string_size {
  size_t temp_byte_string_size;
  $1 = &temp_byte_string_size;
}
%typemap(jstype) const char * jni_rep_get_byte_string "byte[]"
%typemap(jtype) const char * jni_rep_get_byte_string "byte[]"
%typemap(jni) const char * jni_rep_get_byte_string "jbyteArray"
%typemap(javaout) const char * jni_rep_get_byte_string {
  return $jnicall;
}
%typemap(out) const char * jni_rep_get_byte_string {
  if($1 != NULL) {
    $result = JCALL1(NewByteArray, jenv, (jsize)temp_byte_string_size);
    JCALL4(SetByteArrayRegion, jenv, $result, 0, (jsize)temp_byte_string_size, (const jbyte *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_byte_string;
%rename(getByteString) jni_rep_get_byte_string;
%inline %{
const char * jni_rep_get_byte_string(oc_rep_t *rep, const char *key, size_t *byte_string_size) {
  char * c_byte_string = NULL;
  if (oc_rep_get_byte_string(rep, key, &c_byte_string, byte_string_size)) {
    return c_byte_string;
  }
  return NULL;
}
%}

%ignore oc_rep_get_string;
%rename(getString) jni_rep_get_string;
%inline %{
char * jni_rep_get_string(oc_rep_t *rep, const char *key) {
  char * retValue;
  size_t size;
  if(oc_rep_get_string(rep, key, &retValue, &size)) {
    return retValue;
  } else {
    return NULL;
  }
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *int_array_size {
  size_t temp_int_array_size;
  $1 = &temp_int_array_size;
}
%typemap(jstype) const int64_t* jni_rep_get_long_array "long[]"
%typemap(jtype) const int64_t* jni_rep_get_long_array "long[]"
%typemap(jni) const int64_t* jni_rep_get_long_array "jlongArray"
%typemap(javaout) const int64_t* jni_rep_get_long_array {
  return $jnicall;
}
%typemap(out) const int64_t* jni_rep_get_long_array {
  if($1 != NULL) {
    $result = JCALL1(NewLongArray, jenv, (jsize)temp_int_array_size);
    JCALL4(SetLongArrayRegion, jenv, $result, 0, (jsize)temp_int_array_size, (const jlong *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_int_array;
%rename(getLongArray) jni_rep_get_long_array;
%inline %{
const int64_t* jni_rep_get_long_array(oc_rep_t *rep, const char *key, size_t *int_array_size) {
  int64_t *c_int_array;
  if (oc_rep_get_int_array(rep, key, &c_int_array, int_array_size)) {
    return c_int_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *bool_array_size {
  size_t temp_bool_array_size;
  $1 = &temp_bool_array_size;
}
%typemap(jstype) const bool* jni_rep_get_bool_array "boolean[]"
%typemap(jtype) const bool* jni_rep_get_bool_array "boolean[]"
%typemap(jni) const bool* jni_rep_get_bool_array "jbooleanArray"
%typemap(javaout) const bool* jni_rep_get_bool_array {
  return $jnicall;
}
%typemap(out) const bool* jni_rep_get_bool_array {
  if($1 != NULL) {
    $result = JCALL1(NewBooleanArray, jenv, (jsize)temp_bool_array_size);
    JCALL4(SetBooleanArrayRegion, jenv, $result, 0, (jsize)temp_bool_array_size, (const jboolean *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_bool_array;
%rename(getBooleanArray) jni_rep_get_bool_array;
%inline %{
const bool* jni_rep_get_bool_array(oc_rep_t *rep, const char *key, size_t *bool_array_size) {
  bool *c_bool_array;
  if (oc_rep_get_bool_array(rep, key, &c_bool_array, bool_array_size)) {
    return c_bool_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *double_array_size {
  size_t temp_double_array_size;
  $1 = &temp_double_array_size;
}
%typemap(jstype) const double* jni_rep_get_double_array "double[]"
%typemap(jtype) const double* jni_rep_get_double_array "double[]"
%typemap(jni) const double* jni_rep_get_double_array "jdoubleArray"
%typemap(javaout) const double* jni_rep_get_double_array {
  return $jnicall;
}
%typemap(out) const double* jni_rep_get_double_array {
  if($1 != NULL) {
    $result = JCALL1(NewDoubleArray, jenv, (jsize)temp_double_array_size);
    JCALL4(SetDoubleArrayRegion, jenv, $result, 0, (jsize)temp_double_array_size, (const jdouble *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_double_array;
%rename(getDoubleArray) jni_rep_get_double_array;
%inline %{
const double* jni_rep_get_double_array(oc_rep_t *rep, const char *key, size_t *double_array_size) {
  double *c_double_array;
  if (oc_rep_get_double_array(rep, key, &c_double_array, double_array_size)) {
    return c_double_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *byte_string_array_size {
  size_t temp_byte_string_array_size;
  $1 = &temp_byte_string_array_size;
}
%typemap(jstype) const oc_string_array_t * jni_rep_get_byte_string_array "byte[][]"
%typemap(jtype) const oc_string_array_t * jni_rep_get_byte_string_array "byte[][]"
%typemap(jni) const oc_string_array_t * jni_rep_get_byte_string_array "jobjectArray"
%typemap(javaout) const oc_string_array_t * jni_rep_get_byte_string_array {
  return $jnicall;
}
%typemap(out) const oc_string_array_t * jni_rep_get_byte_string_array {
  if($1 != NULL) {
    jbyteArray temp_byte_string;
    const jclass clazz = JCALL1(FindClass, jenv, "[B");
    $result = JCALL3(NewObjectArray, jenv, (jsize)temp_byte_string_array_size, clazz, 0);
    /* exception checking omitted */
    for (size_t i=0; i<temp_byte_string_array_size; i++) {
      jsize jbyte_array_size = oc_byte_string_array_get_item_size(*$1, i);
      temp_byte_string = JCALL1(NewByteArray, jenv, jbyte_array_size);
      JCALL4(SetByteArrayRegion, jenv, temp_byte_string, 0, jbyte_array_size,
             (const jbyte *)oc_byte_string_array_get_item(*$1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, (jsize)i, temp_byte_string);
      JCALL1(DeleteLocalRef, jenv, temp_byte_string);
    }
    /* free the oc_string_array_t that was allocated in the jni_rep_get_byte_string_array function */
    free($1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_byte_string_array;
%rename(getByteStringArray) jni_rep_get_byte_string_array;
%inline %{
const oc_string_array_t * jni_rep_get_byte_string_array(oc_rep_t *rep, const char *key, size_t *byte_string_array_size) {
  oc_string_array_t * c_byte_string_array = (oc_string_array_t *)malloc(sizeof(oc_string_array_t));
  if (oc_rep_get_byte_string_array(rep, key, c_byte_string_array, byte_string_array_size)) {
    return c_byte_string_array;
  }
  return NULL;
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *string_array_size {
  size_t temp_string_array_size;
  $1 = &temp_string_array_size;
}
%typemap(jstype) const oc_string_array_t * jni_rep_get_string_array "String[]"
%typemap(jtype) const oc_string_array_t * jni_rep_get_string_array "String[]"
%typemap(jni) const oc_string_array_t * jni_rep_get_string_array "jobjectArray"
%typemap(javaout) const oc_string_array_t * jni_rep_get_string_array {
  return $jnicall;
}
%typemap(out) const oc_string_array_t * jni_rep_get_string_array {
  if($1 != NULL) {
    jstring temp_string;
    const jclass clazz = JCALL1(FindClass, jenv, "java/lang/String");
    $result = JCALL3(NewObjectArray, jenv, (jsize)temp_string_array_size, clazz, 0);
    /* exception checking omitted */
    for (size_t i=0; i<temp_string_array_size; i++) {
      temp_string = JCALL1(NewStringUTF, jenv, oc_string_array_get_item(*$1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, (jsize)i, temp_string);
      JCALL1(DeleteLocalRef, jenv, temp_string);
    }
    /* free the oc_string_array_t that was allocated in the jni_rep_get_string_array function */
    free($1);
    //JCALL4(SetDoubleArrayRegion, jenv, $result, 0, (jsize)temp_string_array_size, (const jdouble *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_string_array;
%rename(getStringArray) jni_rep_get_string_array;
%inline %{
const oc_string_array_t * jni_rep_get_string_array(oc_rep_t *rep, const char *key, size_t *string_array_size) {
  oc_string_array_t * c_string_array = (oc_string_array_t *)malloc(sizeof(oc_string_array_t));
  if (oc_rep_get_string_array(rep, key, c_string_array, string_array_size)) {
    return c_string_array;
  }
  return NULL;
}
%}

%ignore oc_rep_get_object;
%rename(getObject) jni_rep_get_object;
%inline %{
oc_rep_t * jni_rep_get_object(oc_rep_t* rep, const char *key) {
  oc_rep_t *value;
  if(oc_rep_get_object(rep, key, &value)) {
    return value;
  }
  return NULL;
}
%}
%ignore oc_rep_get_object_array;
%rename(getObjectArray) jni_rep_get_object_array;
%inline %{
oc_rep_t * jni_rep_get_object_array(oc_rep_t* rep, const char *key) {
  oc_rep_t *value;
  if(oc_rep_get_object_array(rep, key, &value)) {
    return value;
  }
  return NULL;
}
%}
%rename(getRepError) jni_get_rep_error;
%inline %{
int jni_get_rep_error() {
  OC_DBG("JNI: %s\n", __func__);
  return g_err;
}
%}

// Expose oc_array_t this will be exposed as a class that has no usage without helper functions
%rename(OCArray) oc_mmem;
typedef struct oc_mmem {} oc_array_t;

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_long_array_len {
  size_t temp_oc_array_long_array_len;
  $1 = &temp_oc_array_long_array_len;
}
%typemap(jstype)  const int64_t * ocArrayToLongArray "long[]"
%typemap(jtype)   const int64_t * ocArrayToLongArray "long[]"
%typemap(jni)     const int64_t * ocArrayToLongArray "jlongArray"
%typemap(javaout) const int64_t * ocArrayToLongArray {
  return $jnicall;
}
%typemap(out) const int64_t * ocArrayToLongArray {
  if($1 != NULL) {
    $result = JCALL1(NewLongArray, jenv, (jsize)temp_oc_array_long_array_len);
    JCALL4(SetLongArrayRegion, jenv, $result, 0, (jsize)temp_oc_array_long_array_len, (const jlong *)$1);
  } else {
    $result = NULL;
  }
}
%inline %{
const int64_t * ocArrayToLongArray(oc_array_t array, size_t *oc_array_long_array_len) {
  *oc_array_long_array_len = (size_t)oc_int_array_size(array);
  return oc_int_array(array);
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_bool_array_len {
  size_t temp_oc_array_bool_array_len;
  $1 = &temp_oc_array_bool_array_len;
}
%typemap(jstype) const bool* ocArrayToBooleanArray "boolean[]"
%typemap(jtype) const bool* ocArrayToBooleanArray "boolean[]"
%typemap(jni) const bool* ocArrayToBooleanArray "jbooleanArray"
%typemap(javaout) const bool* ocArrayToBooleanArray {
  return $jnicall;
}
%typemap(out) const bool* ocArrayToBooleanArray {
  if($1 != NULL) {
    $result = JCALL1(NewBooleanArray, jenv, (jsize)temp_oc_array_bool_array_len);
    JCALL4(SetBooleanArrayRegion, jenv, $result, 0, (jsize)temp_oc_array_bool_array_len, (const jboolean *)$1);
  } else {
    $result = NULL;
  }
}
%inline %{
const bool* ocArrayToBooleanArray(oc_array_t array, size_t *oc_array_bool_array_len) {
  *oc_array_bool_array_len = (size_t)oc_bool_array_size(array);
  return oc_bool_array(array);
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_double_array_len {
  size_t temp_oc_array_double_array_len;
  $1 = &temp_oc_array_double_array_len;
}
%typemap(jstype)  const double* ocArrayToDoubleArray "double[]"
%typemap(jtype)   const double* ocArrayToDoubleArray "double[]"
%typemap(jni)     const double* ocArrayToDoubleArray "jdoubleArray"
%typemap(javaout) const double* ocArrayToDoubleArray {
  return $jnicall;
}
%typemap(out) const double* ocArrayToDoubleArray {
  if($1 != NULL) {
    $result = JCALL1(NewDoubleArray, jenv, (jsize)temp_oc_array_double_array_len);
    JCALL4(SetDoubleArrayRegion, jenv, $result, 0, (jsize)temp_oc_array_double_array_len, (const jdouble *)$1);
  } else {
    $result = NULL;
  }
}
%ignore oc_rep_get_double_array;
%rename(getDoubleArray) jni_rep_get_double_array;
%inline %{
const double* ocArrayToDoubleArray(oc_array_t array, size_t *oc_array_double_array_len) {
  *oc_array_double_array_len = (size_t)oc_double_array_size(array);
  return oc_double_array(array);
}
%}

%typemap(in, numinputs=0, noblock=1) size_t *oc_array_text_string_array_len {
  size_t temp_oc_array_text_string_array_len;
  $1 = &temp_oc_array_text_string_array_len;
}
%typemap(jstype)  const oc_string_array_t * ocArrayToStringArray "String[]"
%typemap(jtype)   const oc_string_array_t * ocArrayToStringArray "String[]"
%typemap(jni)     const oc_string_array_t * ocArrayToStringArray "jobjectArray"
%typemap(javaout) const oc_string_array_t * ocArrayToStringArray {
  return $jnicall;
}
%typemap(out) const oc_string_array_t * ocArrayToStringArray {
  if($1 != NULL) {
    jstring temp_string;
    const jclass clazz = JCALL1(FindClass, jenv, "java/lang/String");
    $result = JCALL3(NewObjectArray, jenv, (jsize)temp_oc_array_text_string_array_len, clazz, 0);
    /* exception checking omitted */
    for (size_t i=0; i<temp_oc_array_text_string_array_len; i++) {
      temp_string = JCALL1(NewStringUTF, jenv, oc_string_array_get_item(*$1, i));
      JCALL3(SetObjectArrayElement, jenv, $result, (jsize)i, temp_string);
      JCALL1(DeleteLocalRef, jenv, temp_string);
    }
  } else {
    $result = NULL;
  }
}
%inline %{
const oc_string_array_t * ocArrayToStringArray(oc_array_t *array, size_t *oc_array_text_string_array_len) {
  *oc_array_text_string_array_len = (size_t)oc_string_array_get_allocated_size(*array);
  return (oc_string_array_t *)array;
}
%}

%include "oc_rep.h"
/*******************End oc_rep.h****************************/
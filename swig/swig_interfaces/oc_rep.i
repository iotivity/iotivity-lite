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
// DOCUMENTATION workaround
%javamethodmodifiers newBuffer "/**
   * Allocate memory needed hold the OCRepresentation object.
   * <p>
   * <strong>IMPORTANT</strong>: the memory buffer needed to hold the an
   * OCRepresentation object is normally created by the IoTivity-lite framework.
   * It is unlikely that developers will ever need to call this method. Its
   * primary purpose is for testing.
   * <p>
   * <strong>NOTE</strong>: The buffer allocated is a single global buffer
   * multiple calls to this method will only result in deleteing the old buffer
   * and changing its size.  The memory allocated by the calling newBuffer is not
   * managed by the Java VM failure to call {@link  OCRep#deleteBuffer()} will result
   * in a memory leak.
   *
   * @param size the size in bytes for the allocated buffer
   *
   * @see OCRep#deleteBuffer()
   * @see OCRep#getOCRepresentaionFromRootObject()
   */
  public";
// DOCUMENTATION workaround
%javamethodmodifiers deleteBuffer "/**
   * Release the memory allocated by the call to {@link OCRep#newBuffer(int)}
   * <p>
   * <strong>NOTE</strong>: memory allocated by the call to newBuffer is not
   * managed by the Java VM failure to call deleteBuffer() will result in a memory leak.
   *
   * @see OCRep#newBuffer
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_double "/**
   * Add a double value to the cbor object
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"pi\": 3.14159
   *     }
   * </pre>
   * <p>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setDouble(root, \"pi\", 3.14);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the CborEncoder holding the double
   * @param key the name of the double value
   * @param value the double value to add to the cbor object
   */
  public";
%rename (setDouble) jni_rep_set_double;
%inline %{
/* Alt implementation of oc_rep_set_double macro*/
void jni_rep_set_double(CborEncoder * object, const char* key, double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_double(object, value);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_long "/**
   * Add an integer value to the cbor object
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"power\": 42
   *     }
   * </pre>
   * <p>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setLong(root, \"power\", 42);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the CborEncoder holding the double
   * @param key the name of the long value
   * @param value the long value to add to the cbor object
   *
   * @see OCRep#getLong(OCRepresentation, String)
   */
  public";
%rename (setLong) jni_rep_set_long;
%inline %{
/* Alt implementation of oc_rep_set_int macro */
void jni_rep_set_long(CborEncoder * object, const char* key, int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_int(object, value);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_uint "/**
   * Add an unsigned integer value to the cbor object
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"power\": 42
   *     }
   * </pre>
   * <p>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setUnsignedInt(root, \"power\", 42);
   *     OCRep.endRootObject();
   * </pre>
   * <p>
   * <strong>Note</strong>: when the cbor object is converted to an
   * OCRepresentation the data type will be encoded as OCType.OC_REP_INT. There
   * is no way for a client to know that the server sent the integer as an unsigned
   * value.
   *
   * @param object the CborEncoder object being writen too
   * @param key the name of the value
   * @param value the unsigned value to add to the cbor object
   *
   * @see OCRep#getLong(OCRepresentation, String)
   */
  public";
%rename (setUnsignedInt) jni_rep_set_uint;
%inline %{
/* Alt implementation of oc_rep_set_uint macro */
void jni_rep_set_uint(CborEncoder * object, const char* key, unsigned int value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_uint(object, value);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_boolean "/**
   * Add a boolean value to the cbor object
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"door_open\": false
   *     }
   * </pre>
   * <p>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setBoolean(root, \"door_open\", false);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the CborEncoder object the boolean object will be writen too
   * @param key the name of the boolean value
   * @param value the boolean value to add to the cbor object
   *
   * @see OCRep#getBoolean(OCRepresentation, String)
   */
  public";
%rename (setBoolean) jni_rep_set_boolean;
%inline %{
/* Alt implementation of oc_rep_set_boolean macro */
void jni_rep_set_boolean(CborEncoder * object, const char* key, bool value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_boolean(object, value);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_text_string "/**
   * Add a string value to the cbor object
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"greeting\": \"Hello, world!\"
   *     }
   * </pre>
   * <p>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setTextString(root, \"hello\", \"world\");
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the CborEncoder object the string value will be writen too
   * @param key the name of the string value
   * @param value the string value to add to the cbor object
   *
   * @see OCRep#getString(OCRepresentation, String)
   */
  public";
%rename (setTextString) jni_rep_set_text_string;
%inline %{
/* Alt implementation of oc_rep_set_text_string macro */
void jni_rep_set_text_string(CborEncoder * object, const char* key, const char* value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(object, key, strlen(key));
  g_err |= cbor_encode_text_string(object, value, strlen(value));
}
%}

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

// DOCUMENTATION workaround
%javamethodmodifiers jni_begin_root_object "/**
   * Begin the root CborEncoder object. Items can be added to the root object
   * till {@link OCRep#endRootObject()} is called
   *
   * @return CborEncoder object representing the root object
   * @see OCRep#endRootObject()
   */
  public";
%rename(beginRootObject) jni_begin_root_object;
%inline %{
/* Alt implementation of oc_rep_start_root_object macro */
CborEncoder * jni_begin_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength);
  return &root_map;
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_end_root_object "/**
   * End the root CborEncoder object. Items can no longer be added to the root
   * object.
   *
   * @see OCRep#beginRootObject()
   */
  public";
%rename(endRootObject) jni_rep_end_root_object;
%inline %{
void jni_rep_end_root_object() {
  OC_DBG("JNI: %s\n", __func__);
  oc_rep_end_root_object();
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_add_byte_string "/**
   * Add a byte string value to a parent arrayObject.
   * <p>
   * Currently the only way to make an array of byte strings is using this method
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <em>note</em>, base64 encoding used to represent binary array data
   * <pre>
   *     {
   *       \"barray\": [ \"AAECAwQFBg==\", \"AQECAwUIEyE0VYk=\", \"AAD/AAA=\" ]
   *     }
   * </pre>
   * The following code could be used:
   * <pre>
   *     byte ba0[] = {0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
   *     byte ba1[] = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x13, 0x21, 0x34, 0x55, (byte)0x89};
   *     byte ba2[] = {0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
   *                      0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42};
   *     byte ba3[] = {0x00, 0x00, (byte)0xff, 0x00, 0x00};
   *
   *     CborEncoder barray = OCRep.openArray(root, \"barray\");
   *     OCRep.addByteString(barray, ba0);
   *     OCRep.addByteString(barray, ba1);
   *     OCRep.addByteString(barray, ba2);
   *     OCRep.addByteString(barray, ba3);
   *     OCRep.closeArray(root, barray);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param arrayObject CborEncoder object already setup to hold an array using {@link OCRep#openArray(CborEncoder, String)}
   * @param value a byte array to add to the CborEncoder object
   *
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_add_text_string "/**
   * Add a text string value to a parent array object.
   * <p>
   * <strong>NOTE</strong>: This method can be used to add separate strings to
   * a cbor array object. If the strings are already in an array the
   * {@link OCRep#setStringArray(CborEncoder, String, String[])} method can be
   * used instead.
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"quotes\": [
   *       \"Do not take life too seriously. You will never get out of it alive.\",
   *       \"All generalizations are false, including this one.\",
   *       \"Those who believe in telekinetics, raise my hand.\",
   *       \"I refuse to join any club that would have me as a member.\"
   *       ]
   *     }
   * </pre>
   *
   * The following code could be used:
   * <pre>
   *     String quote0 = \"Do not take life too seriously. You will never get out of it alive.\";
   *     String quote1 = \"All generalizations are false, including this one.\";
   *     String quote2 = \"Those who believe in telekinetics, raise my hand.\";
   *     String quote3 = \"I refuse to join any club that would have me as a member.\";
   *
   *     CborEncoder quotes = OCRep.openArray(root, \"quotes\");
   *     OCRep.addByteString(quotes, quote0);
   *     OCRep.addByteString(quotes, quote1);
   *     OCRep.addByteString(quotes, quote2);
   *     OCRep.addByteString(quotes, quote3);
   *     OCRep.closeArray(root, quotes);
   *     OCRep.endRootObject();
   * </pre>
   * 
   * @param arrayObject CborEncoder object already setup to hold an array using {@link OCRep#openArray(CborEncoder, String)}
   * @param value a string to add to the CborEncoder object
   * 
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_add_double "/**
   * Add a double value to a parent array object.
   * <p>
   * <strong>NOTE</strong>: This method can be used to add separate double value to
   * a cbor array object. If the numbers are already in an array the
   * {@link OCRep#setDoubleArray(CborEncoder, String, double[])} method should be
   * used instead.
   * <p>
   * See {@link OCRep#addTextString(CborEncoder, String)} for an example similar to this method.
   *
   * @param arrayObject CborEncoder object already setup to hold an array using {@link OCRep#openArray(CborEncoder, String)}
   * @param value a double number to add to the CborEncoder array object
   * 
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   */
  public";
%rename(addDouble) jni_rep_add_double;
%inline %{
/* Alt implementation of oc_rep_add_double macro */
void jni_rep_add_double(CborEncoder *arrayObject, const double value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_double(arrayObject, value);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_add_int "/**
   * Add a long value to a parent array object.
   * <p>
   * <strong>NOTE</strong>: This method can be used to add separate long value to
   * a cbor array object. If the numbers are already in an array the
   * {@link OCRep#setLongArray(CborEncoder, String, long[])} method should be
   * used instead.
   * <p>
   * See {@link OCRep#addTextString(CborEncoder, String)} for an example similar to this method.
   *
   * @param arrayObject CborEncoder object already setup to hold an array using {@link OCRep#openArray(CborEncoder, String)}
   * @param value a long number to add to the CborEncoder array object
   *
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   */
  public";
%rename(addLong) jni_rep_add_int;
%inline %{
/* Alt implementation of oc_rep_add_int macro */
void jni_rep_add_int(CborEncoder *arrayObject, const int64_t value) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_int(arrayObject, value);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_add_boolean "/**
   * Add a boolean value to a parent array object.
   * <p>
   * <strong>NOTE</strong>: This method can be used to add separate boolean value to
   * a cbor array object. If the boolean values are already in an array the
   * {@link OCRep#setBooleanArray(CborEncoder, String, boolean[])} method should be
   * used instead.
   * <p>
   * See {@link OCRep#addTextString(CborEncoder, String)} for an example similar to this method.
   *
   * @param arrayObject CborEncoder object already setup to hold an array using {@link OCRep#openArray(CborEncoder, String)}
   * @param value a boolean value to add to the CborEncoder array object
   *
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_array "/**
   * Open a cbor array object belonging to the parent CborEncoder object.
   * <p>
   * Items can be added to the array object till closeArray is called.
   * <p>
   * Most common array types such as <tt>long</tt>, <tt>bool</tt>, <tt>double</tt>
   * and <tt>strings</tt> have specific macros for handling those array types.
   * This method will mostly be used to make arrays where the length is unknown
   * ahead of time or to make an array of other objects.
   *
   * For and example of this method being used see:
   * <ul>
   * <li>{@link OCRep#addTextString(CborEncoder, String)}</li>
   * <li>{@link OCRep#addByteString(CborEncoder, byte[])}</li>
   * <li>{@link OCRep#objectArrayBeginItem(CborEncoder)}</li>
   * </ul>
   *
   * @param parent the CborEncoder object that will hold the array object
   * @param key the name of the array object
   *
   * @return the CborEncoder representing the array object
   *
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   */
  public";
%rename(openArray) jni_rep_set_array;
%inline %{
/* Alt implementation of oc_rep_set_array macro */
CborEncoder * jni_rep_set_array(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return jni_rep_start_array(parent);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_close_array "/**
   * Close the array object.
   * <p>
   * No additional items can be added to the array after this is called.
   *
   * @param object the parent CborEncoder object same object passed in {@link OCRep#openArray(CborEncoder, String)}
   * @param arrayObject the array object returned from {@link OCRep#openArray(CborEncoder, String)}
   *
   * @see OCRep#openArray(CborEncoder, String)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_object_array_start_item "/**
   * Begin a cbor object for an array of cbor objects.
   * <p>
   * <strong>NOTE</strong> Object Array is a misnomer, it is represented in
   * code as a linked list of OCRepresentation objects, it has the same
   * limitations as a singly-linked-list.
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"space2001\": [
   *                     {\"name\": \"Dave Bowman\", \"job\": \"astronaut\"},
   *                     {\"name\": \"Frank Poole\", \"job\": \"astronaut\"},
   *                     {\"name\": \"Hal 9000\", \"job\": \"AI computer\"}
   *                     ]
   *     }
   * </pre>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     CborEncoder space2001 = OCRep.openArray(root, \"space_2001\");
   *
   *     CborEncoder arrayItemObject;
   *
   *     arrayItemObject = OCRep.objectArrayBeginItem(space2001);
   *     OCRep.setTextString(arrayItemObject, \"name\", \"Dave Bowman\");
   *     OCRep.setTextString(arrayItemObject, \"job\", \"astronaut\");
   *     OCRep.objectArrayEndItem(space2001, arrayItemObject);
   *
   *     arrayItemObject = OCRep.objectArrayBeginItem(space2001);
   *     OCRep.setTextString(arrayItemObject, \"name\", \"Frank Poole\");
   *     OCRep.setTextString(arrayItemObject, \"job\", \"astronaut\");
   *     OCRep.objectArrayEndItem(space2001, arrayItemObject);
   *
   *     arrayItemObject = OCRep.objectArrayBeginItem(space2001);
   *     OCRep.setTextString(arrayItemObject, \"name\", \"Hal 9000\");
   *     OCRep.setTextString(arrayItemObject, \"job\", \"AI computer\");
   *     OCRep.objectArrayEndItem(space2001, arrayItemObject);
   *
   *     OCRep.closeArray(root, space2001);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param arrayObject a CborEncoder object returned from
   *                    {@link OCRep#openArray(CborEncoder, String)}
   *
   * @return CborEncoder object that can be added to till
   *         {@link OCRep#objectArrayEndItem(CborEncoder, CborEncoder)} is
   *         called
   *
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   * @see OCRep#objectArrayEndItem(CborEncoder, CborEncoder)
   */
  public";
%rename (objectArrayBeginItem) jni_rep_object_array_start_item;
%inline %{
/* Alt implementation of oc_rep_object_array_start_item macro */
CborEncoder * jni_rep_object_array_start_item(CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  return jni_rep_start_object(arrayObject);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_object_array_end_item "/**
   * End the cbor object for the array of cbor objects.
   * <p>
   * See {@link OCRep#objectArrayBeginItem(CborEncoder)} for a sample code
   * showing how to use this function
   * 
   * @param parentArrayObject a CborEncoder array object created using
   *                          {@link OCRep#openArray(CborEncoder, String)}
   * @param arrayObject the object array item being ended
   */
  public";
%rename (objectArrayEndItem) jni_rep_object_array_end_item;
%inline %{
/* Alt implementation of oc_rep_object_array_end_item macro */
void jni_rep_object_array_end_item(CborEncoder *parentArrayObject, CborEncoder *arrayObject) {
  OC_DBG("JNI: %s\n", __func__);
  jni_rep_end_object(parentArrayObject, arrayObject);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_open_object "  /**
   * Open a cbor object belonging to parent cbor object.
   * <p>
   * Items can then be added to the object till
   * {@link OCRep#closeObject(CborEncoder, CborEncoder)} is called.
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *         \"my_object\": {
   *             \"a\": 1
   *             \"b\": false
   *             \"c\": \"three\"
   *         }
   *     }
   * </pre>
   * The following code could be used:
   * <pre>
   *     CborEncoder root = OCRep.beginRootObject();
   *     CborEncoder myObject = OCRep.openObject(root, \"my_object\");
   *     OCRep.setLong(myObject, \"a\", 1);
   *     OCRep.setBoolean(myObject, \"b\", false);
   *     OCRep.setTextString(myObject, \"c\", \"three\");
   *     OCRep.closeObject(root, myObject);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param parent the parent CborEncoder object
   * @param key the name of the CborEncoder object being opened
   *
   * @return the CborEncoder object to be filled
   *
   * @see OCRep#closeObject(CborEncoder, CborEncoder)
   */
  public";
%rename(openObject) jni_rep_open_object;
%inline %{
/* Alt implementation of oc_rep_set_object macro */
CborEncoder * jni_rep_open_object(CborEncoder *parent, const char* key) {
  OC_DBG("JNI: %s\n", __func__);
  g_err |= cbor_encode_text_string(parent, key, strlen(key));
  return jni_rep_start_object(parent);
}
%}

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_close_object "/**
   * Close the object.
   * <p>
   * No additional items can be added to the object after this is called.
   * 
   * @param parent the parent cbor object
   * @param object the object being closed
   * 
   * @see OCRep#openObject(CborEncoder, String)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_long_array "/**
   * Add a integer (Long) array to the cbor object.
   * <p>
   * Example:
   * <p>
   * To build an object with the following cbor value
   * <pre>
   *     {
   *       \"fibonacci\": [ 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 ]
   *     }
   * </pre>
   * The following code could be used:
   *<pre>
   *    long fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89};
   *    CborEncoder root = OCRep.beginRootObject();
   *    OCRep.setLongArray(root, \"fibonacci\", fib);
   *    OCRep.endRootObject();
   * </pre>
   * @param object the cbor object the array belongs to
   * @param key the name of the long array
   * @param values an array of long integers
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_bool_array "/**
   * Add a boolean array to the cbor object.
   * <p>
   * Example:
   * <p>
   * To build an object with the following cbor value
   * <pre>
   *     {
   *       \"flip\": [ false, false, true, false, false ]
   *     }
   * </pre>
   * The following code could be used:
   * <pre>
   *     boolean flip[] = {false, false, true, false, false };
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setBooleanArray(root, \"flip\", flip)
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the cbor object the array belongs to
   * @param key the name of the boolean array
   * @param values an array of boolean integers
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_set_double_array "/**
   * Add a double array to the cbor object.
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"math_constants\": [ 3.14159, 2.71828, 1.414121, 1.61803 ]
   *     }
   * </pre>
   * The following code could be used:
   * <pre>
   *     double math_constants[] = { 3.14159, 2.71828, 1.414121, 1.61803 };
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setDoubleArray(root, \"math_constants\", mathConstants);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the cbor object the array belongs to
   * @param key the name of the boolean array
   * @param values an array of boolean integers
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_rep_set_string_array "/**
   * Add a string array to the cbor object
   * <p>
   * Example:
   * <p>
   * To build the an object with the following cbor value
   * <pre>
   *     {
   *       \"lorem_ipsum\" : [\"Lorem\", \"ipsum\", \"dolor\", \"sit\", \"amet\",
   *                        \"consectetur\", \"adipiscing\", \"elit.\", \"Sed\",
   *                        \"nec\", \"feugiat\", \"odio.\", \"Donec.\"]
   *     }
   * </pre>
   * The following code could be used:
   * <pre>
   *     String lorem_ipsum[] = {\"Lorem\", \"ipsum\", \"dolor\", \"sit\", \"amet\",
   *                             \"consectetur\", \"adipiscing\", \"elit.\", \"Sed\",
   *                             \"nec\", \"feugiat\", \"odio.\", \"Donec.\"};
   *     CborEncoder root = OCRep.beginRootObject();
   *     OCRep.setStringArray(root, \"lorem_ipsum\", lorem_ipsum);
   *     OCRep.endRootObject();
   * </pre>
   *
   * @param object the cbor object the array belongs to
   * @param key the name of the string array
   * @param values an array of strings
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_rep_from_root_object "/**
   * Convert the internal <tt>root</tt> CborEncoder object to an OCRepresentation object
   * <p>
   * This method should only be called after calling {@link OCRep#endRootObject()}
   * <p>
   * <strong>NOTE</strong>: This method is not expected to be used in typically
   * use cases.  This method is almost exclusively intended for unit testing code.
   *
   * @return an OCRepresentation object converted from the internal root CborEncoder object
   *
   * @see OCRep#newBuffer(int)
   * @see OCRep#deleteBuffer()
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_cbor_errno "  /**
   * Called after any <tt>set*</tt>, <tt>start*</tt>, <tt>begin*</tt>,
   * <tt>end*</tt>, <tt>add*</tt>, <tt>open*</tt>, and <tt>close*</tt> methods
   * to check if an error occurred while executing.
   * <p>
   * If the value returned is anything other than 0 then one of the
   * methods calls failed.
   * <p>
   * <strong>Note</strong> the error returned is not automatically cleared. To
   * clear the error call {@link OCRep#clearCborErrno()}
   *
   * @return error, any value other than 0 means an error has occurred
   *
   * @see OCRep#clearCborErrno()
   */
  public";
%ignore oc_rep_get_cbor_errno;
%rename(getCborErrno) jni_rep_get_cbor_errno;
%inline %{
int jni_rep_get_cbor_errno() {
  return (int)oc_rep_get_cbor_errno();
}
%}

//method exposed to Java APIs since we don't expose direct access to g_err
// DOCUMENTATION workaround
%javamethodmodifiers clearCborErrno "/**
   * clear the cbor error number back to 0
   *
   * @see OCRep#getCborErrno()
   */
  public";
%inline %{
void clearCborErrno() {
  g_err = CborNoError;
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_long "/**
   * Read a long integer from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     Long ultimate_answer_out = OCRep.getLong(rep, \"ultimat_answer\");
   *     if (outValue != null) {
   *       System.out.println(\"The ultimate answer is : \" +
   *                           ultimate_answer_out.longValue());
   *     }
   * </pre>
   *
   * @param rep the OCRepresentation to read the long value from
   * @param key the key name for the long integer value
   * 
   * @return the Long value, or null if key or value is not found
   * 
   * @see OCRep#setLong(CborEncoder, String, long)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_bool "/**
   * Read a boolean value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     bool door_open_flag = false;
   *     Boolean doorOpen = OCRep.getBoolean(rep, \"door_open_flag\");
   *     if( null != doorOpen ) {
   *       System.out.println(\"The door is open : \" +  doorOpen);
   *     }
   * </pre>
   *
   * @param rep the OCRepresentation to read the boolean value from
   * @param key the key name for the boolean value
   *
   * @return the Boolean value, or null if key or value is not found
   *
   * @see OCRep#setBoolean(CborEncoder, String, boolean)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_double "  /**
   * Read a double value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     Double pi_out = OCRep.getDouble(rep, \"pi\");
   *     if( pi_out != null) {
   *         System.out.println(\"The the value for 'pi' is : \" + pi_out);
   *     }
   * </pre>
   *
   * @param rep the OCRepresentation to read the double value from
   * @param key the key name for the double value
   *
   * @return the Double value, or null if key or value is not found
   *
   * @see OCRep#setDouble(CborEncoder, String, double)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_byte_string "/**
   * Read a byte string value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     byte byteStringOut[] = OCRep.getByteString(rep, \"byte_string_key\");
   *     if( null != byteStringOut) {
   *         // byte_string_out can be used
   *     }
   * </pre>
   *
   * @param rep the OCRepresentation to read byte string value from
   * @param key the key name for the byte string value
   *
   * @return the byte array, or null if key or value is not found
   *
   * @see OCRep#setByteString(CborEncoder, String, byte[])
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_string "/**
   * Read a text string value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     String greetingOut = OCRep.getString(rep, \"greeting\");
   *     if( null != greetingOut )
   *     {
   *       System.out.println(greetingOut);
   *     }
   * </pre>
   *
   * @param rep the OCRepresentation to read string value from
   * @param key the key name for the string value
   * 
   * @return the string, or null if key or value is not found
   *
   * @see OCRep#setTextString(CborEncoder, String, String)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_long_array "/**
   * Read an long integer array value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     long fibOut[] = OCRep.getLongArray(rep, \"fibonacci\");
   *     if( null != fibOut) {
   *         // the fibOut array can now be used
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the integer array value from
   * @param key the key name for the integer array value
   *
   * @return an long integer array, or null if key or value is not found
   * 
   * @see OCRep#setLongArray(CborEncoder, String, long[])
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_bool_array "/**
   * Read an boolean array value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     boolean flipOut[] = OCRep.getBooleanArray(rep, \"flip\");
   *     if( null != flipOut) {
   *         // flipOut can now be used
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the boolean array value from
   * @param key the key name for the boolean array value
   *
   * @return a boolean array, or null if key or value is not found
   *
   * @see OCRep#setBooleanArray(CborEncoder, String, boolean[])
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_double_array "/**
   * Read an double array value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     double mathConstantsOut[] = OCRep.getDoubleArray(rep, \"math_constants\")
   *     if( null != mathConstantsOut) {
   *         // mathConstantsOut can now be used
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the double array value from
   * @param key the key name for the double array value
   *
   * @return a double array, or null if key or value is not found
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_byte_string_array "/**
   * Read an byte string array value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     byte outValue[][] = OCRep.getByteStringArray(rep, \"barray\");
   *     if( null != outValue ) {
   *       // access outValue like any array of byte arrays
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the byte string array value from
   * @param key the key name for the double array value
   *
   * @return an array of byte arrays, or null if key or value is not found
   *
   * @see OCRep#addByteString(CborEncoder, byte[])
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_string_array "/**
   * Read a string array value from an <tt>OCRepresentation</tt>
   * <p>
   * Example:
   * <pre>
   *     String quotesOut[] = OCRep.getStringArray(rep, \"quotes\");
   *     if(null != quotesOut) {
   *         System.out.println(\"Quotes :\");
   *         for (String q : quotesOut) {
   *             System.out.println(q);
   *         }
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the string array value from
   * @param key the key name for the double array value
   *
   * @return an array of Strings, or null if key or value is not found
   * 
   * @see OCRep#setStringArray(CborEncoder, String, String[])
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_object "/**
   * Read a object value from an <tt>OCRepresentation</tt>`
   * <p>
   * Example:
   * <pre>
   *     OCRepresentation myObjectOut = OCRep.getObject(rep, \"my_object\");
   *     if (null != myObjectOut) {
   *         Long a = OCRep.getLong(myObjectOut, \"a\");
   *         if (null != a) {
   *             System.out.println(\"a :\" + a);
   *         Boolean b = OCRep.getBoolean(myObjectOut, \"b\");
   *         if (null != b) {
   *             System.out.println(\"b :\" + b);
   *         String c = OCRep.getString(myObjectOut, \"c\");
   *         if (null != c) {
   *             System.out.println(\"c :\" + c);
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the OCRepresentation object value from
   * @param key the key name for the object value
   *
   * @return the OCRepresentation object, or null if key or value is not found
   *
   * @see OCRep#beginObject(CborEncoder)
   * @see OCRep#endObject(CborEncoder, CborEncoder)
   */
  public";
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

// DOCUMENTATION workaround
%javamethodmodifiers jni_rep_get_object_array "/**
   * Read an object array value from an <tt>OCRepresentation</tt>
   * <p>
   * <strong>Important</strong> Calling the returned value an array is a
   * misnomer.  The value actually returned is a linked list of <tt>OCRepresentation</tt>
   * objects. The linked list must be walked to see each item in the object array.
   * <p>
   * Example:
   * <pre>
   *     OCRepresentation space2001Out = OCRep.getObjectArray(rep, \"space_2001\");
   *
   *     String nameOut;
   *     String jobOut;
   *     while (null != space2001out) { 
   *         nameOut = OCRep.getString(space2001Out.getValue().getObject(), \"name\");
   *         jobOut = OCRep.getString(space2001Out.getValue().getObject(), \"job\");
   *         System.out.println(\"name : \" + nameOut + \" Job : \" + jobOut);
   *
   *         space2001Out = space2001Out.getNext();
   *     }
   * </pre>
   *
   * @param rep OCRepresentation to read the OCRepresentation array object value from
   * @param key key the key name for the object array value
   *
   * @return the OCRepresentation object array, or null if key or value is not found
   *
   * @see OCRep#openArray(CborEncoder, String)
   * @see OCRep#closeArray(CborEncoder, CborEncoder)
   * @see OCRep#objectArrayBeginItem(CborEncoder)
   * @see OCRep#objectArrayEndItem(CborEncoder, CborEncoder)
   */
  public";
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

%newobject jni_rep_to_json;
%ignore oc_rep_to_json;
%rename(toJSON) jni_rep_to_json;
%inline %{
char *jni_rep_to_json(oc_rep_t *rep, bool prettyPrint)
{
  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, prettyPrint);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, prettyPrint);
  return json;
}
%}


%include "oc_rep.h"
/*******************End oc_rep.h****************************/
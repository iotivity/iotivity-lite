/*
// Copyright (c) 2016-2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

/**
  @file
*/
#ifndef OC_REP_H
#define OC_REP_H

#include "deps/tinycbor/src/cbor.h"
#include "oc_helpers.h"
#include "util/oc_memb.h"
#include <oc_config.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

extern CborEncoder g_encoder, root_map, links_array;
extern int g_err;

/**
 * Initialize the buffer used to hold the cbor encoded data
 *
 * Unlikely to be used by outside the IoTivity-lite library.
 *
 * @param[in] payload  pointer to payload buffer
 * @param[in] size     size of the payload buffer
 */
void oc_rep_new(uint8_t *payload, int size);

/**
 * Get the size of the cbor encoded data.
 *
 * This can be used to check if the cbor encode data will fit inside the payload
 * buffer. If the payload buffer is too small -1 is returned.
 *
 * @return
 *  - the size of the cbor encoded data.
 *  - returns -1 if the cbor encoded data will not fit in the oc_rep_t payload
 *
 * @see oc_rep_new
 */
int oc_rep_get_encoded_payload_size(void);

/**
 * Get the buffer pointer at the start of the encoded cbor data.
 *
 * This is used when parsing the encoded cbor data to an oc_rep_t. It is
 * unlikely
 * to be used outside the IoTivity-lite library.
 *
 * @return pointer to the start of the cbor encoded buffer
 *
 * @see oc_parse_rep
 */
const uint8_t *oc_rep_get_encoder_buf(void);

/**
 * @brief Encode raw data, as if it was already encoded.
 * 
 * @param data Pointer to data to be encoded. Will be copied into the global buffer.
 * @param len Length of data.
 */
void oc_rep_encode_raw(const uint8_t* data, size_t len);

/**
 * Get a pointer to the cbor object with the given `name`
 *
 * @return cbor object pointer
 */
#define oc_rep_object(name) &name##_map

/**
 * Get a pointer to the cbor array object with the given `name`
 *
 * @return cbor array object pointer
 */
#define oc_rep_array(name) &name##_array

/**
 * Add a double `value` to the cbor `object` under the `key` name
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "pi": 3.14159
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_begin_root_object();
 *     oc_rep_set_double(root, pi, 3.14159);
 *     oc_rep_end_root_object();
 * ~~~
 */
#define oc_rep_set_double(object, key, value)                                  \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_double(&object##_map, value);                         \
  } while (0)

/**
 * Add an integer `value` to the cbor `object` under the `key` name
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "power": 42
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_begin_root_object();
 *     oc_rep_set_int(root, power, 42);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_get_int
 */
#define oc_rep_set_int(object, key, value)                                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_int(&object##_map, value);                            \
  } while (0)

/**
 * Add an unsigned integer `value` to the cbor `object` under the `key` name
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "power": 42
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_begin_root_object();
 *     oc_rep_set_uint(root, power, 42);
 *     oc_rep_end_root_object();
 * ~~~
 * Note: when the cbor object is converted to a oc_rep_the data
 * type will be encoded as an OC_REP_INT. There is no way for
 * a client to know that the server sent the INT as an unsigned
 * value.
 */
#define oc_rep_set_uint(object, key, value)                                    \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_uint(&object##_map, value);                           \
  } while (0)

/**
 * Add an boolean `value` to the cbor `object` under the `key` name
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "door_open": false
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_begin_root_object();
 *     oc_rep_set_boolean(root, door_open, false);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_get_bool
 */
#define oc_rep_set_boolean(object, key, value)                                 \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_boolean(&object##_map, value);                        \
  } while (0)

/**
 * Add an string `value` to the cbor `object` under the `key` name
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "greeting": "Hello, world!"
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_begin_root_object();
 *     oc_rep_set_text_string(root, greeting, "Hello, world!");
 *     oc_rep_end_root_object();
 * ~~~
 */
#define oc_rep_set_text_string(object, key, value)                             \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    if ((const char *)value != NULL) {                                         \
      g_err |= cbor_encode_text_string(&object##_map, value, strlen(value));   \
    } else {                                                                   \
      g_err |= cbor_encode_text_string(&object##_map, "", 0);                  \
    }                                                                          \
  } while (0)

/**
 * Add an byte array `value` to the cbor `object` under the `key` name
 * Example:
 *
 * To build the an object with the following cbor value
 * Note using base64 encoding in the following example string.
 *
 *     {
 *       "byte_string_key": "AAECAwQF"
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     // the following bytes equal "AAECAwQF" when base64 encoded
 *     uint8_t byte_string[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
 *     oc_rep_begin_root_object();
 *     oc_rep_set_byte_string(root, byte_string_key, byte_string,
 * sizeof(byte_string));
 *     oc_rep_end_root_object();
 * ~~~
 */
#define oc_rep_set_byte_string(object, key, value, length)                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    g_err |= cbor_encode_byte_string(&object##_map, value, length);            \
  } while (0)

/**
 * This macro has been replaced with oc_rep_begin_array
 *
 * @see oc_rep_start_array
 * @see oc_rep_end_array
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 */
#define oc_rep_start_array(parent, name) oc_rep_begin_array(parent, name)

/**
 * This macro is unlikely to be used by outside the IoTivity-lite library.
 *
 * Begin a cbor array object with `name` belonging to `parent` object.  Items
 * can then be added to the array till oc_rep_end_array is called.
 *
 * Since no functions exist to retrieve an array object without a key it is
 * unlikely this macro will be used without using oc_rep_set_key first. Most
 * likely oc_rep_open_array will be used to create an array object with a key.
 *
 * Example:
 * To build the an object with the following cbor value
 *
 *     {
 *       "fibonacci": [ 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     int fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
 *     oc_rep_start_root_object();
 *     oc_rep_set_key(oc_rep_object(root), "fibonacci");
 *     oc_rep_begin_array(oc_rep_object(root), fibonacci);
 *     for(size_t i = 0; i < (sizeof(fib)/ sizeof(fib[0])); i++) {
 *         oc_rep_add_int(fibonacci, fib[i]);
 *     }
 *     oc_rep_end_array(oc_rep_object(root), fibonacci);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * See oc_rep_add_int to see an example using the recommended way to do the same
 * thing using `oc_rep_open_array` and `oc_rep_close_array` instead.
 *
 * @see oc_rep_set_key
 * @see oc_rep_end_array
 * @see oc_rep_add_byte_string
 * @see oc_rep_add_text_string
 * @see oc_rep_add_double
 * @see oc_rep_add_int
 * @see oc_rep_add_boolean
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 */
#define oc_rep_begin_array(parent, name)                                       \
  do {                                                                         \
    CborEncoder name##_array;                                                  \
  g_err |=                                                                     \
    cbor_encoder_create_array(parent, &name##_array, CborIndefiniteLength)

/**
 * End the array object.  No additional items can be added to the array after
 * this is called.
 *
 * @see oc_rep_begin_array
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 */
#define oc_rep_end_array(parent, name)                                         \
  g_err |= cbor_encoder_close_container(parent, &name##_array);                \
  }                                                                            \
  while (0)

#define oc_rep_start_links_array() oc_rep_begin_links_array()

#define oc_rep_begin_links_array()                                             \
  g_err |=                                                                     \
    cbor_encoder_create_array(&g_encoder, &links_array, CborIndefiniteLength)

#define oc_rep_end_links_array()                                               \
  g_err |= cbor_encoder_close_container(&g_encoder, &links_array)

/**
 * This macro has been replaced with oc_rep_begin_root_object
 *
 * @see oc_rep_begin_root_object
 * @see oc_rep_end_root_object
 */
#define oc_rep_start_root_object() oc_rep_begin_root_object()

/**
 * Begin the root object. Items can be added to the root object till
 * oc_rep_end_root_object is called
 *
 * @see oc_rep_end_root_object
 */
#define oc_rep_begin_root_object()                                             \
  g_err |= cbor_encoder_create_map(&g_encoder, &root_map, CborIndefiniteLength)

/**
 * End the root object. Items can no longer be added to the root object.
 *
 * @see oc_rep_begin_root_object
 */
#define oc_rep_end_root_object()                                               \
  g_err |= cbor_encoder_close_container(&g_encoder, &root_map)

/**
 * Add a byte string `value` to a `parent` array. Currently the only way to make
 * an array of byte strings is using this macro
 *
 * Example:
 *
 * To build the an object with the following cbor value
 * note, base64 encoding used to represent binary array data
 *
 *     {
 *       "barray": [ "AAECAwQFBg==", "AQECAwUIEyE0VYk=", "AAD/AAA=" ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     uint8_t ba1[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
 *     uint8_t ba2[] = {0x01, 0x01, 0x02, 0x03, 0x05, 0x08,
 *                      0x13, 0x21, 0x34, 0x55, 0x89};
 *     uint8_t ba3[] = {0x00, 0x00, 0xff, 0x00, 0x00};
 *     // add values to root object
 *     oc_rep_start_root_object();
 *     oc_rep_open_array(root, barray);
 *     oc_rep_add_byte_string(barray, ba1, sizeof(ba1));
 *     oc_rep_add_byte_string(barray, ba2, sizeof(ba2));
 *     oc_rep_add_byte_string(barray, ba3, sizeof(ba3));
 *     oc_rep_close_array(root, barray);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 */
#define oc_rep_add_byte_string(parent, value, value_len)                       \
  g_err |= cbor_encode_byte_string(&parent##_array, value, value_len)

#define oc_rep_set_value_byte_string(parent, value, value_len)                 \
  g_err |= cbor_encode_byte_string(&parent##_map, value, value_len)

/**
 * Add a text string `value` to a `parent` array. Currently the only way to make
 * an array of text strings is using this macro
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "quotes": [
 *       "Do not take life too seriously. You will never get out of it alive.",
 *       "All generalizations are false, including this one.",
 *       "Those who believe in telekinetics, raise my hand.",
 *       "I refuse to join any club that would have me as a member."
 *       ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     const char* str0 = "Do not take life too seriously. You will never get
 * out of it alive.";
 *     const char* str1 = "All generalizations are false, including this one.";
 *     const char* str2 = "Those who believe in telekinetics, raise my hand.";
 *     const char* str3 = "I refuse to join any club that would have me as a
 * member.";
 *
 *     // add values to root object
 *     oc_rep_start_root_object();
 *     oc_rep_open_array(root, quotes);
 *     oc_rep_add_text_string(quotes, str0);
 *     oc_rep_add_text_string(quotes, str1);
 *     oc_rep_add_text_string(quotes, str2);
 *     oc_rep_add_text_string(quotes, str3);
 *     oc_rep_close_array(root, quotes);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 */
#define oc_rep_add_text_string(parent, value)                                  \
  do {                                                                         \
    if ((const char *)value != NULL) {                                         \
      g_err |= cbor_encode_text_string(&parent##_array, value, strlen(value)); \
    } else {                                                                   \
      g_err |= cbor_encode_text_string(&parent##_array, "", 0);                \
    }                                                                          \
  } while (0)

#define oc_rep_set_value_text_string(parent, value)                            \
  do {                                                                         \
    if ((const char *)value != NULL) {                                         \
      g_err |= cbor_encode_text_string(&parent##_map, value, strlen(value));   \
    } else {                                                                   \
      g_err |= cbor_encode_text_string(&parent##_map, "", 0);                  \
    }                                                                          \
  } while (0)

/**
 * Add an `double` `value` to a `parent` array. Using oc_rep_add_double can be
 * useful when the number of items is calculated at run time or for some reason
 * is not know till after calling oc_rep_open_array.
 *
 * If the size of the `double` array is already known `oc_rep_set_double_array`
 * should be used.
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "math_constants": [ 3.14159, 2.71828, 1.414121, 1.61803 ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     double math_constants[] = { 3.14159, 2.71828, 1.414121, 1.61803 };
 *     oc_rep_start_root_object();
 *     oc_rep_open_array(root, math_constants);
 *     for(size_t i = 0; i < (sizeof(math_constants)/
 * sizeof(math_constants[0])); i++) {
 *         oc_rep_add_double(math_constants, math_constants[i]);
 *     }
 *     oc_rep_close_array(root, math_constants);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 * @see oc_rep_set_double_array
 */
#define oc_rep_add_double(parent, value)                                       \
  g_err |= cbor_encode_double(&parent##_array, value)

#define oc_rep_set_value_double(parent, value)                                 \
  g_err |= cbor_encode_double(&parent##_map, value)

/**
 * Add an `int` `value` to a `parent` array. Using oc_rep_add_int can be useful
 * when the number of items is calculated at run time or for some reason it not
 * know till after calling oc_rep_open_array.
 *
 * If the size of the `int` array is already known `oc_rep_set_int_array` should
 * be used.
 *
 * Example:
 * To build the an object with the following cbor value
 *
 *     {
 *       "fibonacci": [ 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     int fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
 *     oc_rep_start_root_object();
 *     oc_rep_open_array(root, fibonacci);
 *     for(size_t i = 0; i < (sizeof(fib)/ sizeof(fib[0])); i++) {
 *         oc_rep_add_int(fibonacci, fib[i]);
 *     }
 *     oc_rep_close_array(root, fibonacci);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 * @see oc_rep_set_int_array
 */
#define oc_rep_add_int(parent, value)                                          \
  g_err |= cbor_encode_int(&parent##_array, value)
#define oc_rep_set_value_int(parent, value)                                    \
  g_err |= cbor_encode_int(&parent##_map, value)

/**
 * Add an `bool` `value` to a `parent` array. Using oc_rep_add_boolean can be
 * used when the number of items is calculated at run time or for some reason it
 * is not know till after calling oc_rep_open_array.
 *
 * If the size of the `bool` array is already known `oc_rep_set_bool_array`
 * should
 * be used.
 *
 * Example:
 * To build the an object with the following cbor value
 *
 *     {
 *       "flip": [ false, false, true, false, false ]
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     bool flip[] = {false, false, true, false, false };
 *     oc_rep_start_root_object();
 *     oc_rep_open_array(root, flip);
 *     for(size_t i = 0; i < (sizeof(flip)/ sizeof(flip[0])); i++) {
 *         oc_rep_add_boolean(flip, flip[i]);
 *     }
 *     oc_rep_close_array(root, flip);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 * @see oc_rep_set_bool_array
 */
#define oc_rep_add_boolean(parent, value)                                      \
  g_err |= cbor_encode_boolean(&parent##_array, value)
#define oc_rep_set_value_boolean(parent, value)                                \
  g_err |= cbor_encode_boolean(&parent##_map, value)

/**
 * End users are very unlikely to use this macro.
 *
 * This will add a `key` to a `parent` object.
 *
 * This is almost always followed by oc_rep_begin_array to build an array when
 * the number of items being placed in the array are not known before the end of
 * the array.
 *
 * See oc_rep_begin_array for example code
 *
 * @see oc_rep_begin_array
 */
#define oc_rep_set_key(parent, key)                                            \
  if ((const char *)key != NULL)                                               \
  g_err |= cbor_encode_text_string(parent, key, strlen(key))

/**
 * This macro has been replaced with oc_rep_open_array
 *
 * @see oc_rep_open_array
 * @see oc_rep_close_array
 */
#define oc_rep_set_array(object, key) oc_rep_open_array(object, key)

/**
 * Open a cbor array object belonging to `parent` object under the `key` name.
 * Items can then be added to the array till oc_rep_close_array is called.
 *
 * Most common array types such as `int`, `bool`, `double` and `strings` have
 * specific macros for handling those array types.  This macro will mostly be
 * used to make arrays where the length is unknown ahead of time or to make
 * an array of other objects.
 *
 * For and example of this macro being used see oc_rep_object_array_begin_item.
 *
 * @see oc_rep_close_array
 */
#define oc_rep_open_array(parent, key)                                         \
  g_err |= cbor_encode_text_string(&parent##_map, #key, strlen(#key));         \
  oc_rep_begin_array(&parent##_map, key)

/**
 * Close the array object.  No additional items can be added to the array after
 * this is called.
 *
 * @see oc_rep_open_array
 */
#define oc_rep_close_array(parent, key) oc_rep_end_array(&parent##_map, key)

/**
 * This macro has been replaced with oc_rep_begin_object
 *
 * @see oc_rep_begin_object
 * @see oc_rep_end_object
 */
#define oc_rep_start_object(parent, key) oc_rep_begin_object(parent, key)

#define oc_rep_begin_object(parent, key)                                       \
  do {                                                                         \
    CborEncoder key##_map;                                                     \
  g_err |= cbor_encoder_create_map(parent, &key##_map, CborIndefiniteLength)

#define oc_rep_end_object(parent, key)                                         \
  g_err |= cbor_encoder_close_container(parent, &key##_map);                   \
  }                                                                            \
  while (0)

/**
 * This macro has been replaced with oc_rep_object_array_begin_item
 *
 * @see oc_rep_object_array_begin_item
 * @see oc_rep_object_array_end_item
 */
#define oc_rep_object_array_start_item(key) oc_rep_object_array_begin_item(key)

/**
 * Begin a cbor object for an array of cbor objects. The `key` is the name of
 * the array object.
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "space2001": [
 *                     {"name": "Dave Bowman", "job": "astronaut"},
 *                     {"name": "Frank Poole", "job": "astronaut"},
 *                     {"name": "Hal 9000", "job": "AI computer"}
 *                     ]
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_start_root_object();
 *     oc_rep_set_array(root, space2001);
 *
 *     oc_rep_object_array_begin_item(space2001);
 *     oc_rep_set_text_string(space2001, name, "Dave Bowman");
 *     oc_rep_set_text_string(space2001, job, "astronaut");
 *     oc_rep_object_array_end_item(space2001);
 *
 *     oc_rep_object_array_begin_item(space2001);
 *     oc_rep_set_text_string(space2001, name, "Frank Poole");
 *     oc_rep_set_text_string(space2001, job, "astronaut");
 *     oc_rep_object_array_end_item(space2001);
 *
 *     oc_rep_object_array_begin_item(space2001);
 *     oc_rep_set_text_string(space2001, name, "Hal 9000");
 *     oc_rep_set_text_string(space2001, job, "AI computer");
 *     oc_rep_object_array_end_item(space2001);
 *
 *     oc_rep_close_array(root, space2001);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_object_array_end_item
 */
#define oc_rep_object_array_begin_item(key)                                    \
  oc_rep_begin_object(&key##_array, key)

/**
 * End the cbor object for the `key` array of cbor objects.
 */
#define oc_rep_object_array_end_item(key) oc_rep_end_object(&key##_array, key)

/**
 * This macro has been replaced with oc_rep_open_object
 *
 * @see oc_rep_open_object
 * @see oc_rep_close_object
 */
#define oc_rep_set_object(object, key) oc_rep_open_object(object, key)

/**
 * Open a cbor object belonging to `parent` object under the `key` name.
 * Items can then be added to the array till oc_rep_close_object is called.
 *
 *Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *         "my_object": {
 *             "a": 1
 *             "b": false
 *             "c": "three"
 *         }
 *     }
 *
 * The following code could be used:
 * ~~~{.c}
 *     oc_rep_start_root_object();
 *     oc_rep_set_object(root, my_object);
 *     oc_rep_set_int(my_object, a, 1);
 *     oc_rep_set_boolean(my_object, b, false);
 *     oc_rep_set_text_string(my_object, c, "three");
 *     oc_rep_close_object(root, my_object);
 *     oc_rep_end_root_object();
 * ~~~
 *
 * @see oc_rep_close_object
 */
#define oc_rep_open_object(parent, key)                                        \
  g_err |= cbor_encode_text_string(&parent##_map, #key, strlen(#key));         \
  oc_rep_begin_object(&parent##_map, key)

/**
 * Close the object. No additional items can be added to the object after
 * this is called.
 *
 * @see oc_rep_open_object
 */
#define oc_rep_close_object(parent, key) oc_rep_end_object(&parent##_map, key)

/**
 * Add an integer array with `values` of `length` to the cbor `object` under the
 * `key` name.
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "fibonacci": [ 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     int fib[] = {1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
 *     oc_rep_start_root_object();
 *     oc_rep_set_int_array(root,
 *                          fibonacci,
 *                          fib,
 *                          (int)(sizeof(fib)/ sizeof(fib[0]) ) );
 *     oc_rep_end_root_object();
 * ~~~
 */
#define oc_rep_set_int_array(object, key, values, length)                      \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |=                                                                   \
      cbor_encoder_create_array(&object##_map, &key##_value_array, length);    \
    int i;                                                                     \
    for (i = 0; i < length; i++) {                                             \
      g_err |= cbor_encode_int(&key##_value_array, values[i]);                 \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

/**
 * Add a boolean array with `values` of `length` to the cbor `object` under the
 * `key` name.
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "flip": [ false, false, true, false, false ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     bool flip[] = {false, false, true, false, false };
 *     oc_rep_start_root_object();
 *     oc_rep_set_bool_array(root,
 *                           flip,
 *                           flip,
 *                           (int)(sizeof(flip)/ sizeof(flip[0]) ) );
 *     oc_rep_end_root_object();
 * ~~~
 */
#define oc_rep_set_bool_array(object, key, values, length)                     \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |=                                                                   \
      cbor_encoder_create_array(&object##_map, &key##_value_array, length);    \
    int i;                                                                     \
    for (i = 0; i < length; i++) {                                             \
      g_err |= cbor_encode_boolean(&key##_value_array, values[i]);             \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

/**
 * Add a double array with `values` of `length` to the cbor `object` under the
 * `key` name.
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "math_constants": [ 3.14159, 2.71828, 1.414121, 1.61803 ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     double math_constants[] = { 3.14159, 2.71828, 1.414121, 1.61803 };
 *     oc_rep_start_root_object();
 *     oc_rep_set_double_array(root,
 *                             math_constants,
 *                             math_constants,
 *                             (int)(sizeof(math_constants)/
 * sizeof(math_constants[0]) ) );
 *     oc_rep_end_root_object();
 * ~~~
 */
#define oc_rep_set_double_array(object, key, values, length)                   \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |=                                                                   \
      cbor_encoder_create_array(&object##_map, &key##_value_array, length);    \
    int i;                                                                     \
    for (i = 0; i < length; i++) {                                             \
      g_err |= cbor_encode_floating_point(&key##_value_array, CborDoubleType,  \
                                          &values[i]);                         \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

/**
 * Add a string array using an oc_string_array_t as `values` to the cbor
 * `object`
 * under the `key` name.
 *
 * Example:
 *
 * To build the an object with the following cbor value
 *
 *     {
 *       "quotes": [
 *       "Do not take life too seriously. You will never get out of it alive.",
 *       "All generalizations are false, including this one.",
 *       "Those who believe in telekinetics, raise my hand.",
 *       "I refuse to join any club that would have me as a member."
 *       ]
 *     }
 *
 * The following code could be used:
 *
 * ~~~{.c}
 *     const char* str0 = "Do not take life too seriously. You will never get
 * out of it alive.";
 *     const char* str1 = "All generalizations are false, including this one.";
 *     const char* str2 = "Those who believe in telekinetics, raise my hand.";
 *     const char* str3 = "I refuse to join any club that would have me as a
 * member.";
 *
 *     oc_string_array_t quotes;
 *     oc_new_string_array(&quotes, (size_t)4);
 *     oc_string_array_add_item(quotes, str0);
 *     oc_string_array_add_item(quotes, str1);
 *     oc_string_array_add_item(quotes, str2);
 *     oc_string_array_add_item(quotes, str3);
 *
 *     //add values to root objec
 *     oc_rep_start_root_object();
 *     oc_rep_set_string_array(root, quotes, quotes);
 *     oc_rep_end_root_object();
 *     oc_free_string_array(&quotes);
 * ~~~
 *
 * @see oc_string_array_t
 * @see oc_new_string_array
 * @see oc_free_string_array
 * @see oc_string_array_add_item
 */
#define oc_rep_set_string_array(object, key, values)                           \
  do {                                                                         \
    g_err |= cbor_encode_text_string(&object##_map, #key, strlen(#key));       \
    CborEncoder key##_value_array;                                             \
    g_err |= cbor_encoder_create_array(&object##_map, &key##_value_array,      \
                                       CborIndefiniteLength);                  \
    int i;                                                                     \
    for (i = 0; i < (int)oc_string_array_get_allocated_size(values); i++) {    \
      if (oc_string_array_get_item_size(values, i) > 0) {                      \
        g_err |= cbor_encode_text_string(                                      \
          &key##_value_array, oc_string_array_get_item(values, i),             \
          oc_string_array_get_item_size(values, i));                           \
      }                                                                        \
    }                                                                          \
    g_err |= cbor_encoder_close_container(&object##_map, &key##_value_array);  \
  } while (0)

/**
 * Called after any `oc_rep_set_*`, `oc_rep_start_*`, `oc_rep_begin_*`,
 * `oc_rep_end_*`, `oc_rep_add_*`, `oc_rep_open_*`, and `oc_rep_close_*` macros
 * to check if an error occurred while executing the commands.
 *
 * If the value returned is anything other than `CborNoError` then one of the
 * `oc_rep_*` macros failed.
 *
 * The error returned is not automatically cleared. To clear the error set
 * g_err to `CborNoError`.
 */
CborError oc_rep_get_cbor_errno(void);

typedef enum {
  OC_REP_NIL = 0,
  OC_REP_INT = 0x01,
  OC_REP_DOUBLE = 0x02,
  OC_REP_BOOL = 0x03,
  OC_REP_BYTE_STRING = 0x04,
  OC_REP_STRING = 0x05,
  OC_REP_OBJECT = 0x06,
  OC_REP_ARRAY = 0x08,
  OC_REP_INT_ARRAY = 0x09,
  OC_REP_DOUBLE_ARRAY = 0x0A,
  OC_REP_BOOL_ARRAY = 0x0B,
  OC_REP_BYTE_STRING_ARRAY = 0x0C,
  OC_REP_STRING_ARRAY = 0x0D,
  OC_REP_OBJECT_ARRAY = 0x0E
} oc_rep_value_type_t;

typedef struct oc_rep_s
{
  oc_rep_value_type_t type;
  struct oc_rep_s *next;
  oc_string_t name;
  union oc_rep_value {
    int64_t integer;
    bool boolean;
    double double_p;
    oc_string_t string;
    oc_array_t array;
    struct oc_rep_s *object;
    struct oc_rep_s *object_array;
  } value;
} oc_rep_t;

void oc_rep_set_pool(struct oc_memb *rep_objects_pool);

int oc_parse_rep(const uint8_t *payload, int payload_size,
                 oc_rep_t **value_list);

void oc_free_rep(oc_rep_t *rep);

/**
 * Read an integer from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *         int ultimate_answer_out = 0;
 *         if( true == oc_rep_get_int(rep, "ultimate_answer",
 * &ultimate_answer_out)) {
 *             printf("The ultimate answer is : %d\n", ultimate_answer_out);
 *         }
 * ~~~
 *
 * @param rep oc_rep_t to read int value from
 * @param key the key name for the integer value
 * @param value the return integer value
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_int
 */
bool oc_rep_get_int(oc_rep_t *rep, const char *key, int64_t *value);

/**
 * Read a boolean value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     bool door_open_flag = false;
 *     if( true == oc_rep_get_bool(rep, "door_open", &door_open_flag)) {
 *         printf("The door is open : %s\n", (door_open_flag) ? "true" :
 * "false");
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to read boolean value from
 * @param key the key name for the boolean value
 * @param value the return boolean value
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_boolean
 */
bool oc_rep_get_bool(oc_rep_t *rep, const char *key, bool *value);

/**
 * Read a double value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     double pi_out = 0;
 *     if( true == oc_rep_get_double(rep, "pi", &pi_out)) {
 *         printf("The the value for 'pi' is : %f\n", pi_out);
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to read double value from
 * @param key the key name for the double value
 * @param value the return double value
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_double
 */
bool oc_rep_get_double(oc_rep_t *rep, const char *key, double *value);

/**
 * Read a byte string value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     char* byte_string_out = NULL;
 *     size_t str_len;
 *     if( true == oc_rep_get_byte_string(rep, "byte_string_key",
 * &byte_string_out, &str_len)) {
 *         // byte_string_out can be used
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to read byte string value from
 * @param key the key name for the byte string value
 * @param value the return byte string value
 * @param size the size of the byte string
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_byte_string
 */
bool oc_rep_get_byte_string(oc_rep_t *rep, const char *key, char **value,
                            size_t *size);

/**
 * Read a text string value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     char* greeting_out = NULL;
 *     size_t str_len;
 *     if( true == oc_rep_get_string(rep, "greeting", &greeting_out, &str_len))
 * {
 *         printf("%s\n", greeting_out);
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to read string value from
 * @param key the key name for the string value
 * @param value the return string value
 * @param size the size of the string
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_text_string
 */
bool oc_rep_get_string(oc_rep_t *rep, const char *key, char **value,
                       size_t *size);

/**
 * Read an integer array value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     int* fib_out = 0;
 *     size_t fib_len;
 *     if( true == oc_rep_get_int_array(rep, "fibonacci", &fib_out, &fib_len)) {
 *         // fib_out can now be used
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to integer array value from
 * @param key the key name for the integer array value
 * @param value the return integer array value
 * @param size the size of the integer array
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_int_array
 */
bool oc_rep_get_int_array(oc_rep_t *rep, const char *key, int64_t **value,
                          size_t *size);

/**
 * Read an boolean array value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     bool* flip_out = 0;
 *     size_t flip_len;
 *     if( true == oc_rep_get_bool_array(rep, "flip", &flip_out, &flip_len)) {
 *         // flip_out can now be used
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to boolean array value from
 * @param key the key name for the boolean array value
 * @param value the return boolean array value
 * @param size the size of the boolean array
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_bool_array
 */
bool oc_rep_get_bool_array(oc_rep_t *rep, const char *key, bool **value,
                           size_t *size);

/**
 * Read an double array value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     double* math_constants_out = 0;
 *     size_t math_constants_len;
 *     if( true == oc_rep_get_double_array(rep,
 *                                         "math_constants",
 *                                         &math_constants_out,
 *                                         &math_constants_len)) {
 *         // math_constants_out can now be used
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to double array value from
 * @param key the key name for the double array value
 * @param value the return double array value
 * @param size the size of the double array
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_double_array
 */
bool oc_rep_get_double_array(oc_rep_t *rep, const char *key, double **value,
                             size_t *size);

/**
 * Read an byte string array value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     oc_string_array_t barray_out;
 *     size_t barray_len;
 *     if( true == oc_rep_get_byte_string_array(rep,
 *                                              "barray",
 *                                              &barray_out,
 *                                              &barray_len)) {
 *         for (size_t i = 0; i < barray_len); i++) {
 *             char* value = oc_byte_string_array_get_item(barray_out, i);
 *             size_t value_len =oc_byte_string_array_get_item_size(barray_out,
 * i);
 *             // access the individual byte string
 *         }
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to byte string array value from
 * @param key the key name for the byte string array value
 * @param value the return double array value
 * @param size the size of the byte string array
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_add_byte_string
 * @see oc_byte_string_array_get_item
 * @see oc_byte_string_array_get_item_size
 */
bool oc_rep_get_byte_string_array(oc_rep_t *rep, const char *key,
                                  oc_string_array_t *value, size_t *size);

/**
 * Read a string array value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     oc_string_array_t quotes_out;
 *     size_t quotes_len;
 *     if( true == oc_rep_get_string_array(rep,
 *                                         "quotes",
 *                                         &quotes_out,
 *                                         &quotes_len)) {
 *         printf("Quotes :\n")
 *         for (size_t i = 0; i < barray_len); i++) {
 *             char* value = oc_string_array_get_item(quotes_out, i);
 *             size_t value_len = oc_string_array_get_item_size(quotes_out, i);
 *             printf("[%zd] %s\n", i + 1, value);
 *         }
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to string array value from
 * @param key the key name for the string array value
 * @param value the return double array value
 * @param size the size of the string array
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_string_array
 * @see oc_rep_add_text_string
 * @see oc_string_array_get_item
 * @see oc_string_array_get_item_size
 */
bool oc_rep_get_string_array(oc_rep_t *rep, const char *key,
                             oc_string_array_t *value, size_t *size);

/**
 * Read a object value from an `oc_rep_t`
 *
 * Example:
 * ~~~{.c}
 *     oc_rep_t * my_object_out = NULL;
 *     if ( true == oc_rep_get_object(rep, "my_object", &my_object_out)) {
 *         int a_out;
 *         if (oc_rep_get_int(my_object_out, "a", &a_out))
 *             printf("a = %d\n", a_out);
 *         bool b_out = true;
 *         if (oc_rep_get_bool(my_object_out, "b", &b_out))
 *             printf("b = %s\n", (b_out) ? "true" : "false");
 *         char * c_out = NULL;
 *         size_t c_out_size = 0;
 *         if (oc_rep_get_string(my_object_out, "c", &c_out, &c_out_size))
 *             printf("c = %s\n", c_cout);
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to read object value from
 * @param key the key name for the object value
 * @param value the return object value
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_object
 */
bool oc_rep_get_object(oc_rep_t *rep, const char *key, oc_rep_t **value);

/**
 * Read a object array value from an `oc_rep_t`
 *
 * Calling the returned value an array is a misnomer. The value actually
 * returned is a linked list of oc_rep_t objects. The linked list must be walked
 * to see each item in the object array.
 *
 * Example:
 * ~~~{.c}
 *     oc_rep_t * space_2001_out = NULL;
 *     if ( true == oc_rep_get_object_array(rep, "space_2001", &space_2001_out))
 * {
 *         while (space_2001_out != NULL) {
 *             char * str_out = NULL;
 *             size_t str_out_size = 0;
 *             if (oc_rep_get_string(space_2001_out->value.object,
 *                                   "name",
 *                                   &str_out,
 *                                   &str_out_size))
 *                 printf("Character Name: %s", str_out);
 *             if (oc_rep_get_string(space_2001_out->value.object,
 *                                   "job",
 *                                    &str_out, &str_out_size))
 *                 printf(" job %s\n", str_out);
 *             space_2001_out = space_2001_out->next;
 *         }
 *     }
 * ~~~
 *
 * @param rep oc_rep_t to read object array value from
 * @param key the key name for the object array value
 * @param value the return object array value
 *
 * @return true if key and value are found and returned.
 *
 * @see oc_rep_set_object
 */
bool oc_rep_get_object_array(oc_rep_t *rep, const char *key, oc_rep_t **value);

/**
 * Tab character(s) used for oc_rep_to_json function when doing pretty_print
 */
#define OC_PRETTY_PRINT_TAB_CHARACTER "  "

/**
 * Convert an oc_rep_t to JSON encoded string.
 *
 * An oc_rep_t that is NULL or empty will return as an empty JSON object "{}".
 *
 * All binary data will be encoded to a string using base64 encoding.
 *
 * Converting binary data to a base64 encoded string is only done if the `buf`
 * can hold the entire base64 string. If the resulting base64 string would
 * overflow the buffer nothing is placed in the buffer.
 *
 * The function will not write more than buf_size bytes (including the
 * terminating null byte ('\0')). If the output was truncated due to this limit
 * then the return value is the number of characters (excluding the terminating
 * null byte) which would have been written to the final string if enough space
 * had been available. Thus, a return value of buf_size or more means that the
 * output was truncated.
 *
 * @param[in]  rep the oc_rep_t object to be converted to JSON
 * @param[out] buf a char array that will hold the JSON encoded string.
 * @param[in]  buf_size the size of the passed in char array
 * @param[in]  pretty_print if true extra white space and new lines will be
 * added to the output making it more human readable. Note return value will
 * differ if pretty_print value is changed.
 *
 * Example:
 * ~~~{.c}
 *     char * json;
 *     size_t json_size;
 *     json_size = oc_rep_to_json(rep, NULL, 0, true);
 *     json = (char *)malloc(json_size + 1);
 *     oc_rep_to_json(rep, json, json_size + 1, true);
 *     printf("%s", rep);
 *     free(json);
 * ~~~
 *
 * @return the number of characters printed (excluding the null byte used to end
 * output to strings).
 *
 */
size_t oc_rep_to_json(oc_rep_t *rep, char *buf, size_t buf_size,
                      bool pretty_print);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_H */

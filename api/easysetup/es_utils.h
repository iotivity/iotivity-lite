/* ****************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef _ES_UTILS_H_
#define _ES_UTILS_H_

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_ALLOC_CHECK(mem)                                                   \
  do {                                                                         \
    if (!mem) {                                                                \
      OC_ERR("Memory allocation failed!");                                     \
      goto exit;                                                               \
    }                                                                          \
  } while (0)

#define INPUT_PARAM_NULL_CHECK(in)                                             \
  do {                                                                         \
    if (!in) {                                                                 \
      OC_ERR("Invalid input!");                                                \
      goto exit;                                                               \
    }                                                                          \
  } while (0)

#define NULL_CHECK(p, mes)                                                     \
  do {                                                                         \
    if (!p) {                                                                  \
      OC_ERR(mes);                                                             \
      goto exit;                                                               \
    }                                                                          \
  } while (0)

#define RESOURCE_CHECK(r) NULL_CHECK(r, "Failed to create resource!")
#define RESOURCE_LINK_CHECK(r) NULL_CHECK(r, "Failed to create link!")

#define es_rep_set_boolean(object, key, value)                                 \
  oc_rep_set_boolean(object, key, value)

#define es_rep_set_int(object, key, value) oc_rep_set_int(object, key, value)

#define es_rep_set_text_string(object, key, value)                             \
  do {                                                                         \
    if (value)                                                                 \
      oc_rep_set_text_string(object, key, value);                              \
  } while (0);

#define es_rep_set_text_string_with_keystr(object, key, value)                 \
  do {                                                                         \
    if (value) {                                                               \
      g_err |= cbor_encode_text_string(&object##_map, key, strlen(key));       \
      g_err |= cbor_encode_text_string(&object##_map, value, strlen(value));   \
    }                                                                          \
  } while (0);

#define es_rep_set_int_with_keystr(object, key, value)                         \
  do {                                                                         \
    if (value) {                                                               \
      g_err |= cbor_encode_text_string(&object##_map, key, strlen(key));       \
      g_err |= cbor_encode_int(&object##_map, value);                          \
    }                                                                          \
  } while (0);

#define es_rep_set_boolean_with_keystr(object, key, value)                     \
  do {                                                                         \
    if (value) {                                                               \
      g_err |= cbor_encode_text_string(&object##_map, key, strlen(key));       \
      g_err |= cbor_encode_boolean(&object##_map, value);                      \
    }                                                                          \
  } while (0);

#define es_free_string(str)                                                    \
  if (oc_string_len(str) > 0)                                                  \
    oc_free_string(&str);

void
es_new_string(oc_string_t *des_string, char *src_string)
{
  if (!des_string || (!src_string || strlen(src_string) == 0)) {
    return;
  }

  if (oc_string_len(*des_string) == 0) {
    oc_new_string(des_string, src_string, strlen(src_string));
  } else if (oc_string_len(*des_string) == strlen(src_string)) {
    strncpy(oc_string(*des_string), src_string, strlen(src_string));
  } else {
    oc_free_string(des_string);
    oc_new_string(des_string, src_string, strlen(src_string));
  }
}

/**
 * Some type conversion helpers
 * For all *enum_tostring(...) functions: They take the Enum Type Value as input (val), and return
 * the corresponding string representation, which conforms to the OCF specification.
 * For all *string_toenum(...) functions: They take the string representation, as per the OCF
 * specification as input (val_in). And return the Enum Value in val_out. If conversion fails,
 * false is returned by the function.
 */

/**
 * convert wifi mode value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_mode_enum_tostring(wifi_mode val);

/**
 * convert wifi freq value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_freq_enum_tostring(wifi_freq val);

/**
 * convert wifi auth type value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_authtype_enum_tostring(wifi_authtype val);

/**
 * convert string representation to Enum value
 *
 * @param val     string representation
 * @param val_out  return the Enum Value in val_out
 *
 * @return result as true or false
 */
bool wifi_authtype_string_toenum(const char *val, wifi_authtype *val_out);

/**
 * convert wifi enc type value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* wifi_enctype_enum_tostring(wifi_enctype val);

/**
 * convert string representation to Enum value
 *
 * @param val     string representation
 * @param val_out  return the Enum Value in val_out
 *
 * @return result as true or false
 */
bool wifi_enctype_string_toenum(const char *val, wifi_enctype *val_out);

/**
 * convert wifi enc type value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* rsp_state_enum_tostring(rsp_state val);

/**
 * convert string representation to Enum value
 *
 * @param val     string representation
 * @param val_out  return the Enum Value in val_out
 *
 * @return result as true or false
 */
bool rsp_state_string_toenum(const char *val, rsp_state *val_out);

/**
 * convert wifi enc type value to related string representation
 *
 * @param val Enum Type Value as input
 *
 * @return corresponding string representation
 */
const char* euc_state_enum_tostring(user_confirmation val);

/**
 * convert string representation to Enum value
 *
 * @param val     string representation
 * @param val_out  return the Enum Value in val_out
 *
 * @return result as true or false
 */
bool euc_state_string_toenum(const char *val, user_confirmation *val_out);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // _ES_UTILS_H_

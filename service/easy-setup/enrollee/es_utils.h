/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef ES_UTILS_H
#define ES_UTILS_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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

static void
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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // ES_UTILS_H

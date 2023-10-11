/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_rep.h"
#include "oc_rep_internal.h"
#include "oc_rep_encode_internal.h"
#include "oc_ri_internal.h"
#include "oc_config.h"
#include "port/oc_assert.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>

static struct oc_memb *g_rep_objects = NULL;
CborEncoder root_map;
CborEncoder links_array;
int g_err = CborNoError;

void
oc_rep_set_pool(struct oc_memb *rep_objects_pool)
{
  g_rep_objects = rep_objects_pool;
}

void
oc_rep_new_v1(uint8_t *payload, size_t size)
{
  g_err = CborNoError;
  oc_rep_encoder_buffer_init(oc_rep_global_encoder(), payload, size);
}

void
oc_rep_new(uint8_t *payload, int size)
{
  assert(size >= 0);
  oc_rep_new_v1(payload, (size_t)size);
}

#ifdef OC_DYNAMIC_ALLOCATION

void
oc_rep_new_realloc_v1(uint8_t **payload, size_t size, size_t max_size)
{
  g_err = CborNoError;
  oc_rep_encoder_buffer_realloc_init(oc_rep_global_encoder(), payload, size,
                                     max_size);
}

void
oc_rep_new_realloc(uint8_t **payload, int size, int max_size)
{
  assert(size >= 0);
  assert(max_size >= 0);
  oc_rep_new_realloc_v1(payload, (size_t)size, (size_t)max_size);
}
#endif /* OC_DYNAMIC_ALLOCATION */

CborError
oc_rep_get_cbor_errno(void)
{
  return g_err;
}

oc_rep_t *
oc_alloc_rep(void)
{
  oc_rep_t *rep = (oc_rep_t *)oc_memb_alloc(g_rep_objects);
#ifdef OC_DEBUG
  oc_assert(rep != NULL);
#endif
  if (rep == NULL) {
    return NULL;
  }
  rep->name.size = 0;
  return rep;
}

static void
free_rep_internal(oc_rep_t *rep_value)
{
  oc_memb_free(g_rep_objects, rep_value);
}

void
oc_free_rep(oc_rep_t *rep)
{
  if (rep == NULL) {
    return;
  }
  oc_free_rep(rep->next);
  switch (rep->type) {
  case OC_REP_BYTE_STRING_ARRAY:
  case OC_REP_STRING_ARRAY:
    oc_free_string_array(&rep->value.array);
    break;
  case OC_REP_BOOL_ARRAY:
    oc_free_bool_array(&rep->value.array);
    break;
  case OC_REP_DOUBLE_ARRAY:
    oc_free_double_array(&rep->value.array);
    break;
  case OC_REP_INT_ARRAY:
    oc_free_int_array(&rep->value.array);
    break;
  case OC_REP_BYTE_STRING:
  case OC_REP_STRING:
    oc_free_string(&rep->value.string);
    break;
  case OC_REP_OBJECT:
    oc_free_rep(rep->value.object);
    break;
  case OC_REP_OBJECT_ARRAY:
    oc_free_rep(rep->value.object_array);
    break;
  default:
    break;
  }
  if (rep->name.size > 0) {
    oc_free_string(&rep->name);
  }
  free_rep_internal(rep);
}

static bool
oc_rep_get_value(const oc_rep_t *rep, oc_rep_value_type_t type, const char *key,
                 size_t key_len, void **value, size_t *size)
{
  if (rep == NULL) {
    OC_ERR("Error of input parameters: invalid rep");
    return false;
  }
  if (value == NULL) {
    OC_ERR("Error of input parameters: invalid value");
    return false;
  }
  if (key_len == 0 || key_len >= OC_MAX_STRING_LENGTH) {
    OC_ERR("Error of input parameters: invalid key");
    return false;
  }

  const oc_rep_t *rep_value = rep;
  while (rep_value != NULL) {
    if ((oc_string_len(rep_value->name) == key_len) &&
        (strncmp(key, oc_string(rep_value->name),
                 oc_string_len(rep_value->name)) == 0) &&
        (rep_value->type == type)) {
      switch (rep_value->type) {
      case OC_REP_NIL:
        **(bool **)value = true;
        break;
      case OC_REP_INT:
        **(int64_t **)value = rep_value->value.integer;
        break;
      case OC_REP_BOOL:
        **(bool **)value = rep_value->value.boolean;
        break;
      case OC_REP_DOUBLE:
        **(double **)value = rep_value->value.double_p;
        break;
      case OC_REP_BYTE_STRING:
      case OC_REP_STRING:
        *(const char **)value = oc_string(rep_value->value.string);
        *size = oc_string_len(rep_value->value.string);
        break;
      case OC_REP_INT_ARRAY:
        *value = oc_int_array(rep_value->value.array);
        *size = (int)oc_int_array_size(rep_value->value.array);
        break;
      case OC_REP_BOOL_ARRAY:
        *value = oc_bool_array(rep_value->value.array);
        *size = (int)oc_bool_array_size(rep_value->value.array);
        break;
      case OC_REP_DOUBLE_ARRAY:
        *value = oc_double_array(rep_value->value.array);
        *size = (int)oc_double_array_size(rep_value->value.array);
        break;
      case OC_REP_BYTE_STRING_ARRAY:
      case OC_REP_STRING_ARRAY:
        **(oc_string_array_t **)value = rep_value->value.array;
        *size = (int)oc_string_array_get_allocated_size(rep_value->value.array);
        break;
      case OC_REP_OBJECT:
        *value = rep_value->value.object;
        break;
      case OC_REP_OBJECT_ARRAY:
        *value = rep_value->value.object_array;
        break;
      default:
        return false;
      }

      return true;
    }
    rep_value = rep_value->next;
  }

  return false;
}

bool
oc_rep_is_null(const oc_rep_t *rep, const char *key, bool *is_null)
{
  if (is_null == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_NIL, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)&is_null, NULL);
}

bool
oc_rep_get_int(const oc_rep_t *rep, const char *key, int64_t *value)
{
  if (value == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_INT, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)&value, NULL);
}

bool
oc_rep_get_bool(const oc_rep_t *rep, const char *key, bool *value)
{
  if (value == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BOOL, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)&value, NULL);
}

bool
oc_rep_get_double(const oc_rep_t *rep, const char *key, double *value)
{
  if (value == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_DOUBLE, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)&value, NULL);
}

bool
oc_rep_get_byte_string(const oc_rep_t *rep, const char *key, char **value,
                       size_t *size)
{
  if (size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BYTE_STRING, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, size);
}

bool
oc_rep_get_string(const oc_rep_t *rep, const char *key, char **value,
                  size_t *size)
{
  // TODO: for oc_rep_get_byte_string, oc_rep_get_string and for all the arrays
  // the value parameter should be changed to const since it points to a
  // value of const oc_rep_t*

  if (size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_STRING, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, size);
}

bool
oc_rep_get_int_array(const oc_rep_t *rep, const char *key, int64_t **value,
                     size_t *size)
{
  if (size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_INT_ARRAY, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, size);
}

bool
oc_rep_get_bool_array(const oc_rep_t *rep, const char *key, bool **value,
                      size_t *size)
{
  if (size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BOOL_ARRAY, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, size);
}

bool
oc_rep_get_double_array(const oc_rep_t *rep, const char *key, double **value,
                        size_t *size)
{
  if (size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_DOUBLE_ARRAY, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, size);
}

bool
oc_rep_get_byte_string_array(const oc_rep_t *rep, const char *key,
                             oc_string_array_t *value, size_t *size)
{
  if (value == NULL || size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BYTE_STRING_ARRAY, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)&value, size);
}

bool
oc_rep_get_string_array(const oc_rep_t *rep, const char *key,
                        oc_string_array_t *value, size_t *size)
{
  if (value == NULL || size == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_STRING_ARRAY, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)&value, size);
}

bool
oc_rep_get_object(const oc_rep_t *rep, const char *key, oc_rep_t **value)
{
  return oc_rep_get_value(rep, OC_REP_OBJECT, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, NULL);
}

bool
oc_rep_get_object_array(const oc_rep_t *rep, const char *key, oc_rep_t **value)
{
  return oc_rep_get_value(rep, OC_REP_OBJECT_ARRAY, key,
                          oc_strnlen_s(key, OC_MAX_STRING_LENGTH),
                          (void **)value, NULL);
}

bool
oc_rep_is_property(const oc_rep_t *rep, const char *propname,
                   size_t propname_len)
{
  assert(rep != NULL);
  assert(propname != NULL);
  return oc_string_len(rep->name) == propname_len &&
         memcmp(oc_string((rep)->name), propname, propname_len) == 0;
}

bool
oc_rep_is_property_with_type(const oc_rep_t *rep, oc_rep_value_type_t proptype,
                             const char *propname, size_t propname_len)
{
  return rep->type == proptype &&
         oc_rep_is_property(rep, propname, propname_len);
}

bool
oc_rep_is_baseline_interface_property(const oc_rep_t *rep)
{
  // Common properties grouped by type:
  // OC_REP_STRING: n, tag-pos-desc, tag-func-desc, tag-locn
  if (rep->type == OC_REP_STRING) {
    return oc_rep_is_property(rep, OC_BASELINE_PROP_NAME,
                              OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_NAME)) ||
           oc_rep_is_property(
             rep, OC_BASELINE_PROP_TAG_POS_DESC,
             OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_POS_DESC)) ||
           oc_rep_is_property(rep, OC_BASELINE_PROP_FUNC_DESC,
                              OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_FUNC_DESC)) ||
           oc_rep_is_property(rep, OC_BASELINE_PROP_TAG_LOCN,
                              OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_LOCN));
  }
  // OC_REP_STRING_ARRAY: rt, if
  if (rep->type == OC_REP_STRING_ARRAY) {
    return oc_rep_is_property(rep, OC_BASELINE_PROP_RT,
                              OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_RT)) ||
           oc_rep_is_property(rep, OC_BASELINE_PROP_IF,
                              OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_IF));
  }
  // OC_REP_DOUBLE_ARRAY: tag-pos-rel
  if (rep->type == OC_REP_DOUBLE_ARRAY) {
    return oc_rep_is_property(rep, OC_BASELINE_PROP_TAG_POS_REL,
                              OC_CHAR_ARRAY_LEN(OC_BASELINE_PROP_TAG_POS_REL));
  }
  return false;
}

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
#include "util/oc_macros.h"
#include "util/oc_memb.h"
#include "util/oc_features.h"

static struct oc_memb *g_rep_objects;
CborEncoder root_map;
CborEncoder links_array;
int g_err;

typedef enum oc_rep_error_t {
  OC_REP_NO_ERROR = 0,

  OC_REP_ERROR_INTERNAL = -1,
  OC_REP_ERROR_OUT_OF_MEMORY = -2,
} oc_rep_error_t;

void
oc_rep_set_pool(struct oc_memb *rep_objects_pool)
{
  g_rep_objects = rep_objects_pool;
}

void
oc_rep_new(uint8_t *out_payload, int size)
{
  g_err = CborNoError;
  oc_rep_encoder_init(out_payload, size);
}

#ifdef OC_DYNAMIC_ALLOCATION
void
oc_rep_new_realloc(uint8_t **out_payload, int size, int max_size)
{
  g_err = CborNoError;
  oc_rep_encoder_realloc_init(out_payload, size, max_size);
}
#endif /* OC_DYNAMIC_ALLOCATION */

CborError
oc_rep_get_cbor_errno(void)
{
  return g_err;
}

static oc_rep_t *
alloc_rep_internal(void)
{
  oc_rep_t *rep = (oc_rep_t *)oc_memb_alloc(g_rep_objects);
  if (rep != NULL) {
    rep->name.size = 0;
  }
#ifdef OC_DEBUG
  oc_assert(rep != NULL);
#endif
  return rep;
}

#ifdef OC_HAS_FEATURE_PUSH
oc_rep_t *
oc_alloc_rep(void)
{
  return alloc_rep_internal();
}
#endif

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

/*
  An Object is a collection of key-value pairs.
  A value_object value points to the first key-value pair,
  and subsequent items are accessed via the next pointer.

  An Object Array is a collection of objects, where each object
  is a collection of key-value pairs.
  A value_object_array value points to the first object in the
  array. This object is then traversed via its value_object pointer.
  Subsequent objects in the object array are then accessed through
  the next pointer of the first object.
*/

static CborError
oc_parse_rep_key(const CborValue *value, oc_rep_t **rep)
{
  oc_rep_t *cur = *rep;
  if (!cbor_value_is_text_string(value)) {
    return CborErrorIllegalType;
  }
  size_t len;
  CborError err = cbor_value_calculate_string_length(value, &len);
  if (err != CborNoError) {
    return err;
  }
  len++;
  if (len == 0) {
    return CborErrorInternalError;
  }
  oc_alloc_string(&cur->name, len);
  return cbor_value_copy_text_string(value, oc_string(cur->name), &len, NULL);
}

typedef struct
{
  CborValue value;
  oc_rep_value_type_t type;
  size_t length;
} oc_parse_array_rep_t;

static int
cbor_type_to_oc_rep_value_type(CborType type)
{
  switch (type) {
  case CborIntegerType:
    return OC_REP_INT;
  case CborDoubleType:
    return OC_REP_DOUBLE;
  case CborBooleanType:
    return OC_REP_BOOL;
  case CborMapType:
    return OC_REP_OBJECT;
  case CborArrayType:
    return OC_REP_ARRAY;
  case CborByteStringType:
    return OC_REP_BYTE_STRING;
  case CborTextStringType:
    return OC_REP_STRING;
  default:
    break;
  }
  return OC_REP_ERROR_INTERNAL;
}

static CborError
oc_parse_rep_array_init(const CborValue *value, oc_parse_array_rep_t *rep_array)
{
  CborValue array;
  CborError err = cbor_value_enter_container(value, &array);
  if (err != CborNoError) {
    return err;
  }
  size_t len = 0;
  cbor_value_get_array_length(value, &len);
  if (len == 0) {
    CborValue t = array;
    while (!cbor_value_at_end(&t)) {
      len++;
      err = cbor_value_advance(&t);
      if (err != CborNoError) {
        return err;
      }
    }
  }

  if (len == 0) {
    rep_array->value = array;
    rep_array->type = OC_REP_NIL;
    rep_array->length = len;
    return CborNoError;
  }

  // we support only arrays with a single type
  int ret = cbor_type_to_oc_rep_value_type(array.type);
  if (ret < 0) {
    return CborErrorIllegalType;
  }
  oc_rep_value_type_t value_type = (oc_rep_value_type_t)ret;

  rep_array->value = array;
  rep_array->type = value_type | OC_REP_ARRAY;
  rep_array->length = len;
  return CborNoError;
}

static oc_rep_error_t
oc_rep_array_init(oc_rep_t *rep, oc_rep_value_type_t array_type, size_t len)
{
  switch (array_type) {
  case OC_REP_INT_ARRAY:
    oc_new_int_array(&rep->value.array, len);
    break;
  case OC_REP_DOUBLE_ARRAY:
    oc_new_double_array(&rep->value.array, len);
    break;
  case OC_REP_BOOL_ARRAY:
    oc_new_bool_array(&rep->value.array, len);
    break;
  case OC_REP_BYTE_STRING_ARRAY: // NOLINT(bugprone-branch-clone)
    oc_new_byte_string_array(&rep->value.array, len);
    break;
  case OC_REP_STRING_ARRAY:
    oc_new_string_array(&rep->value.array, len);
    break;
  case OC_REP_OBJECT_ARRAY:
    rep->value.object_array = alloc_rep_internal();
    if (rep->value.object_array == NULL) {
      return OC_REP_ERROR_OUT_OF_MEMORY;
    }
    break;
  default:
    return OC_REP_ERROR_INTERNAL;
  }

  rep->type = array_type;
  return OC_REP_NO_ERROR;
}

static CborError
oc_rep_array_value_type_check(const oc_rep_t *rep, oc_rep_value_type_t type)
{
  if ((rep->type & type) != type) {
    return CborErrorIllegalType;
  }
  return CborNoError;
}

static CborError oc_parse_rep_object(CborValue *value, oc_rep_t **rep);

static CborError
oc_parse_rep_object_array(CborValue *array, size_t array_len, oc_rep_t *rep)
{
  oc_rep_t **prev = &rep->value.object_array;
  size_t k = 0;
  while (!cbor_value_at_end(array)) {
    if (array->type != CborMapType) {
      return CborErrorIllegalType;
    }
    if (k > 0) {
      if (prev == NULL) {
        return CborErrorInternalError;
      }
      if ((*prev) == NULL) {
        return CborErrorOutOfMemory;
      }
      (*prev)->next = alloc_rep_internal();
      if ((*prev)->next == NULL) {
        return CborErrorOutOfMemory;
      }
      prev = &(*prev)->next;
    }
    (*prev)->type = OC_REP_OBJECT;
    (*prev)->next = NULL;
    oc_rep_t **obj = &(*prev)->value.object;
    /* Process a series of properties that make up an object of the array */
    CborValue map;
    CborError err = cbor_value_enter_container(array, &map);
    if (err != CborNoError) {
      return err;
    }
    while (!cbor_value_at_end(&map) && (err == CborNoError)) {
      err |= oc_parse_rep_object(&map, obj);
      obj = &(*obj)->next;
      err |= cbor_value_advance(&map);
    }
    if (err != CborNoError) {
      return err;
    }
    ++k;
    err = cbor_value_advance(array);
    if (err != CborNoError) {
      return err;
    }
  }

  if (k != array_len) {
    return CborErrorInternalError;
  }
  return CborNoError;
}

static CborError
oc_parse_rep_simple_array(CborValue *array, size_t array_len, oc_rep_t *rep)
{
  size_t k = 0;
  while (!cbor_value_at_end(array)) {
    int ret = cbor_type_to_oc_rep_value_type(array->type);
    if (ret < 0) {
      return CborErrorIllegalType;
    }
    oc_rep_value_type_t value_type = (oc_rep_value_type_t)ret;
    CborError err = oc_rep_array_value_type_check(rep, value_type);
    if (err != CborNoError) {
      return err;
    }

    switch (rep->type) {
    case OC_REP_INT_ARRAY:
      err = cbor_value_get_int64(array, oc_int_array(rep->value.array) + k);
      break;
    case OC_REP_DOUBLE_ARRAY:
      err = cbor_value_get_double(array, oc_double_array(rep->value.array) + k);
      break;
    case OC_REP_BOOL_ARRAY:
      err = cbor_value_get_boolean(array, oc_bool_array(rep->value.array) + k);
      break;
    case OC_REP_BYTE_STRING_ARRAY: {
      size_t len = 0;
      err |= cbor_value_calculate_string_length(array, &len);
      if (len >= STRING_ARRAY_ITEM_MAX_LEN) {
        len = STRING_ARRAY_ITEM_MAX_LEN - 1;
      }
      uint8_t *size =
        (uint8_t *)oc_byte_string_array_get_item(rep->value.array, k);
      size -= 1;
      *size = (uint8_t)len;
      err |= cbor_value_copy_byte_string(
        array, (uint8_t *)oc_byte_string_array_get_item(rep->value.array, k),
        &len, NULL);
    } break;
    case OC_REP_STRING_ARRAY: {
      size_t len = 0;
      err |= cbor_value_calculate_string_length(array, &len);
      len++;
      if (len > STRING_ARRAY_ITEM_MAX_LEN) {
        len = STRING_ARRAY_ITEM_MAX_LEN;
      }
      err |= cbor_value_copy_text_string(
        array, oc_string_array_get_item(rep->value.array, k), &len, NULL);
    } break;
    default:
      return CborErrorIllegalType;
    }
    if (err != CborNoError) {
      return err;
    }
    ++k;
    err = cbor_value_advance(array);
    if (err != CborNoError) {
      return err;
    }
  }
  if (k != array_len) {
    return CborErrorInternalError;
  }
  return CborNoError;
}

static CborError
oc_parse_rep_array(const CborValue *value, oc_rep_t *rep)
{
  oc_parse_array_rep_t rep_array;
  CborError err = oc_parse_rep_array_init(value, &rep_array);
  if (err != CborNoError) {
    return err;
  }
  if (rep_array.length == 0) {
    return CborNoError;
  }

  oc_rep_error_t rep_err =
    oc_rep_array_init(rep, rep_array.type, rep_array.length);
  if (rep_err != OC_REP_NO_ERROR) {
    OC_ERR("initialize rep array error(%d)", rep_err);
    return rep_err == OC_REP_ERROR_OUT_OF_MEMORY ? CborErrorOutOfMemory
                                                 : CborErrorInternalError;
  }

  if (rep->type == OC_REP_OBJECT_ARRAY) {
    return oc_parse_rep_object_array(&rep_array.value, rep_array.length, rep);
  }
  return oc_parse_rep_simple_array(&rep_array.value, rep_array.length, rep);
}

static CborError
oc_parse_rep_value(CborValue *value, oc_rep_t **rep)
{
  /* skip over CBOR Tags */
  CborError err = cbor_value_skip_tag(value);
  if (err != CborNoError) {
    return err;
  }

  oc_rep_t *cur = *rep;
  switch (value->type) {
  case CborIntegerType: {
    err = cbor_value_get_int64(value, &cur->value.integer);
    cur->type = OC_REP_INT;
    return err;
  }
  case CborBooleanType: {
    err = cbor_value_get_boolean(value, &cur->value.boolean);
    cur->type = OC_REP_BOOL;
    return err;
  }
  case CborDoubleType: {
    err = cbor_value_get_double(value, &cur->value.double_p);
    cur->type = OC_REP_DOUBLE;
    return err;
  }
  case CborByteStringType: {
    size_t len;
    err = cbor_value_calculate_string_length(value, &len);
    if (err != CborNoError) {
      return err;
    }
    len++;
    if (len == 0) {
      return CborErrorInternalError;
    }
    cur->type = OC_REP_BYTE_STRING;
    oc_alloc_string(&cur->value.string, len);
    err |= cbor_value_copy_byte_string(
      value, oc_cast(cur->value.string, uint8_t), &len, NULL);
    return err;
  }
  case CborTextStringType: {
    size_t len;
    err = cbor_value_calculate_string_length(value, &len);
    if (err != CborNoError) {
      return err;
    }
    len++;
    if (len == 0) {
      return CborErrorInternalError;
    }
    cur->type = OC_REP_STRING;
    oc_alloc_string(&cur->value.string, len);
    err |= cbor_value_copy_text_string(value, oc_string(cur->value.string),
                                       &len, NULL);
    return err;
  }
  case CborMapType: {
    oc_rep_t **obj = &cur->value.object;
    cur->type = OC_REP_OBJECT;
    CborValue map;
    err = cbor_value_enter_container(value, &map);
    while (!cbor_value_at_end(&map)) {
      err = oc_parse_rep_object(&map, obj);
      if (err != CborNoError) {
        return err;
      }
      (*obj)->next = NULL;
      obj = &(*obj)->next;
      err |= cbor_value_advance(&map);
    }
    return err;
  }
  case CborArrayType:
    return oc_parse_rep_array(value, cur);
  case CborInvalidType:
    return CborErrorIllegalType;
  default:
    break;
  }

  return CborNoError;
}

/* Parse single property */
static CborError
oc_parse_rep_object(CborValue *value, oc_rep_t **rep)
{
  oc_rep_t *cur = alloc_rep_internal();
  if (cur == NULL) {
    return CborErrorOutOfMemory;
  }
  cur->next = NULL;
  cur->value.object_array = NULL;

  CborError err = oc_parse_rep_key(value, &cur);
  if (err != CborNoError) {
    OC_ERR("failed to parse rep: cannot parse key(%d)", err);
    oc_free_rep(cur);
    return err;
  }
  err = cbor_value_advance(value);
  if (err != CborNoError) {
    OC_ERR("failed to parse rep: cannot advance iterator(%d)", err);
    oc_free_rep(cur);
    return err;
  }

  err = oc_parse_rep_value(value, &cur);
  if (err != CborNoError) {
    OC_ERR("failed to parse rep: cannot parse value(%d)", err);
    oc_free_rep(cur);
    return err;
  }

  *rep = cur;
  return CborNoError;
}

int
oc_parse_rep(const uint8_t *in_payload, size_t payload_size, oc_rep_t **out_rep)
{
  if (out_rep == NULL) {
    return -1;
  }
  CborParser parser;
  CborValue root_value;
  CborError err =
    cbor_parser_init(in_payload, payload_size, 0, &parser, &root_value);
  if (err != CborNoError) {
    return err;
  }
  *out_rep = NULL;
  if (cbor_value_is_map(&root_value)) {
    CborValue cur_value;
    err = cbor_value_enter_container(&root_value, &cur_value);
    oc_rep_t **cur = out_rep;
    while (cbor_value_is_valid(&cur_value) && err == CborNoError) {
      err |= oc_parse_rep_object(&cur_value, cur);
      if (err != CborNoError) {
        return err;
      }
      err |= cbor_value_advance(&cur_value);
      assert(*cur != NULL);
      cur = &(*cur)->next;
    }
    return err;
  }
  if (cbor_value_is_array(&root_value)) {
    CborValue map;
    err = cbor_value_enter_container(&root_value, &map);
    oc_rep_t **cur = out_rep;
    while (cbor_value_is_valid(&map)) {
      *cur = alloc_rep_internal();
      if (*cur == NULL) {
        return CborErrorOutOfMemory;
      }
      (*cur)->type = OC_REP_OBJECT;
      oc_rep_t **kv = &(*cur)->value.object;
      CborValue cur_value;
      err |= cbor_value_enter_container(&map, &cur_value);
      while (cbor_value_is_valid(&cur_value) && err == CborNoError) {
        err |= oc_parse_rep_object(&cur_value, kv);
        err |= cbor_value_advance(&cur_value);
        assert(*kv != NULL);
        (*kv)->next = NULL;
        kv = &(*kv)->next;
      }
      (*cur)->next = NULL;
      cur = &(*cur)->next;
      err |= cbor_value_advance(&map);
      if (err != CborNoError) {
        return err;
      }
    }
    return err;
  }
  return CborNoError;
}

static bool
oc_rep_get_value(const oc_rep_t *rep, oc_rep_value_type_t type, const char *key,
                 void **value, size_t *size)
{
  if (!rep || !key || !value) {
    OC_ERR("Error of input parameters");
    return false;
  }

  const oc_rep_t *rep_value = rep;
  while (rep_value != NULL) {
    if ((oc_string_len(rep_value->name) == strlen(key)) &&
        (strncmp(key, oc_string(rep_value->name),
                 oc_string_len(rep_value->name)) == 0) &&
        (rep_value->type == type)) {
      OC_DBG("Found the value with %s", key);
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
  if (!is_null) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_NIL, key, (void **)&is_null,
                          (size_t *)NULL);
}

bool
oc_rep_get_int(const oc_rep_t *rep, const char *key, int64_t *value)
{
  if (!value) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_INT, key, (void **)&value,
                          (size_t *)NULL);
}

bool
oc_rep_get_bool(const oc_rep_t *rep, const char *key, bool *value)
{
  if (!value) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BOOL, key, (void **)&value,
                          (size_t *)NULL);
}

bool
oc_rep_get_double(const oc_rep_t *rep, const char *key, double *value)
{
  if (!value) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_DOUBLE, key, (void **)&value,
                          (size_t *)NULL);
}

bool
oc_rep_get_byte_string(const oc_rep_t *rep, const char *key, char **value,
                       size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BYTE_STRING, key, (void **)value, size);
}

bool
oc_rep_get_string(const oc_rep_t *rep, const char *key, char **value,
                  size_t *size)
{
  // TODO: for oc_rep_get_byte_string, oc_rep_get_string and for all the arrays
  // the value parameter should be changed to const since it points to a
  // value of const oc_rep_t*

  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_STRING, key, (void **)value, size);
}

bool
oc_rep_get_int_array(const oc_rep_t *rep, const char *key, int64_t **value,
                     size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_INT_ARRAY, key, (void **)value, size);
}

bool
oc_rep_get_bool_array(const oc_rep_t *rep, const char *key, bool **value,
                      size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BOOL_ARRAY, key, (void **)value, size);
}

bool
oc_rep_get_double_array(const oc_rep_t *rep, const char *key, double **value,
                        size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_DOUBLE_ARRAY, key, (void **)value, size);
}

bool
oc_rep_get_byte_string_array(const oc_rep_t *rep, const char *key,
                             oc_string_array_t *value, size_t *size)
{
  if (!value || !size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BYTE_STRING_ARRAY, key, (void **)&value,
                          size);
}

bool
oc_rep_get_string_array(const oc_rep_t *rep, const char *key,
                        oc_string_array_t *value, size_t *size)
{
  if (!value || !size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_STRING_ARRAY, key, (void **)&value, size);
}

bool
oc_rep_get_object(const oc_rep_t *rep, const char *key, oc_rep_t **value)
{
  return oc_rep_get_value(rep, OC_REP_OBJECT, key, (void **)value, NULL);
}

bool
oc_rep_get_object_array(const oc_rep_t *rep, const char *key, oc_rep_t **value)
{
  return oc_rep_get_value(rep, OC_REP_OBJECT_ARRAY, key, (void **)value, NULL);
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

bool
oc_rep_is_property(const oc_rep_t *rep, const char *name, size_t name_len)
{
  assert(rep != NULL);
  assert(name != NULL);
  return ((oc_string_len(rep->name) == name_len) &&
          (memcmp(oc_string(rep->name), name, name_len) == 0));
}

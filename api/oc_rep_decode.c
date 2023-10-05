/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_internal.h"
#include "port/oc_log_internal.h"

#ifdef OC_JSON_ENCODER
#include "api/oc_rep_decode_json_internal.h"
#endif /* OC_JSON_ENCODER */

typedef CborError (*oc_rep_parse_payload_t)(const uint8_t *payload,
                                            size_t payload_size,
                                            oc_rep_t **out_rep);

typedef struct
{
  oc_rep_decoder_type_t type;
  oc_rep_parse_payload_t parse;
} oc_rep_decoder_t;

static int oc_rep_parse_cbor(const uint8_t *payload, size_t payload_size,
                             oc_rep_t **out_rep);

static oc_rep_decoder_t g_rep_decoder = {
  .type = OC_REP_CBOR_DECODER,
  .parse = &oc_rep_parse_cbor,
};

static CborError rep_parse_object(CborValue *value, oc_rep_t **rep);

static CborError
rep_parse_object_array(CborValue *array, size_t array_len, oc_rep_t *rep)
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
      (*prev)->next = oc_alloc_rep();
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
      err |= rep_parse_object(&map, obj);
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
rep_array_value_type_check(const oc_rep_t *rep, oc_rep_value_type_t type)
{
  if ((rep->type & type) != type) {
    return CborErrorIllegalType;
  }
  return CborNoError;
}

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
rep_parse_simple_array(CborValue *array, size_t array_len, oc_rep_t *rep)
{
  size_t k = 0;
  while (!cbor_value_at_end(array)) {
    int ret = cbor_type_to_oc_rep_value_type(array->type);
    if (ret < 0) {
      return CborErrorIllegalType;
    }
    oc_rep_value_type_t value_type = (oc_rep_value_type_t)ret;
    CborError err = rep_array_value_type_check(rep, value_type);
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

static oc_rep_error_t
rep_array_init(oc_rep_t *rep, oc_rep_value_type_t array_type, size_t len)
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
    rep->value.object_array = oc_alloc_rep();
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

typedef struct
{
  CborValue value;
  oc_rep_value_type_t type;
  size_t length;
} oc_parse_array_rep_t;

static CborError
rep_parse_array_init(const CborValue *value, oc_parse_array_rep_t *rep_array)
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

static CborError
rep_parse_array(const CborValue *value, oc_rep_t *rep)
{
  oc_parse_array_rep_t rep_array;
  CborError err = rep_parse_array_init(value, &rep_array);
  if (err != CborNoError) {
    return err;
  }
  if (rep_array.length == 0) {
    return CborNoError;
  }

  oc_rep_error_t rep_err =
    rep_array_init(rep, rep_array.type, rep_array.length);
  if (rep_err != OC_REP_NO_ERROR) {
    OC_ERR("initialize rep array error(%d)", rep_err);
    return rep_err == OC_REP_ERROR_OUT_OF_MEMORY ? CborErrorOutOfMemory
                                                 : CborErrorInternalError;
  }

  if (rep->type == OC_REP_OBJECT_ARRAY) {
    return rep_parse_object_array(&rep_array.value, rep_array.length, rep);
  }
  return rep_parse_simple_array(&rep_array.value, rep_array.length, rep);
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
      err = rep_parse_object(&map, obj);
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
    return rep_parse_array(value, cur);
  case CborInvalidType:
    return CborErrorIllegalType;
  default:
    break;
  }

  return CborNoError;
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
rep_parse_key(const CborValue *value, oc_rep_t **rep)
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

/* Parse single property */
static CborError
rep_parse_object(CborValue *value, oc_rep_t **rep)
{
  oc_rep_t *cur = oc_alloc_rep();
  if (cur == NULL) {
    return CborErrorOutOfMemory;
  }
  cur->next = NULL;
  cur->value.object_array = NULL;

  CborError err = rep_parse_key(value, &cur);
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

static int
oc_rep_parse_cbor(const uint8_t *payload, size_t payload_size,
                  oc_rep_t **out_rep)
{
  CborParser parser;
  CborValue root_value;
  CborError err =
    cbor_parser_init(payload, payload_size, 0, &parser, &root_value);
  if (err != CborNoError) {
    return err;
  }
  *out_rep = NULL;
  if (cbor_value_is_map(&root_value)) {
    CborValue cur_value;
    err = cbor_value_enter_container(&root_value, &cur_value);
    oc_rep_t **cur = out_rep;
    while (cbor_value_is_valid(&cur_value) && err == CborNoError) {
      err |= rep_parse_object(&cur_value, cur);
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
      *cur = oc_alloc_rep();
      if (*cur == NULL) {
        return CborErrorOutOfMemory;
      }
      (*cur)->type = OC_REP_OBJECT;
      oc_rep_t **kv = &(*cur)->value.object;
      CborValue cur_value;
      err |= cbor_value_enter_container(&map, &cur_value);
      while (cbor_value_is_valid(&cur_value) && err == CborNoError) {
        err |= rep_parse_object(&cur_value, kv);
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

void
oc_rep_decoder_set_type(oc_rep_decoder_type_t decoder_type)
{
  g_rep_decoder.type = decoder_type;
  if (g_rep_decoder.type == OC_REP_CBOR_DECODER) {
    g_rep_decoder.parse = &oc_rep_parse_cbor;
    return;
  }
#ifdef OC_JSON_ENCODER
  if (g_rep_decoder.type == OC_REP_JSON_DECODER) {
    g_rep_decoder.parse = &oc_rep_parse_json;
    return;
  }
#endif /* OC_JSON_ENCODER */
}

oc_rep_decoder_type_t
oc_rep_decoder_get_type(void)
{
  return g_rep_decoder.type;
}

bool
oc_rep_decoder_set_type_by_content_format(oc_content_format_t content_format)
{
  if (content_format == APPLICATION_CBOR ||
      content_format == APPLICATION_VND_OCF_CBOR ||
      content_format == APPLICATION_NOT_DEFINED) {
    oc_rep_decoder_set_type(OC_REP_CBOR_DECODER);
    return true;
  }
#ifdef OC_JSON_ENCODER
  if (content_format == APPLICATION_JSON ||
      content_format == APPLICATION_TD_JSON) {
    oc_rep_decoder_set_type(OC_REP_JSON_DECODER);
    return true;
  }
#endif /* OC_JSON_ENCODER */
  return false;
}

int
oc_parse_rep(const uint8_t *payload, size_t payload_size, oc_rep_t **out_rep)
{
  if (out_rep == NULL) {
    return -1;
  }
  return g_rep_decoder.parse(payload, payload_size, out_rep);
}

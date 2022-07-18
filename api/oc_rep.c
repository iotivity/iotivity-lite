/*
// Copyright (c) 2016 Intel Corporation
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

#include "oc_api.h"
#include "oc_rep.h"
#include "oc_base64.h"
#include "oc_config.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include "util/oc_memb.h"

#include <inttypes.h>

static struct oc_memb *rep_objects;
CborEncoder g_encoder, root_map, links_array;
CborError g_err;
static uint8_t *g_buf;
#ifdef OC_DYNAMIC_ALLOCATION
static bool g_enable_realloc;
static size_t g_buf_size;
static size_t g_buf_max_size;
static uint8_t **g_buf_ptr;
#endif /* OC_DYNAMIC_ALLOCATION */

static CborEncoder *
convert_offset_to_ptr(CborEncoder *encoder)
{
  if (!encoder || (encoder->data.ptr && !encoder->end)) {
    return encoder;
  }
  encoder->data.ptr = g_buf + (intptr_t)encoder->data.ptr;
#ifdef OC_DYNAMIC_ALLOCATION
  encoder->end = g_buf ? g_buf + g_buf_size : NULL;
#else  /* OC_DYNAMIC_ALLOCATION */
  encoder->end = g_buf + (intptr_t)encoder->end;
#endif /* !OC_DYNAMIC_ALLOCATION */
  return encoder;
}

static CborEncoder *
convert_ptr_to_offset(CborEncoder *encoder)
{
  if (!encoder || (encoder->data.ptr && !encoder->end)) {
    return encoder;
  }
  encoder->data.ptr = (uint8_t *)(encoder->data.ptr - g_buf);
  encoder->end = (uint8_t *)(encoder->end - g_buf);
  return encoder;
}

#ifdef OC_DYNAMIC_ALLOCATION
static size_t
oc_rep_encoder_get_extra_bytes_needed(CborEncoder *encoder)
{
  convert_offset_to_ptr(encoder);
  size_t size = cbor_encoder_get_extra_bytes_needed(encoder);
  convert_ptr_to_offset(encoder);
  return size;
}

static CborError
realloc_buffer(size_t needed)
{
  if (!g_enable_realloc || g_buf_size + needed > g_buf_max_size) {
    return CborErrorOutOfMemory;
  }
  // preallocate buffer to avoid reallocation
  if (2 * (g_buf_size + needed) < (size_t)(g_buf_max_size / 4)) {
    needed += g_buf_size + needed;
  } else {
    needed = (size_t)g_buf_max_size - g_buf_size;
  }
  uint8_t *tmp = (uint8_t *)realloc(*g_buf_ptr, g_buf_size + needed);
  if (tmp == NULL) {
    return CborErrorOutOfMemory;
  }
  *g_buf_ptr = tmp;
  g_buf = tmp;
  g_buf_size = g_buf_size + needed;
  return CborNoError;
}

#endif /* OC_DYNAMIC_ALLOCATION */

void
oc_rep_set_pool(struct oc_memb *rep_objects_pool)
{
  rep_objects = rep_objects_pool;
}

void
oc_rep_new(uint8_t *out_payload, int size)
{
  g_err = CborNoError;
  g_buf = out_payload;
#ifdef OC_DYNAMIC_ALLOCATION
  g_enable_realloc = false;
  g_buf_size = size;
  g_buf_ptr = NULL;
  g_buf_max_size = size;
#endif /* OC_DYNAMIC_ALLOCATION */
  cbor_encoder_init(&g_encoder, out_payload, size, 0);
  convert_ptr_to_offset(&g_encoder);
}

#ifdef OC_DYNAMIC_ALLOCATION
void
oc_rep_new_realloc(uint8_t **out_payload, int size, int max_size)
{
  g_err = CborNoError;
  g_enable_realloc = true;
  g_buf_size = size;
  g_buf_max_size = max_size;
  g_buf_ptr = out_payload;
  g_buf = *out_payload;
  cbor_encoder_init(&g_encoder, g_buf, size, 0);
  convert_ptr_to_offset(&g_encoder);
}
#endif /* OC_DYNAMIC_ALLOCATION */

CborError
oc_rep_get_cbor_errno(void)
{
  return g_err;
}

const uint8_t *
oc_rep_get_encoder_buf(void)
{
  return g_buf;
}

#ifdef OC_DYNAMIC_ALLOCATION
int
oc_rep_get_encoder_buffer_size(void)
{
  return (int)g_buf_size;
}
#endif /* OC_DYNAMIC_ALLOCATION */

uint8_t *
oc_rep_shrink_encoder_buf(uint8_t *buf)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return buf;
#else  /* !OC_DYNAMIC_ALLOCATION */
  if (!g_enable_realloc || !buf || !g_buf_ptr || buf != g_buf)
    return buf;
  int size = oc_rep_get_encoded_payload_size();
  if (size <= 0) {
    // if the size is 0, then it means that the encoder was not used at all
    return buf;
  }
  uint8_t *tmp = (uint8_t *)realloc(buf, size);
  if (tmp == NULL && size > 0) {
    return buf;
  }
  OC_DBG("cbor encoder buffer was shrinked from %d to %d", (int)g_buf_size,
         size);
  g_buf_size = (size_t)size;
  *g_buf_ptr = tmp;
  g_buf = tmp;
  return tmp;
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_rep_encode_raw(const uint8_t *data, size_t len)
{
  if (g_encoder.end == NULL) {
    OC_WRN("encoder has not set end pointer.");
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  size_t needed = g_buf_size - (size_t)g_encoder.data.ptr;
  if (needed < len) {
    if (!g_enable_realloc) {
      OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
             "accomodate a larger payload(+%d)",
             (int)needed);
      return;
    }
    realloc_buffer(g_buf_size - (size_t)g_encoder.data.ptr);
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  intptr_t needed = (intptr_t)g_encoder.end - (intptr_t)g_encoder.data.ptr;
  if (needed < (intptr_t)len) {
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
           "accomodate a larger payload(+%d)",
           (int)needed);
    return;
  }
#endif /* !OC_DYNAMIC_ALLOCATION */
  convert_offset_to_ptr(&g_encoder);
  memcpy(g_encoder.data.ptr, data, len);
  g_encoder.data.ptr = g_encoder.data.ptr + len;
  g_err = CborNoError;
  convert_ptr_to_offset(&g_encoder);
}

int
oc_rep_get_encoded_payload_size(void)
{
  convert_offset_to_ptr(&g_encoder);
  size_t size = cbor_encoder_get_buffer_size(&g_encoder, g_buf);
  size_t needed = cbor_encoder_get_extra_bytes_needed(&g_encoder);
  convert_ptr_to_offset(&g_encoder);
  if (g_err == CborErrorOutOfMemory) {
    OC_WRN("Insufficient memory: Increase OC_MAX_APP_DATA_SIZE to "
           "accomodate a larger payload(+%d)",
           (int)needed);
    (void)needed;
  }
  if (g_err != CborNoError)
    return -1;
  return (int)size;
}

static oc_rep_t *
_alloc_rep(void)
{
  oc_rep_t *rep = oc_memb_alloc(rep_objects);
  if (rep != NULL) {
    rep->name.size = 0;
  }
#ifdef OC_DEBUG
  oc_assert(rep != NULL);
#endif
  return rep;
}

static void
_free_rep(oc_rep_t *rep_value)
{
  oc_memb_free(rep_objects, rep_value);
}

void
oc_free_rep(oc_rep_t *rep)
{
  if (rep == 0)
    return;
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
  if (rep->name.size > 0)
    oc_free_string(&rep->name);
  _free_rep(rep);
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

/* Parse single property */
static void
oc_parse_rep_value(CborValue *value, oc_rep_t **rep, CborError *err)
{
  size_t k, len;
  CborValue map, array;
  *rep = _alloc_rep();
  if (*rep == NULL) {
    *err = CborErrorOutOfMemory;
    return;
  }
  oc_rep_t *cur = *rep, **prev = 0;
  cur->next = 0;
  cur->value.object_array = 0;
  /* key */
  if (!cbor_value_is_text_string(value)) {
    *err = CborErrorIllegalType;
    return;
  }
  *err |= cbor_value_calculate_string_length(value, &len);
  len++;
  if (*err != CborNoError || len == 0)
    return;
  oc_alloc_string(&cur->name, len);
  *err |= cbor_value_copy_text_string(value, (char *)oc_string(cur->name), &len,
                                      NULL);
  if (*err != CborNoError)
    return;
get_tagged_value:
  *err |= cbor_value_advance(value);
  /* value */
  switch (value->type) {
  case CborTagType: {
    CborTag tag;
    cbor_value_get_tag(value, &tag);
    /* skip over CBOR Tags */
    goto get_tagged_value;
  } break;
  case CborIntegerType:
    *err |= cbor_value_get_int64(value, &cur->value.integer);
    cur->type = OC_REP_INT;
    break;
  case CborBooleanType:
    *err |= cbor_value_get_boolean(value, &cur->value.boolean);
    cur->type = OC_REP_BOOL;
    break;
  case CborDoubleType:
    *err |= cbor_value_get_double(value, &cur->value.double_p);
    cur->type = OC_REP_DOUBLE;
    break;
  case CborByteStringType:
    *err |= cbor_value_calculate_string_length(value, &len);
    len++;
    if (*err != CborNoError || len == 0)
      return;
    oc_alloc_string(&cur->value.string, len);
    *err |= cbor_value_copy_byte_string(
      value, oc_cast(cur->value.string, uint8_t), &len, NULL);
    cur->type = OC_REP_BYTE_STRING;
    break;
  case CborTextStringType:
    *err |= cbor_value_calculate_string_length(value, &len);
    len++;
    if (*err != CborNoError || len == 0)
      return;
    oc_alloc_string(&cur->value.string, len);
    *err |= cbor_value_copy_text_string(value, oc_string(cur->value.string),
                                        &len, NULL);
    cur->type = OC_REP_STRING;
    break;
  case CborMapType: {
    oc_rep_t **obj = &cur->value.object;
    *err |= cbor_value_enter_container(value, &map);
    while (!cbor_value_at_end(&map)) {
      oc_parse_rep_value(&map, obj, err);
      if (*err != CborNoError)
        return;
      (*obj)->next = NULL;
      obj = &(*obj)->next;
      *err |= cbor_value_advance(&map);
    }
    cur->type = OC_REP_OBJECT;
  } break;
  case CborArrayType:
    *err |= cbor_value_enter_container(value, &array);
    len = 0;
    cbor_value_get_array_length(value, &len);
    if (len == 0) {
      CborValue t = array;
      while (!cbor_value_at_end(&t)) {
        len++;
        if (*err != CborNoError)
          return;
        *err = cbor_value_advance(&t);
      }
    }
    k = 0;
    while (!cbor_value_at_end(&array)) {
      switch (array.type) {
      case CborIntegerType:
        if (k == 0) {
          oc_new_int_array(&cur->value.array, len);
          cur->type = OC_REP_INT | OC_REP_ARRAY;
        } else if ((cur->type & OC_REP_INT) != OC_REP_INT) {
          *err |= CborErrorIllegalType;
          return;
        }

        *err |=
          cbor_value_get_int64(&array, oc_int_array(cur->value.array) + k);
        break;
      case CborDoubleType:
        if (k == 0) {
          oc_new_double_array(&cur->value.array, len);
          cur->type = OC_REP_DOUBLE | OC_REP_ARRAY;
        } else if ((cur->type & OC_REP_DOUBLE) != OC_REP_DOUBLE) {
          *err |= CborErrorIllegalType;
          return;
        }

        *err |=
          cbor_value_get_double(&array, oc_double_array(cur->value.array) + k);
        break;
      case CborBooleanType:
        if (k == 0) {
          oc_new_bool_array(&cur->value.array, len);
          cur->type = OC_REP_BOOL | OC_REP_ARRAY;
        } else if ((cur->type & OC_REP_BOOL) != OC_REP_BOOL) {
          *err |= CborErrorIllegalType;
          return;
        }

        *err |=
          cbor_value_get_boolean(&array, oc_bool_array(cur->value.array) + k);
        break;
      case CborByteStringType: {
        if (k == 0) {
          oc_new_byte_string_array(&cur->value.array, len);
          cur->type = OC_REP_BYTE_STRING | OC_REP_ARRAY;
        } else if ((cur->type & OC_REP_BYTE_STRING) != OC_REP_BYTE_STRING) {
          *err |= CborErrorIllegalType;
          return;
        }

        *err |= cbor_value_calculate_string_length(&array, &len);
        if (len >= STRING_ARRAY_ITEM_MAX_LEN) {
          len = STRING_ARRAY_ITEM_MAX_LEN - 1;
        }
        uint8_t *size =
          (uint8_t *)oc_byte_string_array_get_item(cur->value.array, k);
        size -= 1;
        *size = (uint8_t)len;
        *err |= cbor_value_copy_byte_string(
          &array, (uint8_t *)oc_byte_string_array_get_item(cur->value.array, k),
          &len, NULL);
      } break;
      case CborTextStringType:
        if (k == 0) {
          oc_new_string_array(&cur->value.array, len);
          cur->type = OC_REP_STRING | OC_REP_ARRAY;
        } else if ((cur->type & OC_REP_STRING) != OC_REP_STRING) {
          *err |= CborErrorIllegalType;
          return;
        }

        *err |= cbor_value_calculate_string_length(&array, &len);
        len++;
        if (len > STRING_ARRAY_ITEM_MAX_LEN) {
          len = STRING_ARRAY_ITEM_MAX_LEN;
        }
        *err |= cbor_value_copy_text_string(
          &array, (char *)oc_string_array_get_item(cur->value.array, k), &len,
          NULL);
        break;
      case CborMapType:
        if (k == 0) {
          cur->type = OC_REP_OBJECT | OC_REP_ARRAY;
          cur->value.object_array = _alloc_rep();
          if (cur->value.object_array == NULL) {
            *err = CborErrorOutOfMemory;
            return;
          }
          prev = &cur->value.object_array;
        } else if ((cur->type & OC_REP_OBJECT) != OC_REP_OBJECT) {
          *err |= CborErrorIllegalType;
          return;
        } else {
          if (prev == NULL) {
            *err = CborErrorInternalError;
            return;
          } else if ((*prev) == NULL) {
            *err = CborErrorOutOfMemory;
            return;
          }
          (*prev)->next = _alloc_rep();
          if ((*prev)->next == NULL) {
            *err = CborErrorOutOfMemory;
            return;
          }
          prev = &(*prev)->next;
        }
        (*prev)->type = OC_REP_OBJECT;
        (*prev)->next = NULL;
        oc_rep_t **obj = &(*prev)->value.object;
        /* Process a series of properties that make up an object of the array */
        *err |= cbor_value_enter_container(&array, &map);
        while (!cbor_value_at_end(&map)) {
          oc_parse_rep_value(&map, obj, err);
          if (*err != CborNoError)
            return;
          obj = &(*obj)->next;
          *err |= cbor_value_advance(&map);
        }
        break;
      default:
        break;
      }
      k++;
      if (*err != CborNoError)
        return;
      *err |= cbor_value_advance(&array);
    }
    break;
  case CborInvalidType:
    *err |= CborErrorIllegalType;
    return;
  default:
    break;
  }
}

int
oc_parse_rep(const uint8_t *in_payload, size_t payload_size, oc_rep_t **out_rep)
{
  CborParser parser;
  CborValue root_value, cur_value, map;
  CborError err = CborNoError;
  err |= cbor_parser_init(in_payload, payload_size, 0, &parser, &root_value);
  if (cbor_value_is_map(&root_value)) {
    err |= cbor_value_enter_container(&root_value, &cur_value);
    *out_rep = 0;
    oc_rep_t **cur = out_rep;
    while (cbor_value_is_valid(&cur_value)) {
      oc_parse_rep_value(&cur_value, cur, &err);
      if (err != CborNoError)
        return err;
      err |= cbor_value_advance(&cur_value);
      cur = &(*cur)->next;
    }
  } else if (cbor_value_is_array(&root_value)) {
    *out_rep = 0;
    oc_rep_t **cur = out_rep, **kv;
    err |= cbor_value_enter_container(&root_value, &map);
    while (cbor_value_is_valid(&map)) {
      *cur = _alloc_rep();
      if (*cur == NULL)
        return CborErrorOutOfMemory;
      (*cur)->type = OC_REP_OBJECT;
      kv = &(*cur)->value.object;
      err |= cbor_value_enter_container(&map, &cur_value);
      while (cbor_value_is_valid(&cur_value)) {
        oc_parse_rep_value(&cur_value, kv, &err);
        if (err != CborNoError)
          return err;
        err |= cbor_value_advance(&cur_value);
        (*kv)->next = 0;
        kv = &(*kv)->next;
      }
      (*cur)->next = 0;
      cur = &(*cur)->next;
      if (err != CborNoError)
        return err;
      err |= cbor_value_advance(&map);
    }
  } else {
    *out_rep = 0;
  }
  return err;
}

static bool
oc_rep_get_value(oc_rep_t *rep, oc_rep_value_type_t type, const char *key,
                 void **value, size_t *size)
{
  if (!rep || !key || !value) {
    OC_ERR("Error of input parameters");
    return false;
  }

  oc_rep_t *rep_value = rep;
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
        *value = oc_string(rep_value->value.string);
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
oc_rep_is_null(oc_rep_t *rep, const char *key, bool *is_null)
{
  if (!is_null) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_NIL, key, (void **)&is_null,
                          (size_t *)NULL);
}

bool
oc_rep_get_int(oc_rep_t *rep, const char *key, int64_t *value)
{
  if (!value) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_INT, key, (void **)&value,
                          (size_t *)NULL);
}

bool
oc_rep_get_bool(oc_rep_t *rep, const char *key, bool *value)
{
  if (!value) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BOOL, key, (void **)&value,
                          (size_t *)NULL);
}

bool
oc_rep_get_double(oc_rep_t *rep, const char *key, double *value)
{
  if (!value) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_DOUBLE, key, (void **)&value,
                          (size_t *)NULL);
}

bool
oc_rep_get_byte_string(oc_rep_t *rep, const char *key, char **value,
                       size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BYTE_STRING, key, (void **)value, size);
}

bool
oc_rep_get_string(oc_rep_t *rep, const char *key, char **value, size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_STRING, key, (void **)value, size);
}

bool
oc_rep_get_int_array(oc_rep_t *rep, const char *key, int64_t **value,
                     size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_INT_ARRAY, key, (void **)value, size);
}

bool
oc_rep_get_bool_array(oc_rep_t *rep, const char *key, bool **value,
                      size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_BOOL_ARRAY, key, (void **)value, size);
}

bool
oc_rep_get_double_array(oc_rep_t *rep, const char *key, double **value,
                        size_t *size)
{
  if (!size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_DOUBLE_ARRAY, key, (void **)value, size);
}

bool
oc_rep_get_byte_string_array(oc_rep_t *rep, const char *key,
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
oc_rep_get_string_array(oc_rep_t *rep, const char *key,
                        oc_string_array_t *value, size_t *size)
{
  if (!value || !size) {
    OC_ERR("Error of input parameters");
    return false;
  }
  return oc_rep_get_value(rep, OC_REP_STRING_ARRAY, key, (void **)&value, size);
}

bool
oc_rep_get_object(oc_rep_t *rep, const char *key, oc_rep_t **value)
{
  return oc_rep_get_value(rep, OC_REP_OBJECT, key, (void **)value, NULL);
}

bool
oc_rep_get_object_array(oc_rep_t *rep, const char *key, oc_rep_t **value)
{
  return oc_rep_get_value(rep, OC_REP_OBJECT_ARRAY, key, (void **)value, NULL);
}

/*
 * This macro assumes that four variables are already avalible to be changed.
 *
 *  - total_char_printed = running total of characters printed to buf
 *  - num_char_printed = the number of characters the command just before the
 *                       macro is called reports is printed typically the return
 *                       value of snprintf function but not always.
 *  - buf = the character buffer being updated
 *  - buf_size = the size of the character buffer being updated.
 *
 * Tracking the total number characters and moving the pointer forward in the
 * buffer so it the addition of each string looks like concatenation means
 * moving the buf pointer forward and reducing the buf_size after every function
 * that adds to the buffer.
 *
 * In addition it will update the total character count that would be printed
 * regardless of the buf_size. (total_char_print is expected to be larger than
 * or equal to buf_size if the buffer is too small.)
 */
#define OC_JSON_UPDATE_BUFFER_AND_TOTAL                                        \
  do {                                                                         \
    total_char_printed += num_char_printed;                                    \
    if (num_char_printed < buf_size && buf != NULL) {                          \
      buf += num_char_printed;                                                 \
      buf_size -= num_char_printed;                                            \
    } else {                                                                   \
      buf += buf_size;                                                         \
      buf_size = 0;                                                            \
    }                                                                          \
  } while (0);

/*
 * Internal function used to complete the oc_rep_to_json function
 *
 * This function is used when pretty_print param of the oc_rep_to_json function
 * is set to true. It helps produce output with reasonably human readable
 * white-space.
 */
size_t
oc_rep_to_json_tab(char *buf, size_t buf_size, int tab_depth)
{
  size_t num_char_printed = 0;
  size_t total_char_printed = 0;
  for (int i = 0; i < tab_depth; i++) {
    num_char_printed =
      snprintf(buf, buf_size, "%s", OC_PRETTY_PRINT_TAB_CHARACTER);
    OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  }
  return total_char_printed;
}

/*
 * Internal function used to complete the oc_rep_to_json function
 *
 * This function is called when the data type is an OC_REP_BYTE_STRING or
 * an OC_REP_BYTE_STRING_ARRAY. If uses the base64 encoded to encode the
 * byte_string to a base64 string.
 */
size_t
oc_rep_to_json_base64_encoded_byte_string(char *buf, size_t buf_size,
                                          char *byte_str, size_t byte_str_size)
{
  size_t num_char_printed = 0;
  size_t total_char_printed = 0;
  // calculate the b64 encoded string size
  size_t b64_buf_size = (byte_str_size / 3) * 4;
  if (byte_str_size % 3 != 0) {
    b64_buf_size += 4;
  }
  // one extra byte for terminating NUL character.
  b64_buf_size++;
  num_char_printed = snprintf(buf, buf_size, "\"");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;

  if (buf_size > b64_buf_size) {
    int output_len = oc_base64_encode((uint8_t *)byte_str, byte_str_size,
                                      (uint8_t *)buf, b64_buf_size);
    num_char_printed = output_len;
    OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  } else {
    buf += buf_size;
    buf_size = 0;
    total_char_printed += (b64_buf_size - 1);
  }
  num_char_printed = snprintf(buf, buf_size, "\"");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  return total_char_printed;
}

/*
 * Internal function called by oc_rep_to_json function
 *
 * oc_rep_to_json_format will take any oc_rep_t and print out the json
 * equivalent of that value.  This function will be called recursively for
 * nested objects.
 *
 * Currently does not handle OC_REP_ARRAY data type.
 */
size_t
oc_rep_to_json_format(oc_rep_t *rep, char *buf, size_t buf_size, int tab_depth,
                      bool pretty_print)
{
  (void)buf;
  (void)buf_size;
  size_t num_char_printed = 0;
  size_t total_char_printed = 0;
  while (rep != NULL) {
    if (pretty_print) {
      num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }

    if (oc_string_len(rep->name) > 0) {
      num_char_printed =
        (pretty_print)
          ? snprintf(buf, buf_size, "\"%s\" : ", oc_string(rep->name))
          : snprintf(buf, buf_size, "\"%s\":", oc_string(rep->name));
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }
    switch (rep->type) {
    case OC_REP_NIL: {
      num_char_printed = snprintf(buf, buf_size, "null");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_INT: {
      num_char_printed =
        snprintf(buf, buf_size, "%" PRId64, rep->value.integer);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_DOUBLE: {
      num_char_printed = snprintf(buf, buf_size, "%f", rep->value.double_p);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BOOL: {
      num_char_printed =
        snprintf(buf, buf_size, "%s", (rep->value.boolean) ? "true" : "false");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BYTE_STRING: {
      char *byte_string = NULL;
      size_t byte_string_size;
      const char *name = oc_string(rep->name);
      if (!oc_rep_get_byte_string(rep, name, &byte_string, &byte_string_size)) {
        OC_ERR("failed to encode byte string(%s)",
               name != NULL ? name : "NULL");
        break;
      }
      num_char_printed = oc_rep_to_json_base64_encoded_byte_string(
        buf, buf_size, byte_string, byte_string_size);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_STRING: {
      num_char_printed =
        snprintf(buf, buf_size, "\"%s\"", oc_string(rep->value.string));
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_OBJECT: {
      num_char_printed = (pretty_print) ? snprintf(buf, buf_size, "{\n")
                                        : snprintf(buf, buf_size, "{");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      num_char_printed = oc_rep_to_json_format(rep->value.object, buf, buf_size,
                                               tab_depth + 1, pretty_print);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "}");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_INT_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      int64_t *int_array;
      size_t int_array_size = 0;
      oc_rep_get_int_array(rep, oc_string(rep->name), &int_array,
                           &int_array_size);
      for (size_t i = 0; i < int_array_size; i++) {
        num_char_printed = snprintf(buf, buf_size, "%" PRId64, int_array[i]);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < int_array_size - 1) {
          num_char_printed = (pretty_print) ? snprintf(buf, buf_size, ", ")
                                            : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_DOUBLE_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      double *double_array;
      size_t double_array_size = 0;
      oc_rep_get_double_array(rep, oc_string(rep->name), &double_array,
                              &double_array_size);
      for (size_t i = 0; i < double_array_size; i++) {
        num_char_printed = snprintf(buf, buf_size, "%f", double_array[i]);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < double_array_size - 1) {
          num_char_printed = (pretty_print) ? snprintf(buf, buf_size, ", ")
                                            : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BOOL_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      bool *bool_array;
      size_t bool_array_size = 0;
      oc_rep_get_bool_array(rep, oc_string(rep->name), &bool_array,
                            &bool_array_size);
      for (size_t i = 0; i < bool_array_size; i++) {
        num_char_printed =
          snprintf(buf, buf_size, "%s", (bool_array[i]) ? "true" : "false");
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < bool_array_size - 1) {
          num_char_printed = (pretty_print) ? snprintf(buf, buf_size, ", ")
                                            : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BYTE_STRING_ARRAY: {
      num_char_printed = (pretty_print) ? snprintf(buf, buf_size, "[\n")
                                        : snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      oc_string_array_t byte_str_array;
      size_t byte_str_array_size = 0;
      oc_rep_get_byte_string_array(rep, oc_string(rep->name), &byte_str_array,
                                   &byte_str_array_size);
      for (size_t i = 0; i < byte_str_array_size; i++) {
        if (pretty_print) {
          num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
        char *byte_string = oc_byte_string_array_get_item(byte_str_array, i);
        size_t byte_string_size =
          oc_byte_string_array_get_item_size(byte_str_array, i);
        num_char_printed = oc_rep_to_json_base64_encoded_byte_string(
          buf, buf_size, byte_string, byte_string_size);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < byte_str_array_size - 1) {
          num_char_printed = (pretty_print) ? snprintf(buf, buf_size, ",\n")
                                            : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        } else {
          if (pretty_print) {
            num_char_printed = snprintf(buf, buf_size, "\n");
            OC_JSON_UPDATE_BUFFER_AND_TOTAL;
          }
        }
      }
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_STRING_ARRAY: {
      num_char_printed = (pretty_print) ? snprintf(buf, buf_size, "[\n")
                                        : snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      oc_string_array_t str_array;
      size_t str_array_size = 0;
      oc_rep_get_string_array(rep, oc_string(rep->name), &str_array,
                              &str_array_size);
      for (size_t i = 0; i < str_array_size; i++) {
        if (pretty_print) {
          num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
        num_char_printed = snprintf(buf, buf_size, "\"%s\"",
                                    oc_string_array_get_item(str_array, i));
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < str_array_size - 1) {
          num_char_printed = (pretty_print) ? snprintf(buf, buf_size, ",\n")
                                            : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        } else {
          if (pretty_print) {
            num_char_printed = snprintf(buf, buf_size, "\n");
            OC_JSON_UPDATE_BUFFER_AND_TOTAL;
          }
        }
      }
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_OBJECT_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      oc_rep_t *rep_array = rep->value.object_array;
      if (pretty_print) {
        num_char_printed = snprintf(buf, buf_size, "\n");
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      do {
        oc_rep_t *rep_item = rep_array->value.object;
        if (pretty_print) {
          num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
        num_char_printed = (pretty_print) ? snprintf(buf, buf_size, "{\n")
                                          : snprintf(buf, buf_size, "{");
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        num_char_printed = oc_rep_to_json_format(rep_item, buf, buf_size,
                                                 tab_depth + 2, pretty_print);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        rep_array = rep_array->next;
        if (rep_array) {
          if (pretty_print) {
            num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
            OC_JSON_UPDATE_BUFFER_AND_TOTAL;
          }
          num_char_printed = (pretty_print) ? snprintf(buf, buf_size, "},\n")
                                            : snprintf(buf, buf_size, "},");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      } while (rep_array);
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "}]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    default:
      break;
    }
    rep = rep->next;
    if (rep != NULL) {
      num_char_printed = snprintf(buf, buf_size, ",");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }
    if (pretty_print) {
      num_char_printed = snprintf(buf, buf_size, "\n");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }
  }
  return total_char_printed;
}

size_t
oc_rep_to_json(oc_rep_t *rep, char *buf, size_t buf_size, bool pretty_print)
{
  size_t num_char_printed = 0;
  size_t total_char_printed = 0;
  bool object_array =
    (rep && (rep->type == OC_REP_OBJECT) && (oc_string_len(rep->name) == 0));
  num_char_printed = (pretty_print)
                       ? snprintf(buf, buf_size, (object_array) ? "[\n" : "{\n")
                       : snprintf(buf, buf_size, (object_array) ? "[" : "{");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;

  num_char_printed = oc_rep_to_json_format(rep, buf, buf_size, 0, pretty_print);
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;

  num_char_printed = (pretty_print)
                       ? snprintf(buf, buf_size, (object_array) ? "]\n" : "}\n")
                       : snprintf(buf, buf_size, (object_array) ? "]" : "}");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  return total_char_printed;
}

static CborError
oc_rep_encoder_create_map_internal(CborEncoder *encoder,
                                   CborEncoder *mapEncoder, size_t length)
{
  convert_offset_to_ptr(encoder);
  convert_offset_to_ptr(mapEncoder);
  CborError err = cbor_encoder_create_map(encoder, mapEncoder, length);
  convert_ptr_to_offset(encoder);
  convert_ptr_to_offset(mapEncoder);
  return err;
}

CborError
oc_rep_encoder_create_map(CborEncoder *encoder, CborEncoder *mapEncoder,
                          size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encoder_create_map_internal(encoder, mapEncoder, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevMapEncoder;
  memcpy(&prevMapEncoder, mapEncoder, sizeof(prevMapEncoder));
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err =
    oc_rep_encoder_create_map_internal(encoder, mapEncoder, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(mapEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(mapEncoder, &prevMapEncoder, sizeof(prevMapEncoder));
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encoder_create_map_internal(encoder, mapEncoder, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encoder_close_container_internal(CborEncoder *encoder,
                                        CborEncoder *containerEncoder)
{
  convert_offset_to_ptr(encoder);
  convert_offset_to_ptr(containerEncoder);
  CborError err = cbor_encoder_close_container(encoder, containerEncoder);
  convert_ptr_to_offset(encoder);
  convert_ptr_to_offset(containerEncoder);
  return err;
}

CborError
oc_rep_encoder_close_container(CborEncoder *encoder,
                               CborEncoder *containerEncoder)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encoder_close_container_internal(encoder, containerEncoder);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevContainerEncoder;
  memcpy(&prevContainerEncoder, containerEncoder, sizeof(prevContainerEncoder));
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err =
    oc_rep_encoder_close_container_internal(encoder, containerEncoder);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    memcpy(containerEncoder, &prevContainerEncoder,
           sizeof(prevContainerEncoder));
    return oc_rep_encoder_close_container_internal(encoder, containerEncoder);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_text_string_internal(CborEncoder *encoder, const char *string,
                                   size_t length)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_text_string(encoder, string, length);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_text_string(CborEncoder *encoder, const char *string,
                          size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_text_string_internal(encoder, string, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_text_string_internal(encoder, string, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_text_string_internal(encoder, string, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_double_internal(CborEncoder *encoder, double value)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_double(encoder, value);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_double(CborEncoder *encoder, double value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_double_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_double_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_double_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_boolean_internal(CborEncoder *encoder, bool value)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_boolean(encoder, value);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_boolean(CborEncoder *encoder, bool value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_boolean_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_boolean_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_boolean_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_int_internal(CborEncoder *encoder, int64_t value)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_int(encoder, value);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_int(CborEncoder *encoder, int64_t value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_int_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_int_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_int_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_uint_internal(CborEncoder *encoder, uint64_t value)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_uint(encoder, value);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_uint(CborEncoder *encoder, uint64_t value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_uint_internal(encoder, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_uint_internal(encoder, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_uint_internal(encoder, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_byte_string_internal(CborEncoder *encoder, const uint8_t *string,
                                   size_t length)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_byte_string(encoder, string, length);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_byte_string(CborEncoder *encoder, const uint8_t *string,
                          size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_byte_string_internal(encoder, string, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_byte_string_internal(encoder, string, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_byte_string_internal(encoder, string, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encoder_create_array_internal(CborEncoder *encoder,
                                     CborEncoder *arrayEncoder, size_t length)
{
  convert_offset_to_ptr(encoder);
  convert_offset_to_ptr(arrayEncoder);
  CborError err = cbor_encoder_create_array(encoder, arrayEncoder, length);
  convert_ptr_to_offset(encoder);
  convert_ptr_to_offset(arrayEncoder);
  return err;
}

CborError
oc_rep_encoder_create_array(CborEncoder *encoder, CborEncoder *arrayEncoder,
                            size_t length)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encoder_create_array_internal(encoder, arrayEncoder, length);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborEncoder prevArrayEncoder;
  memcpy(&prevArrayEncoder, arrayEncoder, sizeof(prevArrayEncoder));
  CborError err =
    oc_rep_encoder_create_array_internal(encoder, arrayEncoder, length);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(arrayEncoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    memcpy(arrayEncoder, &prevArrayEncoder, sizeof(prevArrayEncoder));
    return oc_rep_encoder_create_array_internal(encoder, arrayEncoder, length);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

static CborError
oc_rep_encode_floating_point_internal(CborEncoder *encoder, CborType fpType,
                                      const void *value)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_floating_point(encoder, fpType, value);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_floating_point(CborEncoder *encoder, CborType fpType,
                             const void *value)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_floating_point_internal(encoder, fpType, value);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_floating_point_internal(encoder, fpType, value);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_floating_point_internal(encoder, fpType, value);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

CborError
oc_rep_encode_null_internal(CborEncoder *encoder)
{
  convert_offset_to_ptr(encoder);
  CborError err = cbor_encode_null(encoder);
  convert_ptr_to_offset(encoder);
  return err;
}

CborError
oc_rep_encode_null(CborEncoder *encoder)
{
#ifndef OC_DYNAMIC_ALLOCATION
  return oc_rep_encode_null_internal(encoder);
#else  /* !OC_DYNAMIC_ALLOCATION */
  CborEncoder prevEncoder;
  memcpy(&prevEncoder, encoder, sizeof(prevEncoder));
  CborError err = oc_rep_encode_null_internal(encoder);
  if (err == CborErrorOutOfMemory) {
    err = realloc_buffer(oc_rep_encoder_get_extra_bytes_needed(encoder));
    if (err != CborNoError) {
      return err;
    }
    memcpy(encoder, &prevEncoder, sizeof(prevEncoder));
    return oc_rep_encode_null_internal(encoder);
  }
  return err;
#endif /* OC_DYNAMIC_ALLOCATION */
}

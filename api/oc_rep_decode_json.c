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

#include "util/oc_features.h"

#ifdef OC_JSON_ENCODER

#include "api/oc_rep_decode_json_internal.h"
#include "api/oc_rep_internal.h"
#include "port/oc_log_internal.h"
#include "util/jsmn/jsmn_internal.h"
#include "util/oc_macros_internal.h"

#include <errno.h>
#include <stdlib.h>

typedef struct
{
  oc_rep_t *root;
  oc_rep_t *previous;
  oc_rep_t *cur;
  int err;
} rep_data_t;

static void
json_parse_string_value(rep_data_t *data, const char *str, size_t len)
{
  data->cur->type = OC_REP_STRING;
  oc_new_string(&data->cur->value.string, str, len);
  data->cur = NULL;
}

static bool
json_set_rep(rep_data_t *data, oc_rep_value_type_t value_type)
{
  if (data->cur == NULL) {
    data->cur = oc_alloc_rep();
    if (data->cur == NULL) {
      data->err = CborErrorOutOfMemory;
      return false;
    }
    if (data->root == NULL) {
      data->root = data->cur;
    }
    if (data->previous != NULL) {
      data->previous->next = data->cur;
    }
    data->previous = data->cur;
  } else if (data->cur->name.size == 0) {
    data->err = CborErrorIllegalType;
    return false;
  }
  data->cur->type = value_type;
  return true;
}

#define OC_REP_UNKNOWN_TYPE 255

static bool
json_parse_string(rep_data_t *data, const char *str, size_t len)
{
  if (data->cur) {
    if (data->cur->name.size == 0) {
      data->err = CborErrorIllegalType;
      return false;
    }
    json_parse_string_value(data, str, len);
    return true;
  }
  if (!json_set_rep(data, OC_REP_UNKNOWN_TYPE)) {
    return false;
  }
  oc_new_string(&data->cur->name, str, len);
  return true;
}

static bool
json_parse_null(const char *str, size_t len)
{
#define JSON_NULL "null"
  return (len == OC_CHAR_ARRAY_LEN(JSON_NULL) &&
          strncmp(str, JSON_NULL, OC_CHAR_ARRAY_LEN(JSON_NULL)) == 0);
#undef JSON_NULL
}

static bool
json_parse_bool(const char *str, size_t len, bool *value)
{
#define JSON_TRUE "true"
#define JSON_FALSE "false"
  if (len == OC_CHAR_ARRAY_LEN(JSON_TRUE) &&
      strncmp(str, JSON_TRUE, OC_CHAR_ARRAY_LEN(JSON_TRUE)) == 0) {
    if (value != NULL) {
      *value = true;
    }
    return true;
  }
  if (len == OC_CHAR_ARRAY_LEN(JSON_FALSE) &&
      strncmp(str, JSON_FALSE, OC_CHAR_ARRAY_LEN(JSON_FALSE)) == 0) {
    if (value != NULL) {
      *value = false;
    }
    return true;
  }
  return false;
#undef JSON_TRUE
#undef JSON_FALSE
}

static bool
json_parse_int(const char *str, size_t len, int64_t *value)
{
  // ASAN with strict_string_checks=true checks that the string is
  // null-terminated
  char buf[32] = { 0 };
  memcpy(buf, str, MIN(len, sizeof(buf) - 1));
  buf[sizeof(buf) - 1] = '\0';
  errno = 0;
  char *eptr = NULL;
  int64_t val = strtoll(buf, &eptr, 10);
  if (errno != 0 || eptr == buf) {
    return false;
  }
  if (value != NULL) {
    *value = val;
  }
  return true;
}

static bool
json_parse_primitive(rep_data_t *data, const char *str, size_t len)
{
  (void)len;
  if (data->cur == NULL) {
    data->err = CborErrorIllegalType;
    return false;
  }
  if (json_parse_null(str, len)) {
    data->cur->type = OC_REP_NIL;
  } else if (json_parse_bool(str, len, &data->cur->value.boolean)) {
    data->cur->type = OC_REP_BOOL;
  } else {
    int64_t value;
    if (!json_parse_int(str, len, &value)) {
      data->err = CborErrorIllegalNumber;
      return false;
    }
    data->cur->type = OC_REP_INT;
    data->cur->value.integer = value;
  }
  data->cur = NULL;
  return true;
}

static bool json_parse_token(const jsmntok_t *token, const char *js,
                             void *data);

static bool
json_parse_object(rep_data_t *data, const char *start, size_t len)
{
  rep_data_t obj_data = {
    .root = NULL,
    .previous = NULL,
    .cur = NULL,
    .err = CborNoError,
  };
  jsmn_parser_t parser;
  jsmn_init(&parser);
  int r = jsmn_parse(&parser, start, len, json_parse_token, &obj_data);
  if (r < 0) {
    oc_free_rep(obj_data.root);
    data->err =
      obj_data.err != CborNoError ? obj_data.err : CborErrorUnexpectedEOF;
    return false;
  }
  if (obj_data.root != NULL &&
      // must have a string key and a valid value
      (oc_string(obj_data.root->name) == NULL ||
       obj_data.root->type == OC_REP_UNKNOWN_TYPE)) {
    oc_free_rep(obj_data.root);
    data->err = CborErrorIllegalType;
    return false;
  }
  if (!json_set_rep(data, OC_REP_OBJECT)) {
    oc_free_rep(obj_data.root);
    return false;
  }
  data->cur->value.object = obj_data.root;
  data->cur = NULL;
  return true;
}

typedef struct
{
  oc_rep_value_type_t type;
  int size;
  CborError err;
} array_scan_data_t;

static bool
json_scan_array_type(const jsmntok_t *token, const char *js, void *data)
{
  array_scan_data_t *array_data = (array_scan_data_t *)data;
  oc_rep_value_type_t type = OC_REP_UNKNOWN_TYPE;
  if (token->type == JSMN_PRIMITIVE) {
    if (json_parse_null(js + token->start, token->end - token->start)) {
      type = OC_REP_NIL;
    } else if (json_parse_bool(js + token->start, token->end - token->start,
                               NULL)) {
      type = OC_REP_BOOL;
    } else if (json_parse_int(js + token->start, token->end - token->start,
                              NULL)) {
      type = OC_REP_INT;
    }
  } else if (token->type == JSMN_STRING) {
    type = OC_REP_STRING;
  } else if (token->type == JSMN_OBJECT) {
    type = OC_REP_OBJECT;
  } else if (token->type == JSMN_ARRAY) {
    type = OC_REP_ARRAY;
  }
  if (type == OC_REP_UNKNOWN_TYPE) {
    array_data->err = CborErrorIllegalType;
    return false;
  }
  if (array_data->type == OC_REP_UNKNOWN_TYPE) {
    array_data->type = type;
  }
  if (array_data->type != type) {
    array_data->err = CborErrorIllegalType;
    return false;
  }
  array_data->size++;
  return true;
}

typedef struct
{
  oc_array_t array;
  size_t idx;
  CborError err;
} json_array_values_t;

static bool
json_assign_array_bool_values(const jsmntok_t *token, const char *js,
                              void *data)
{
  // json_scan_array_type already checked that the token is an array of booleans
  assert(token->type == JSMN_PRIMITIVE);
  json_array_values_t *d = (json_array_values_t *)data;
  if (!json_parse_bool(js + token->start, token->end - token->start,
                       (oc_bool_array(d->array) + d->idx))) {
    d->err = CborErrorIllegalType;
    return false;
  }
  d->idx++;
  return true;
}

static bool
json_parse_array_bool(rep_data_t *data, const char *start, size_t len,
                      size_t array_size)
{
  if (!json_set_rep(data, OC_REP_BOOL_ARRAY)) {
    return false;
  }
  oc_new_bool_array(&data->cur->value.array, array_size);
  json_array_values_t arr_data = {
    .array = data->cur->value.array,
    .idx = 0,
    .err = CborNoError,
  };
  jsmn_parser_t parser;
  jsmn_init(&parser);
  int r =
    jsmn_parse(&parser, start, len, json_assign_array_bool_values, &arr_data);
  if (r < 0) {
    data->err =
      arr_data.err != CborNoError ? arr_data.err : CborErrorUnexpectedEOF;
    return false;
  }
  return true;
}

static bool
json_assign_array_int_values(const jsmntok_t *token, const char *js, void *data)
{
  // json_scan_array_type already checked that the token is an array of integers
  assert(token->type == JSMN_PRIMITIVE);
  json_array_values_t *d = (json_array_values_t *)data;
  int64_t v;
  if (!json_parse_int(js + token->start, token->end - token->start, &v)) {
    d->err = CborErrorIllegalNumber;
    return false;
  }
  *(oc_int_array(d->array) + d->idx) = v;
  d->idx++;
  return true;
}

static bool
json_parse_array_int(rep_data_t *data, const char *start, size_t len,
                     size_t array_size)
{
  if (!json_set_rep(data, OC_REP_INT_ARRAY)) {
    return false;
  }
  oc_new_int_array(&data->cur->value.array, array_size);
  json_array_values_t arr_data = {
    .array = data->cur->value.array,
    .idx = 0,
    .err = CborNoError,
  };
  jsmn_parser_t parser;
  jsmn_init(&parser);
  int r =
    jsmn_parse(&parser, start, len, json_assign_array_int_values, &arr_data);
  if (r < 0) {
    data->err =
      arr_data.err != CborNoError ? arr_data.err : CborErrorUnexpectedEOF;
    return false;
  }
  return true;
}

static bool
json_assign_array_string_values(const jsmntok_t *token, const char *js,
                                void *data)
{
  // json_scan_array_type already checked that the token is an array of strings
  assert(token->type == JSMN_STRING);
  json_array_values_t *d = (json_array_values_t *)data;
  size_t len = token->end - token->start;
  if (len >= STRING_ARRAY_ITEM_MAX_LEN) {
    len = STRING_ARRAY_ITEM_MAX_LEN - 1;
    OC_DBG("Truncating string array item(%s) trucated to %d chars",
           js + token->start, STRING_ARRAY_ITEM_MAX_LEN - 1);
  }
  memcpy(oc_string_array_get_item(d->array, d->idx), js + token->start, len);
  oc_string_array_get_item(d->array, d->idx)[len] = '\0';
  d->idx++;
  return true;
}

static bool
json_parse_array_string(rep_data_t *data, const char *start, size_t len,
                        size_t array_size)
{
  if (!json_set_rep(data, OC_REP_STRING_ARRAY)) {
    return false;
  }
  oc_new_string_array(&data->cur->value.array, array_size);
  json_array_values_t arr_data = {
    .array = data->cur->value.array,
    .idx = 0,
    .err = CborNoError,
  };
  jsmn_parser_t parser;
  jsmn_init(&parser);
  int r =
    jsmn_parse(&parser, start, len, json_assign_array_string_values, &arr_data);
  if (r < 0) {
    data->err =
      arr_data.err != CborNoError ? arr_data.err : CborErrorUnexpectedEOF;
    return false;
  }
  return true;
}

static bool
json_assign_array_object_values(const jsmntok_t *token, const char *js,
                                void *data)
{
  // json_scan_array_type already checked that the token is an array of objects
  assert(token->type == JSMN_OBJECT);
  rep_data_t *d = (rep_data_t *)data;
  return json_parse_object(d, js + token->start, token->end - token->start);
}

static bool
json_parse_array_object(rep_data_t *data, const char *start, size_t len,
                        size_t array_size)
{
  (void)array_size;
  jsmn_parser_t parser;
  jsmn_init(&parser);
  rep_data_t obj_data = {
    .root = NULL,
    .cur = NULL,
    .previous = NULL,
    .err = CborNoError,
  };
  int r =
    jsmn_parse(&parser, start, len, json_assign_array_object_values, &obj_data);
  if (r < 1) {
    if (obj_data.err != CborNoError) {
      oc_free_rep(obj_data.cur);
      return obj_data.err;
    }
    return CborErrorUnexpectedEOF;
  }
  if (!json_set_rep(data, OC_REP_OBJECT_ARRAY)) {
    return false;
  }
  data->cur->value.object_array = obj_data.root;
  return true;
}

typedef bool (*json_array_value_parser_t)(rep_data_t *data, const char *start,
                                          size_t len, size_t array_size);

static bool
json_parse_array(rep_data_t *data, const char *start, size_t len)
{
  array_scan_data_t array_scan_data = {
    .type = OC_REP_UNKNOWN_TYPE,
    .size = 0,
    .err = CborNoError,
  };
  jsmn_parser_t parser;
  jsmn_init(&parser);
  int r =
    jsmn_parse(&parser, start, len, json_scan_array_type, &array_scan_data);
  if (r < 0) {
    data->err = array_scan_data.err != CborNoError ? array_scan_data.err
                                                   : CborErrorUnexpectedEOF;
    return false;
  }
  json_array_value_parser_t value_parser_fn = NULL;
  switch (array_scan_data.type) {
  case OC_REP_ARRAY:
    data->err = CborErrorIllegalType;
    return false;
  case OC_REP_BOOL:
    value_parser_fn = json_parse_array_bool;
    break;
  case OC_REP_INT:
    value_parser_fn = json_parse_array_int;
    break;
  case OC_REP_STRING:
    value_parser_fn = json_parse_array_string;
    break;
  case OC_REP_OBJECT:
    value_parser_fn = json_parse_array_object;
    break;
  default:
    if (!json_set_rep(data, OC_REP_NIL)) {
      return false;
    }
    break;
  }
  if (value_parser_fn != NULL &&
      !value_parser_fn(data, start, len, array_scan_data.size)) {
    return false;
  }
  data->cur = NULL;
  return true;
}

static bool
json_parse_token(const jsmntok_t *token, const char *js, void *data)
{
  rep_data_t *d = (rep_data_t *)data;
  if (token->type == JSMN_PRIMITIVE) {
    return json_parse_primitive(d, js + token->start,
                                token->end - token->start);
  }
  if (token->type == JSMN_STRING) {
    return json_parse_string(d, js + token->start, token->end - token->start);
  }
  if (token->type == JSMN_ARRAY) {
    return json_parse_array(d, js + token->start, token->end - token->start);
  }
  if (token->type == JSMN_OBJECT) {
    return json_parse_object(d, js + token->start, token->end - token->start);
  }
  OC_DBG("Skipping unexpected token type: %d", token->type);
  return true;
}

int
oc_rep_parse_json(const uint8_t *json, size_t json_len, oc_rep_t **out_rep)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  rep_data_t data = {
    .root = NULL,
    .cur = NULL,
    .previous = NULL,
    .err = CborNoError,
  };
  int r =
    jsmn_parse(&parser, (const char *)json, json_len, json_parse_token, &data);
  if (r < 1) {
    return CborErrorUnexpectedEOF;
  }
  assert(data.err == CborNoError);
  if ((data.root->type == OC_REP_OBJECT_ARRAY ||
       data.root->type == OC_REP_OBJECT) &&
      data.root->name.size == 0 && data.root->next == NULL) {
    *out_rep = data.root->value.object_array;
    data.root->value.object_array = NULL;
    oc_free_rep(data.root);
  } else {
    *out_rep = data.root;
  }
  return CborNoError;
}

#endif /* OC_JSON_ENCODER */

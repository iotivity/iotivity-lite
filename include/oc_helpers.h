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
/**
  @file
*/
#ifndef OC_HELPERS_H
#define OC_HELPERS_H

#include "util/oc_list.h"
#include "util/oc_mmem.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_mmem oc_handle_t, oc_string_t, oc_array_t, oc_string_array_t,
  oc_byte_string_array_t;

#define oc_cast(block, type) ((type *)(OC_MMEM_PTR(&(block))))
#define oc_string(ocstring) (oc_cast(ocstring, char))

#ifdef OC_MEMORY_TRACE
#define oc_alloc_string(ocstring, size)                                        \
  _oc_alloc_string(__func__, ocstring, size)
#define oc_new_string(ocstring, str, str_len)                                  \
  _oc_new_string(__func__, ocstring, str, str_len)

#define oc_free_string(ocstring) _oc_free_string(__func__, ocstring)
#define oc_free_int_array(ocarray) (_oc_free_array(__func__, ocarray, INT_POOL))
#define oc_free_bool_array(ocarray)                                            \
  (_oc_free_array(__func__, ocarray, BYTE_POOL))
#define oc_free_double_array(ocarray)                                          \
  (_oc_free_array(__func__, ocarray, DOUBLE_POOL))

#define oc_new_int_array(ocarray, size)                                        \
  (_oc_new_array(__func__, ocarray, size, INT_POOL))
#define oc_new_bool_array(ocarray, size)                                       \
  (_oc_new_array(__func__, ocarray, size, BYTE_POOL))
#define oc_new_double_array(ocarray, size)                                     \
  (_oc_new_array(__func__, ocarray, size, DOUBLE_POOL))

#define oc_new_string_array(ocstringarray, size)                               \
  (_oc_alloc_string_array(__func__, ocstringarray, size))

#define oc_free_string_array(ocstringarray)                                    \
  (_oc_free_string(__func__, ocstringarray))

#define oc_new_byte_string_array(ocstringarray, size)                          \
  (_oc_alloc_string_array(__func__, ocstringarray, size))

#define oc_free_byte_string_array(ocstringarray)                               \
  (__func__, _oc_free_string(ocstringarray))

#else /* OC_MEMORY_TRACE */

#define oc_alloc_string(ocstring, size) _oc_alloc_string((ocstring), (size))
#define oc_new_string(ocstring, str, str_len)                                  \
  _oc_new_string(ocstring, str, str_len)

#define oc_free_string(ocstring) _oc_free_string(ocstring)
#define oc_free_int_array(ocarray) (_oc_free_array(ocarray, INT_POOL))
#define oc_free_bool_array(ocarray) (_oc_free_array(ocarray, BYTE_POOL))
#define oc_free_double_array(ocarray) (_oc_free_array(ocarray, DOUBLE_POOL))

#define oc_new_int_array(ocarray, size) (_oc_new_array(ocarray, size, INT_POOL))
#define oc_new_bool_array(ocarray, size)                                       \
  (_oc_new_array(ocarray, size, BYTE_POOL))
#define oc_new_double_array(ocarray, size)                                     \
  (_oc_new_array(ocarray, size, DOUBLE_POOL))

#define oc_new_string_array(ocstringarray, size)                               \
  (_oc_alloc_string_array(ocstringarray, size))

#define oc_free_string_array(ocstringarray) (_oc_free_string(ocstringarray))

#define oc_new_byte_string_array(ocstringarray, size)                          \
  (_oc_alloc_string_array(ocstringarray, size))

#define oc_free_byte_string_array(ocstringarray)                               \
  (_oc_free_string(ocstringarray))

#endif /* !OC_MEMORY_TRACE */

void oc_concat_strings(oc_string_t *concat, const char *str1, const char *str2);
#define oc_string_len(ocstring) ((ocstring).size ? (ocstring).size - 1 : 0)

#define oc_int_array_size(ocintarray) ((ocintarray).size)
#define oc_bool_array_size(ocboolarray) ((ocboolarray).size)
#define oc_double_array_size(ocdoublearray) ((ocdoublearray).size)
#define oc_int_array(ocintarray) (oc_cast(ocintarray, int64_t))
#define oc_bool_array(ocboolarray) (oc_cast(ocboolarray, bool))
#define oc_double_array(ocdoublearray) (oc_cast(ocdoublearray, double))

#ifdef OC_DYNAMIC_ALLOCATION
#define STRING_ARRAY_ITEM_MAX_LEN 128
#else /* OC_DYNAMIC_ALLOCATION */
#define STRING_ARRAY_ITEM_MAX_LEN 32
#endif /* !OC_DYNAMIC_ALLOCATION */

bool _oc_copy_string_to_array(oc_string_array_t *ocstringarray,
                              const char str[], size_t index);
bool _oc_string_array_add_item(oc_string_array_t *ocstringarray,
                               const char str[]);
void oc_join_string_array(oc_string_array_t *ocstringarray,
                          oc_string_t *ocstring);

bool _oc_copy_byte_string_to_array(oc_string_array_t *ocstringarray,
                                   const char str[], size_t str_len,
                                   size_t index);
bool _oc_byte_string_array_add_item(oc_string_array_t *ocstringarray,
                                    const char str[], size_t str_len);

/* Arrays of text strings */
#define oc_string_array_add_item(ocstringarray, str)                           \
  (_oc_string_array_add_item(&(ocstringarray), str))
#define oc_string_array_get_item(ocstringarray, index)                         \
  (oc_string(ocstringarray) + index * STRING_ARRAY_ITEM_MAX_LEN)
#define oc_string_array_set_item(ocstringarray, str, index)                    \
  (_oc_copy_string_to_array(&(ocstringarray), str, index))
#define oc_string_array_get_item_size(ocstringarray, index)                    \
  (strlen((const char *)oc_string_array_get_item(ocstringarray, index)))
#define oc_string_array_get_allocated_size(ocstringarray)                      \
  ((ocstringarray).size / STRING_ARRAY_ITEM_MAX_LEN)

/* Arrays of byte strings */
#define oc_byte_string_array_add_item(ocstringarray, str, str_len)             \
  (_oc_byte_string_array_add_item(&(ocstringarray), str, str_len))
#define oc_byte_string_array_get_item(ocstringarray, index)                    \
  (oc_string(ocstringarray) + index * STRING_ARRAY_ITEM_MAX_LEN + 1)
#define oc_byte_string_array_set_item(ocstringarray, str, str_len, index)      \
  (_oc_copy_byte_string_to_array(&(ocstringarray), str, str_len, index))
#define oc_byte_string_array_get_item_size(ocstringarray, index)               \
  (*(oc_string(ocstringarray) + index * STRING_ARRAY_ITEM_MAX_LEN))
#define oc_byte_string_array_get_allocated_size(ocstringarray)                 \
  ((ocstringarray).size / STRING_ARRAY_ITEM_MAX_LEN)

void _oc_new_string(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_t *ocstring, const char *str, size_t str_len);

void _oc_alloc_string(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_t *ocstring, size_t size);

void _oc_free_string(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_t *ocstring);

void _oc_free_array(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_array_t *ocarray, pool type);

void _oc_new_array(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_array_t *ocarray, size_t size, pool type);

void _oc_alloc_string_array(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_array_t *ocstringarray, size_t size);

/* Conversions between hex encoded strings and byte arrays */

int oc_conv_byte_array_to_hex_string(const uint8_t *array, size_t array_len,
                                     char *hex_str, size_t *hex_str_len);

int oc_conv_hex_string_to_byte_array(const char *hex_str, size_t hex_str_len,
                                     uint8_t *array, size_t *array_len);

#ifdef __cplusplus
}
#endif

#endif /* OC_HELPERS_H */

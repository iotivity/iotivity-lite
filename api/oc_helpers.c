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

#include "messaging/coap/coap_internal.h"
#include "oc_helpers.h"
#include "oc_helpers_internal.h"
#include "port/oc_assert.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"
#include "util/oc_mmem_internal.h"
#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>

static bool g_mmem_initialized = false;

static void
oc_malloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_handle_t *block, size_t num_items, oc_mmem_pool_t pool_type)
{
  if (!g_mmem_initialized) {
    oc_mmem_init();
    g_mmem_initialized = true;
  }
  size_t alloc_ret = _oc_mmem_alloc(
#ifdef OC_MEMORY_TRACE
    func,
#endif
    block, num_items, pool_type);
  oc_assert(alloc_ret > 0);
}

static void
oc_free(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_handle_t *block, oc_mmem_pool_t pool_type)
{
  _oc_mmem_free(
#ifdef OC_MEMORY_TRACE
    func,
#endif
    block, pool_type);

#ifndef OC_DYNAMIC_ALLOCATION
  block->next = NULL;
#endif /* !OC_DYNAMIC_ALLOCATION */
  block->ptr = NULL;
  block->size = 0;
}

void
_oc_new_string(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_t *ocstring, const char *str, size_t str_len)
{
  oc_malloc(
#ifdef OC_MEMORY_TRACE
    func,
#endif
    ocstring, str_len + 1, BYTE_POOL);
  memcpy(oc_string(*ocstring), (const uint8_t *)str, str_len);
  memcpy(oc_string(*ocstring) + str_len, (const uint8_t *)"", 1);
}

void
_oc_alloc_string(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_t *ocstring, size_t size)
{
  oc_malloc(
#ifdef OC_MEMORY_TRACE
    func,
#endif
    ocstring, size, BYTE_POOL);
}

void
_oc_free_string(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_t *ocstring)
{
  if (ocstring && ocstring->size > 0) {
    oc_free(
#ifdef OC_MEMORY_TRACE
      func,
#endif
      ocstring, BYTE_POOL);
  }
}

void
oc_set_string(oc_string_t *dst, const char *str, size_t str_len)
{
  assert(dst != NULL);

  if (str == NULL || str_len == 0) {
    oc_free_string(dst);
    memset(dst, 0, sizeof(*dst));
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_free_string(dst);
  oc_new_string(dst, str, str_len);
#else  /* !OC_DYNAMIC_ALLOCATION */
  oc_string_t copy;
  // create a oc_string_t to ensure that str won't get invalidated by
  // oc_free_string
  oc_new_string(&copy, str, str_len);
  oc_free_string(dst);
  oc_new_string(dst, oc_string(copy), oc_string_len(copy));
  oc_free_string(&copy);
#endif /* OC_DYNAMIC_ALLOCATION */
}

oc_string_view_t
oc_string_view(const char *data, size_t length)
{
  oc_string_view_t view = {
    .data = data,
    .length = length,
  };
  return view;
}

oc_string_view_t
oc_string_view2(const oc_string_t *str)
{
  if (str == NULL) {
    return oc_string_view(NULL, 0);
  }
  return oc_string_view(oc_string(*str), oc_string_len(*str));
}

bool
oc_string_view_is_equal(oc_string_view_t str1, oc_string_view_t str2)
{
  return str1.length == str2.length &&
         (str1.length == 0 || memcmp(str1.data, str2.data, str1.length) == 0);
}

bool
oc_string_is_equal(const oc_string_t *str1, const oc_string_t *str2)
{
  return oc_string_view_is_equal(oc_string_view2(str1), oc_string_view2(str2));
}

bool
oc_string_is_cstr_equal(const oc_string_t *str1, const char *str2,
                        size_t str2_len)
{
  if (str1 == NULL || oc_string(*str1) == NULL) {
    return str2 == NULL;
  }
  return oc_string_view_is_equal(oc_string_view2(str1),
                                 oc_string_view(str2, str2_len));
}

void
oc_copy_string(oc_string_t *dst, const oc_string_t *src)
{
  assert(dst != NULL);
  if (dst == src) {
    return;
  }

  oc_free_string(dst);
  if (src == NULL || oc_string(*src) == NULL) {
    memset(dst, 0, sizeof(*dst));
    return;
  }
  oc_new_string(dst, oc_string(*src), oc_string_len(*src));
}

void
oc_concat_strings(oc_string_t *concat, const char *str1, const char *str2)
{
  size_t len1 = strlen(str1);
  size_t len2 = strlen(str2);
  oc_alloc_string(concat, len1 + len2 + 1);
  memcpy(oc_string(*concat), str1, len1);
  memcpy(oc_string(*concat) + len1, str2, len2);
  oc_string(*concat)[len1 + len2] = '\0';
}

void
_oc_new_array(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_array_t *ocarray, size_t size, oc_mmem_pool_t type)
{
  switch (type) {
  case INT_POOL:
  case BYTE_POOL:
  case DOUBLE_POOL:
    oc_malloc(
#ifdef OC_MEMORY_TRACE
      func,
#endif
      ocarray, size, type);
    break;
  default:
    break;
  }
}

void
_oc_free_array(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_array_t *ocarray, oc_mmem_pool_t type)
{
  oc_free(
#ifdef OC_MEMORY_TRACE
    func,
#endif
    ocarray, type);
}

void
_oc_alloc_string_array(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  oc_string_array_t *ocstringarray, size_t size)
{
  _oc_alloc_string(
#ifdef OC_MEMORY_TRACE
    func,
#endif
    ocstringarray, size * STRING_ARRAY_ITEM_MAX_LEN);

  for (size_t i = 0; i < size; ++i) {
    size_t pos = i * STRING_ARRAY_ITEM_MAX_LEN;
    memcpy(oc_string(*ocstringarray) + pos, (const char *)"", 1);
  }
}

bool
_oc_copy_byte_string_to_array(oc_string_array_t *ocstringarray,
                              const char str[], size_t str_len, size_t index)
{
  assert(index < oc_string_array_get_allocated_size(*ocstringarray));
  if (str_len >= STRING_ARRAY_ITEM_MAX_LEN) {
    return false;
  }
  size_t pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  oc_cast(*ocstringarray, uint8_t)[pos] = (uint8_t)str_len;
  pos++;
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t *)str, str_len);
  return true;
}

bool
_oc_byte_string_array_add_item(oc_string_array_t *ocstringarray,
                               const char str[], size_t str_len)
{
  for (size_t i = 0;
       i < oc_byte_string_array_get_allocated_size(*ocstringarray); ++i) {
    if (oc_byte_string_array_get_item_size(*ocstringarray, i) == 0) {
      return oc_byte_string_array_set_item(*ocstringarray, str, str_len, i);
    }
  }
  return false;
}

bool
_oc_copy_string_to_array(oc_string_array_t *ocstringarray, const char str[],
                         size_t index)
{
  size_t len = strlen(str);
  if (len >= STRING_ARRAY_ITEM_MAX_LEN) {
    return false;
  }
  size_t pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t *)str, len);
  oc_string(*ocstringarray)[pos + len] = '\0';
  return true;
}

bool
_oc_string_array_add_item(oc_string_array_t *ocstringarray, const char str[])
{
  for (size_t i = 0; i < oc_string_array_get_allocated_size(*ocstringarray);
       ++i) {
    if (oc_string_array_get_item_size(*ocstringarray, i) == 0) {
      return oc_string_array_set_item(*ocstringarray, str, i);
    }
  }
  return false;
}

void
oc_join_string_array(oc_string_array_t *ocstringarray, oc_string_t *ocstring)
{
  size_t len = 0;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(*ocstringarray);
       ++i) {
    size_t item_len = oc_string_array_get_item_size(*ocstringarray, i);
    if (item_len != 0) {
      len += item_len;
      len++;
    }
  }
  oc_alloc_string(ocstring, len);
  len = 0;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(*ocstringarray);
       ++i) {
    const char *item =
      (const char *)oc_string_array_get_item(*ocstringarray, i);
    size_t item_len = strlen(item);
    if (item_len != 0) {
      if (len > 0) {
        oc_string(*ocstring)[len] = ' ';
        len++;
      }
      memcpy(oc_string(*ocstring) + len, item, item_len);
      len += item_len;
    }
  }
  oc_string(*ocstring)[len] = '\0';
}

int
oc_conv_byte_array_to_hex_string(const uint8_t *array, size_t array_len,
                                 char *hex_str, size_t *hex_str_len)
{
  if (*hex_str_len < array_len * 2 + 1) {
    return -1;
  }
  size_t hlen = 0;
  for (size_t i = 0; i < array_len; i++) {
    snprintf(hex_str + hlen, 3, "%02x", array[i]);
    hlen += 2;
  }
  hex_str[hlen] = '\0';
  *hex_str_len = hlen;
  return 0;
}

int
oc_conv_hex_string_to_byte_array(const char *hex_str, size_t hex_str_len,
                                 uint8_t *array, size_t *array_len)
{
  if (hex_str_len < 1) {
    return -1;
  }

  size_t len = hex_str_len / 2;
  if ((hex_str_len % 2) != 0) {
    ++len;
  }
  if (*array_len < len) {
    return -1;
  }
  *array_len = len;

  size_t a = 0;
  size_t start = 0;
  if (hex_str_len % 2 != 0) {
    start = 1;
    uint32_t tmp;
    sscanf(&hex_str[0], "%1" SCNx32, &tmp);
    array[a++] = (uint8_t)tmp;
  }

  for (size_t i = start; i + 2 <= hex_str_len; i += 2) {
    uint32_t tmp;
    sscanf(&hex_str[i], "%2" SCNx32, &tmp);
    array[a++] = (uint8_t)tmp;
  }

  return 0;
}

void
oc_random_buffer(uint8_t *buffer, size_t buffer_size)
{
  assert(buffer != NULL);
  size_t i = 0;
  while (i < buffer_size) {
    uint32_t r = oc_random_value();
    memcpy(buffer + i, &r, MIN(sizeof(r), buffer_size - i));
    i += sizeof(r);
  }
}

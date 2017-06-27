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

#include "oc_helpers.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include <stdbool.h>

static bool mmem_initialized = false;

static void
oc_malloc(oc_handle_t *block, int num_items, pool pool_type)
{
  if (!mmem_initialized) {
    oc_mmem_init();
    mmem_initialized = true;
  }
  oc_assert(oc_mmem_alloc(block, num_items, pool_type) > 0);
}

static void
oc_free(oc_handle_t *block, pool pool_type)
{
  oc_mmem_free(block, pool_type);
  block->next = 0;
  block->ptr = 0;
  block->size = 0;
}

void
oc_new_string(oc_string_t *ocstring, const char *str, int str_len)
{
  oc_malloc(ocstring, str_len + 1, BYTE_POOL);
  memcpy(oc_string(*ocstring), (const uint8_t *)str, str_len);
  memcpy(oc_string(*ocstring) + str_len, (const uint8_t *)"", 1);
}

void
oc_alloc_string(oc_string_t *ocstring, int size)
{
  oc_malloc(ocstring, size, BYTE_POOL);
}

void
oc_free_string(oc_string_t *ocstring)
{
  oc_free(ocstring, BYTE_POOL);
}

void
oc_concat_strings(oc_string_t *concat, const char *str1, const char *str2)
{
  size_t len1 = strlen(str1), len2 = strlen(str2);
  oc_alloc_string(concat, len1 + len2 + 1);
  memcpy(oc_string(*concat), str1, len1);
  memcpy(oc_string(*concat) + len1, str2, len2);
  memcpy(oc_string(*concat) + len1 + len2, (const char *)"", 1);
}

void
_oc_new_array(oc_array_t *ocarray, int size, pool type)
{
  switch (type) {
  case INT_POOL:
    oc_malloc(ocarray, size, INT_POOL);
    break;
  case BYTE_POOL:
    oc_malloc(ocarray, size, BYTE_POOL);
    break;
  case DOUBLE_POOL:
    oc_malloc(ocarray, size, DOUBLE_POOL);
    break;
  default:
    break;
  }
}

void
_oc_free_array(oc_array_t *ocarray, pool type)
{
  oc_free(ocarray, type);
}

void
_oc_alloc_string_array(oc_string_array_t *ocstringarray, int size)
{
  oc_alloc_string(ocstringarray, size * STRING_ARRAY_ITEM_MAX_LEN);
  int i, pos;
  for (i = 0; i < size; i++) {
    pos = i * STRING_ARRAY_ITEM_MAX_LEN;
    memcpy((char *)oc_string(*ocstringarray) + pos, (const char *)"", 1);
  }
}

bool
_oc_copy_string_to_string_array(oc_string_array_t *ocstringarray,
                                const char str[], int index)
{
  if (strlen(str) >= STRING_ARRAY_ITEM_MAX_LEN) {
    return false;
  }
  int pos = index * STRING_ARRAY_ITEM_MAX_LEN;
  size_t len = strlen(str);
  memcpy(oc_string(*ocstringarray) + pos, (const uint8_t *)str, len);
  memcpy(oc_string(*ocstringarray) + pos + len, (const uint8_t *)"", 1);
  return true;
}

bool
_oc_string_array_add_item(oc_string_array_t *ocstringarray, const char str[])
{
  bool success = false;
  size_t i;
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++) {
    if (oc_string_array_get_item_size(*ocstringarray, i) == 0) {
      success = oc_string_array_set_item(*ocstringarray, str, i);
      break;
    }
  }
  return success;
}

void
oc_join_string_array(oc_string_array_t *ocstringarray, oc_string_t *ocstring)
{
  size_t len = 0;
  size_t i;
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++) {
    const char *item =
      (const char *)oc_string_array_get_item(*ocstringarray, i);
    if (strlen(item)) {
      len += strlen(item);
      len++;
    }
  }
  oc_alloc_string(ocstring, len);
  len = 0;
  for (i = 0; i < oc_string_array_get_allocated_size(*ocstringarray); i++) {
    const char *item =
      (const char *)oc_string_array_get_item(*ocstringarray, i);
    if (strlen(item)) {
      if (len > 0) {
        oc_string(*ocstring)[len] = ' ';
        len++;
      }
      memcpy((char *)oc_string(*ocstring) + len, item, strlen(item));
      len += strlen(item);
    }
  }
  strcpy((char *)oc_string(*ocstring) + len, "");
}

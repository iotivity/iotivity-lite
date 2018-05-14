/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifdef OC_DYNAMIC_ALLOCATION

#include "oc_list.h"
#include "port/oc_log.h"
#include <stdio.h>
#include <stdlib.h>

#ifdef OC_MEMORY_TRACE
#include "oc_mem_trace.h"

typedef struct _mem_item
{
  struct mem_item_s *next;
  size_t mem_size;
  void *mem_address;
} mem_item_s;

OC_LIST(mem_list);

static mem_item_s *
oc_mem_list_search(void *address)
{

  mem_item_s *obs = (mem_item_s *)oc_list_head(mem_list), *next = NULL;

  while (obs) {
    next = oc_list_item_next(obs);
    if (obs->mem_address == address) {
      return obs;
    }
    obs = next;
  }

  return NULL;
}
#endif /* OC_MEMORY_TRACE */

void *
_oc_mem_malloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  size_t size)
{
  void *ptr = malloc(size);

#ifdef OC_MEMORY_TRACE
  if (!ptr)
    return NULL;

  mem_item_s *mem_item = calloc(1, sizeof(mem_item_s));
  if (!mem_item) {
    OC_ERR("insufficient memory to create new mem_item");
    return ptr;
  }

  mem_item->mem_size = size;
  mem_item->mem_address = ptr;
  oc_list_push(mem_list, mem_item);

  oc_mem_trace_add_pace(func, size, MEM_TRACE_ALLOC, ptr);
#endif /* OC_MEMORY_TRACE */

  return ptr;
}

void *
_oc_mem_calloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  size_t num, size_t calloc_size)
{
  void *ptr = calloc(num, calloc_size);

#ifdef OC_MEMORY_TRACE
  if (!ptr)
    return NULL;

  mem_item_s *mem_item = calloc(1, sizeof(mem_item_s));
  if (!mem_item) {
    OC_ERR("insufficient memory to create new mem_item");
    return ptr;
  }

  mem_item->mem_size = calloc_size * num;
  mem_item->mem_address = ptr;
  oc_list_push(mem_list, mem_item);

  oc_mem_trace_add_pace(func, calloc_size * num, MEM_TRACE_ALLOC, ptr);

#endif /* OC_MEMORY_TRACE */
  return ptr;
}

void *
_oc_mem_realloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  void *realloc_ptr, size_t realloc_size)
{
  void *ptr = realloc(realloc_ptr, realloc_size);

#ifdef OC_MEMORY_TRACE
  if (!ptr)
    return NULL;

  mem_item_s *mem_item = NULL;
  mem_item = oc_mem_list_search(realloc_ptr);

  if (mem_item) {
    oc_mem_trace_add_pace(func, mem_item->mem_size, MEM_TRACE_FREE,
                          mem_item->mem_address);
  } else {
    mem_item = calloc(1, sizeof(mem_item_s));
    if (!mem_item) {
      OC_ERR("insufficient memory to create new mem_item");
      return ptr;
    }
  }

  mem_item->mem_size = realloc_size;
  mem_item->mem_address = ptr;
  oc_list_push(mem_list, mem_item);

  oc_mem_trace_add_pace(func, realloc_size, MEM_TRACE_REALLOC, ptr);

#endif /* OC_MEMORY_TRACE */
  return ptr;
}

void
_oc_mem_free(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  void *ptr)
{
  free(ptr);

#ifdef OC_MEMORY_TRACE
  size_t size = 0;
  mem_item_s *mem_item = NULL;
  mem_item = oc_mem_list_search(ptr);
  if (mem_item) {
    size = mem_item->mem_size;
    oc_list_remove(mem_list, mem_item);
  } else {
    OC_ERR("mem_list doesn't have %x to free", ptr);
  }
  oc_mem_trace_add_pace(func, size, MEM_TRACE_FREE, ptr);
#endif /* OC_MEMORY_TRACE */
}
#else  /* !OC_DYNAMIC_ALLOCATION */
// TODO : it would be removed if OC_DYNAMIC_ALLOCATION=0 excludes compiling this
// file
void
dummy_null_mem_func(void)
{
}
#endif  /* OC_DYNAMIC_ALLOCATION */
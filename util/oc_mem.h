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

#ifndef OC_MEM_H
#define OC_MEM_H

#ifdef OC_DYNAMIC_ALLOCATION

void *_oc_mem_malloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  size_t size);

void *_oc_mem_calloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  size_t num, size_t calloc_size);

void *_oc_mem_realloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  void *realloc_ptr, size_t realloc_size);

void *_oc_mem_free(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  void *ptr);

#ifdef OC_MEMORY_TRACE
#define oc_mem_malloc(size) (void *)_oc_mem_malloc(__func__, size)
#define oc_mem_calloc(num, size) (void *)_oc_mem_calloc(__func__, num, size)
#define oc_mem_realloc(ptr, size) (void *)_oc_mem_realloc(__func__, ptr, size)
#define oc_mem_free(ptr) _oc_mem_free(__func__, ptr)
#else
#define oc_mem_malloc(size) (void *)_oc_mem_malloc(size)
#define oc_mem_calloc(num, size) (void *)_oc_mem_calloc(num, size)
#define oc_mem_realloc(ptr, size) (void *)_oc_mem_realloc(ptr, size)
#define oc_mem_free(ptr) _oc_mem_free(ptr)
#endif /* OC_MEMORY_TRACE */

#else /* !OC_DYNAMIC_ALLOCATION */

#define oc_mem_malloc(size) NULL
#define oc_mem_calloc(num, size) NULL
#define oc_mem_realloc(ptr, size) NULL
#define oc_mem_free(ptr) ((void)ptr)

#endif /* OC_DYNAMIC_ALLOCATION */

#endif /* OC_MEM_H */
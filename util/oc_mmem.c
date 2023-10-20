/*
 * Copyright (c) 2016 Intel Corporation
 *
 * Copyright (c) 2005, Swedish Institute of Computer Science
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 */

#include "oc_config.h"
#include "oc_list.h"
#include "oc_mmem.h"
#include "oc_mmem_internal.h"
#include "port/oc_log_internal.h"

#ifdef OC_MEMORY_TRACE
#include "util/oc_mem_trace_internal.h"
#endif /* OC_MEMORY_TRACE */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifndef OC_DYNAMIC_ALLOCATION
#if !defined(OC_BYTES_POOL_SIZE) || !defined(OC_INTS_POOL_SIZE) ||             \
  !defined(OC_DOUBLES_POOL_SIZE)
#error "Please define byte, int, double pool sizes in oc_config.h"
#endif /* !OC_BYTES_POOL_SIZE || !OC_INTS_POOL_SIZE || !OC_DOUBLES_POOL_SIZE   \
        */

static unsigned char g_mmem_bytes[OC_BYTES_POOL_SIZE] = { 0 };
static unsigned int g_mmem_avail_bytes = OC_BYTES_POOL_SIZE;
OC_LIST(g_mmem_bytes_list);

static int64_t g_mmem_ints[OC_INTS_POOL_SIZE] = { 0 };
static unsigned int g_mmem_avail_ints = OC_INTS_POOL_SIZE;
OC_LIST(g_mmem_ints_list);

static double g_mmem_doubles[OC_DOUBLES_POOL_SIZE] = { 0.0 };
static unsigned int g_mmem_avail_doubles = OC_DOUBLES_POOL_SIZE;
OC_LIST(g_mmem_doubles_list);
#endif /* !OC_DYNAMIC_ALLOCATION */

static uint8_t
memm_type_size(oc_mmem_pool_t pool_type)
{
  switch (pool_type) {
  case BYTE_POOL:
    return sizeof(unsigned char);
  case INT_POOL:
    return sizeof(int64_t);
  case DOUBLE_POOL:
    return sizeof(double);
  }
  return 0;
}

size_t
_oc_mmem_alloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  struct oc_mmem *m, size_t size, oc_mmem_pool_t pool_type)
{
  if (!m) {
    OC_ERR("oc_mmem is NULL");
    return 0;
  }

  const uint8_t type_size = memm_type_size(pool_type);
  size_t bytes_allocated = size * type_size;
#ifdef OC_DYNAMIC_ALLOCATION
  m->ptr = malloc(size * type_size);
  m->size = size;
#else  /* !OC_DYNAMIC_ALLOCATION */
  switch (pool_type) {
  case BYTE_POOL:
    if (g_mmem_avail_bytes < size) {
      OC_WRN("byte pool exhausted");
      return 0;
    }
    oc_list_add(g_mmem_bytes_list, m);
    m->ptr = &g_mmem_bytes[OC_BYTES_POOL_SIZE - g_mmem_avail_bytes];
    m->size = size;
    g_mmem_avail_bytes -= size;
    break;
  case INT_POOL:
    if (g_mmem_avail_ints < size) {
      OC_WRN("int pool exhausted");
      return 0;
    }
    oc_list_add(g_mmem_ints_list, m);
    m->ptr = &g_mmem_ints[OC_INTS_POOL_SIZE - g_mmem_avail_ints];
    m->size = size;
    g_mmem_avail_ints -= size;
    break;
  case DOUBLE_POOL:
    if (g_mmem_avail_doubles < size) {
      OC_WRN("double pool exhausted");
      return 0;
    }
    oc_list_add(g_mmem_doubles_list, m);
    m->ptr = &g_mmem_doubles[OC_DOUBLES_POOL_SIZE - g_mmem_avail_doubles];
    m->size = size;
    g_mmem_avail_doubles -= size;
    break;
  }
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_add_pace(func, bytes_allocated, MEM_TRACE_ALLOC, m->ptr);
#endif

  return (int)bytes_allocated;
}

void
_oc_mmem_free(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  struct oc_mmem *m, oc_mmem_pool_t pool_type)
{
  if (!m) {
    OC_ERR("oc_mmem is NULL");
    return;
  }

#if defined(OC_MEMORY_TRAC) || !defined(OC_DYNAMIC_ALLOCATION)
  const uint8_t type_size = memm_type_size(pool_type);
#endif /* OC_MEMORY_TRACE || !OC_DYNAMIC_ALLOCATION */

#ifdef OC_MEMORY_TRACE
  unsigned int bytes_freed = m->size * type_size;
  oc_mem_trace_add_pace(func, bytes_freed, MEM_TRACE_FREE, m->ptr);
#endif /* OC_MEMORY_TRACE */

#ifndef OC_DYNAMIC_ALLOCATION
  struct oc_mmem *n;

  if (m->next != NULL) {
    switch (pool_type) {
    case BYTE_POOL:
      memmove(m->ptr, m->next->ptr,
              (&g_mmem_bytes[OC_BYTES_POOL_SIZE - g_mmem_avail_bytes] -
               (unsigned char *)m->next->ptr) *
                type_size);

      break;
    case INT_POOL:
      memmove(m->ptr, m->next->ptr,
              (&g_mmem_ints[OC_INTS_POOL_SIZE - g_mmem_avail_ints] -
               (int64_t *)m->next->ptr) *
                type_size);
      break;
    case DOUBLE_POOL:
      memmove(m->ptr, m->next->ptr,
              (&g_mmem_doubles[OC_DOUBLES_POOL_SIZE - g_mmem_avail_doubles] -
               (double *)m->next->ptr) *
                type_size);
      break;
    }
    for (n = m->next; n != NULL; n = n->next) {
      if (pool_type == BYTE_POOL) {
        n->ptr = (void *)((unsigned char *)n->ptr - m->size);
        continue;
      }
      if (pool_type == INT_POOL) {
        n->ptr = (void *)((int64_t *)n->ptr - m->size);
        continue;
      }
      if (pool_type == DOUBLE_POOL) {
        n->ptr = (void *)((double *)n->ptr - m->size);
        continue;
      }
    }
  }

  switch (pool_type) {
  case BYTE_POOL:
    g_mmem_avail_bytes += m->size;
    oc_list_remove(g_mmem_bytes_list, m);
    break;
  case INT_POOL:
    g_mmem_avail_ints += m->size;
    oc_list_remove(g_mmem_ints_list, m);
    break;
  case DOUBLE_POOL:
    g_mmem_avail_doubles += m->size;
    oc_list_remove(g_mmem_doubles_list, m);
    break;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  (void)pool_type;
  free(m->ptr);
  m->size = 0;
#endif /* OC_DYNAMIC_ALLOCATION */
}

#ifndef OC_DYNAMIC_ALLOCATION

size_t
oc_mmem_available_size(oc_mmem_pool_t pool_type)
{
  if (pool_type == BYTE_POOL) {
    return g_mmem_avail_bytes;
  }
  if (pool_type == INT_POOL) {
    return g_mmem_avail_ints;
  }
  if (pool_type == DOUBLE_POOL) {
    return g_mmem_avail_doubles;
  }
  return 0;
}

#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_mmem_init(void)
{
#ifndef OC_DYNAMIC_ALLOCATION
  static bool initialized = false;
  if (initialized) {
    return;
  }
  oc_list_init(g_mmem_bytes_list);
  oc_list_init(g_mmem_ints_list);
  oc_list_init(g_mmem_doubles_list);
  g_mmem_avail_bytes = OC_BYTES_POOL_SIZE;
  g_mmem_avail_ints = OC_INTS_POOL_SIZE;
  g_mmem_avail_doubles = OC_DOUBLES_POOL_SIZE;
  initialized = true;
#endif /* OC_DYNAMIC_ALLOCATION */
}

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

#ifndef OC_MMEM_INTERNAL_H
#define OC_MMEM_INTERNAL_H

#include <util/oc_mmem.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus

#ifdef OC_DYNAMIC_ALLOCATION
#define OC_MMEM(ptr, size, next)                                               \
  oc_mmem                                                                      \
  {                                                                            \
    (size), (ptr),                                                             \
  }

#else /* !OC_DYNAMIC_ALLOCATION */
#define OC_MMEM(ptr, size, next)                                               \
  oc_mmem                                                                      \
  {                                                                            \
    (next), (size), (ptr),                                                     \
  }
#endif /* OC_DYNAMIC_ALLOCATION */

#else /* !__cplusplus */

#ifdef OC_DYNAMIC_ALLOCATION
#define OC_MMEM(ptr, size, next)                                               \
  (struct oc_mmem)                                                             \
  {                                                                            \
    (size), (ptr),                                                             \
  }

#else /* !OC_DYNAMIC_ALLOCATION */
#define OC_MMEM(ptr, size, next)                                               \
  (struct oc_mmem)                                                             \
  {                                                                            \
    (next), (size), (ptr),                                                     \
  }
#endif /* OC_DYNAMIC_ALLOCATION */

#endif /* __cplusplus */

#define OC_MMEM_NULL() OC_MMEM(NULL, 0, NULL)

void oc_mmem_init(void);

#ifdef OC_MEMORY_TRACE

#define oc_mmem_alloc(m, size, pool_type)                                      \
  _oc_mmem_alloc(__func__, m, size, pool_type)
#define oc_mmem_free(m, pool_type) _oc_mmem_free(__func__, m, pool_type)

#else /* OC_MEMORY_TRACE */

#define oc_mmem_alloc(m, size, pool_type) _oc_mmem_alloc(m, size, pool_type)
#define oc_mmem_free(m, pool_type) _oc_mmem_free(m, pool_type)

#endif /* !OC_MEMORY_TRACE */

size_t _oc_mmem_alloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  struct oc_mmem *m, size_t size, oc_mmem_pool_t pool_type);

void _oc_mmem_free(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  struct oc_mmem *m, oc_mmem_pool_t pool_type);

#ifdef __cplusplus
}
#endif

#endif /* OC_MMEM_INTERNAL_H */

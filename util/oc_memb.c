/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
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
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "oc_memb.h"
#include "port/oc_log.h"
#include <string.h>

#ifdef OC_MEMORY_TRACE
#include "oc_mem_trace.h"
#endif

/*---------------------------------------------------------------------------*/
void
oc_memb_init(struct oc_memb *m)
{
  if (m->num > 0) {
    memset(m->count, 0, m->num);
    memset(m->mem, 0, (unsigned)m->num * sizeof(char *));
  }
}
/*---------------------------------------------------------------------------*/
void *
_oc_memb_alloc(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  struct oc_memb *m)
{
  if (!m) {
    OC_ERR("oc_memb is NULL");
    return NULL;
  }

  int i = m->num;
  void *ptr = NULL;
  if (m->num > 0) {
    for (i = 0; i < m->num; i++) {
      if (m->count[i] == 0) {
        /* If this block was unused, we increase the reference count to
     indicate that it now is used and return a pointer to the
     memory block. */
        ++(m->count[i]);
        break;
      }
    }

    if (i < m->num) {
      ptr = (void *)((char *)m->mem + (i * m->size));
      memset(ptr, 0, m->size);
    }
  }
#ifdef OC_DYNAMIC_ALLOCATION
  else {
    ptr = calloc(1, m->size);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  if (!ptr) {
    /* No free block was found, so we return NULL to indicate failure to
       allocate block. */
    return NULL;
  }

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_add_pace(func, m->size, MEM_TRACE_ALLOC, ptr);
#endif

  return ptr;
}
/*---------------------------------------------------------------------------*/
char
_oc_memb_free(
#ifdef OC_MEMORY_TRACE
  const char *func,
#endif
  struct oc_memb *m, void *ptr)
{
  if (!m) {
    OC_ERR("oc_memb is NULL");
    return -1;
  }

#ifdef OC_MEMORY_TRACE
  oc_mem_trace_add_pace(func, m->size, MEM_TRACE_FREE, ptr);
#endif

  int i = m->num;
  char *ptr2 = NULL;
  if (m->num > 0) {
    /* Walk through the list of blocks and try to find the block to
       which the pointer "ptr" points to. */
    ptr2 = (char *)m->mem;
    for (i = 0; i < m->num; ++i) {
      if (ptr2 == (char *)ptr) {
        /* We've found to block to which "ptr" points so we decrease the
           reference count and return the new value of it. */
        if (m->count[i] > 0) {
          /* Make sure that we don't deallocate free memory. */
          --(m->count[i]);
        }
        break;
      }
      ptr2 += m->size;
    }
  }
#ifdef OC_DYNAMIC_ALLOCATION
  else {
    free(ptr);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  if (m->buffers_avail_cb) {
    m->buffers_avail_cb(oc_memb_numfree(m));
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
int
oc_memb_inmemb(struct oc_memb *m, void *ptr)
{
  return (char *)ptr >= (char *)m->mem &&
         (char *)ptr < (char *)m->mem + (m->num * m->size);
}
/*---------------------------------------------------------------------------*/
int
oc_memb_numfree(struct oc_memb *m)
{
  int i;
  int num_free = 0;

  for (i = 0; i < m->num; ++i) {
    if (m->count[i] == 0) {
      ++num_free;
    }
  }

  return num_free;
}
/*---------------------------------------------------------------------------*/
void
oc_memb_set_buffers_avail_cb(struct oc_memb *m,
                             oc_memb_buffers_avail_callback_t cb)
{
  m->buffers_avail_cb = cb;
}
/*---------------------------------------------------------------------------*/

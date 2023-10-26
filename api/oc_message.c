/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation, All Rights Reserved.
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

#include "api/oc_message_internal.h"
#include "oc_buffer.h"
#include "oc_config.h"
#include "port/oc_allocator_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "util/oc_atomic.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_INOUT_BUFFER_POOL
OC_MEMB_STATIC(oc_incoming_buffers, oc_message_t, OC_INOUT_BUFFER_POOL);
OC_MEMB_STATIC(oc_outgoing_buffers, oc_message_t, OC_INOUT_BUFFER_POOL);
#else  /* !OC_INOUT_BUFFER_POOL */
OC_MEMB(oc_incoming_buffers, oc_message_t, OC_MAX_NUM_CONCURRENT_REQUESTS);
OC_MEMB(oc_outgoing_buffers, oc_message_t, OC_MAX_NUM_CONCURRENT_REQUESTS);
#endif /* OC_INOUT_BUFFER_POOL */

static void
message_deallocate(oc_message_t *message, struct oc_memb *pool)
{
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
  free(message->data);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
  oc_allocator_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
  oc_memb_free(pool, message);
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
  oc_allocator_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
}

static oc_message_t *
message_allocate_with_size(struct oc_memb *pool, size_t size)
{
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
  oc_allocator_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
  oc_message_t *message = (oc_message_t *)oc_memb_alloc(pool);
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
  oc_allocator_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
  if (message == NULL) {
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
    OC_WRN("buffer: No free TX/RX buffers!");
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
    return NULL;
  }
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
  message->data = (uint8_t *)malloc(size);
  if (message->data == NULL) {
    OC_ERR("Out of memory, cannot allocate message");
    message_deallocate(message, pool);
    return NULL;
  }
  memset(message->data, 0, size);
#else  /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  (void)size;
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
  message->pool = pool;
  message->length = 0;
  message->next = 0;
  message->ref_count = 1;
  message->endpoint.interface_index = 0;
#ifdef OC_SECURITY
  message->encrypted = 0;
#endif /* OC_SECURITY */
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
  OC_DBG("buffer: Allocated TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
  OC_DBG("buffer: allocated message(%p) from pool(%p)", (void *)message,
         (void *)pool);
  return message;
}

static oc_message_t *
message_allocate(struct oc_memb *pool)
{
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_SIZE)
  return message_allocate_with_size(pool, OC_PDU_SIZE);
#else  /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_SIZE */
  return message_allocate_with_size(pool, 0);
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_SIZE */
}

size_t
oc_message_buffer_size(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
#ifdef OC_INOUT_BUFFER_SIZE
  return OC_ARRAY_SIZE(((oc_message_t *)(NULL))->data);
#else
  return OC_PDU_SIZE;
#endif /* OC_DYNAMIC_ALLOCATION && OC_INOUT_BUFFER_SIZE */
#else  /* !OC_DYNAMIC_ALLOCATION */
  return OC_ARRAY_SIZE(((oc_message_t *)(NULL))->data);
#endif /* OC_DYNAMIC_ALLOCATION  */
}

oc_message_t *
oc_allocate_message_from_pool(struct oc_memb *pool)
{
  if (pool) {
    return message_allocate(pool);
  }
  return NULL;
}

void
oc_set_buffers_avail_cb(oc_memb_buffers_avail_callback_t cb)
{
  oc_memb_set_buffers_avail_cb(&oc_incoming_buffers, cb);
}

oc_message_t *
oc_allocate_message(void)
{
  return message_allocate(&oc_incoming_buffers);
}

oc_message_t *
oc_message_allocate_with_size(size_t size)
{
  return message_allocate_with_size(&oc_incoming_buffers, size);
}

oc_message_t *
oc_message_allocate_outgoing(void)
{
  return message_allocate(&oc_outgoing_buffers);
}

oc_message_t *
oc_message_allocate_outgoing_with_size(size_t size)
{
  return message_allocate_with_size(&oc_outgoing_buffers, size);
}

void
oc_message_add_ref(oc_message_t *message)
{
  if (message == NULL) {
    return;
  }
  bool swapped = false;
  uint8_t count = OC_ATOMIC_LOAD8(message->ref_count);
  while (!swapped) { // NOLINT(bugprone-infinite-loop)
    OC_ATOMIC_COMPARE_AND_SWAP8(message->ref_count, count, count + 1, swapped);
  }
}

void
oc_message_unref(oc_message_t *message)
{
  if (message == NULL) {
    return;
  }
  bool dealloc = false;
  uint8_t count = OC_ATOMIC_LOAD8(message->ref_count);
  uint8_t new_count = 0;
  while (count > 0) {
    bool swapped = false;
    new_count = count - 1;
    OC_ATOMIC_COMPARE_AND_SWAP8(message->ref_count, count, new_count, swapped);
    if (swapped) {
      dealloc = new_count == 0;
      break;
    }
  }

  if (!dealloc) {
    OC_DBG("buffer: message(%p) unreferenced, ref_count=%d", (void *)message,
           (int)new_count);
    return;
  }

  struct oc_memb *pool = message->pool;
  message_deallocate(message, pool);
  OC_DBG("buffer: deallocated message(%p) from pool(%p)", (void *)message,
         (void *)pool);
#if !defined(OC_DYNAMIC_ALLOCATION) || defined(OC_INOUT_BUFFER_POOL)
  OC_DBG("buffer: freed TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */
}

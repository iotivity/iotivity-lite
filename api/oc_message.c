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
#include "util/oc_features.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#include <assert.h>

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
message_deallocate(oc_message_t *message, oc_memb_t *pool)
{
#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
  free(message->data);
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  oc_allocator_mutex_lock();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
  oc_memb_free(pool, message);
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  oc_allocator_mutex_unlock();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
}

static oc_message_t *
message_allocate_with_size(oc_memb_t *pool, size_t size)
{
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  oc_allocator_mutex_lock();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
  oc_message_t *message = (oc_message_t *)oc_memb_alloc(pool);
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  oc_allocator_mutex_unlock();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
  if (message == NULL) {
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
    OC_WRN("buffer: No free TX/RX buffers!");
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
    return NULL;
  }
#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
  message->data = (uint8_t *)malloc(size);
  if (message->data == NULL) {
    OC_ERR("Out of memory, cannot allocate message");
    message_deallocate(message, pool);
    return NULL;
  }
  memset(message->data, 0, size);
  message->size = size;
#else  /* !OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
  (void)size;
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
  message->pool = pool;
  message->length = 0;
  message->next = 0;
  message->ref_count = 1;
  message->endpoint.interface_index = 0;
#ifdef OC_SECURITY
  message->encrypted = 0;
#endif /* OC_SECURITY */
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  OC_TRACE("buffer: Allocated TX/RX buffer; num free: %d",
           oc_memb_numfree(pool));
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
  OC_TRACE("buffer: allocated message(%p) from pool(%p)", (void *)message,
           (void *)pool);
  return message;
}

static oc_message_t *
message_allocate(oc_memb_t *pool)
{
#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
  return message_allocate_with_size(pool, OC_PDU_SIZE);
#else  /* !OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
  return message_allocate_with_size(pool, 0);
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
}

size_t
oc_message_max_buffer_size(void)
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

size_t
oc_message_buffer_size(const oc_message_t *message)
{
  assert(message != NULL);
#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
  if (message->data == NULL) {
    return 0;
  }
  return message->size;
#else  /* !OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
  (void)message;
  return oc_message_max_buffer_size();
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */
}

oc_message_t *
oc_allocate_message_from_pool(oc_memb_t *pool)
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

uint8_t
oc_message_refcount(const oc_message_t *message)
{
  return OC_ATOMIC_LOAD8(message->ref_count);
}

void
oc_message_deallocate(oc_message_t *message)
{
  oc_memb_t *pool = message->pool;
  message_deallocate(message, pool);
  OC_TRACE("buffer: deallocated message(%p) from pool(%p)", (void *)message,
           (void *)pool);
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  OC_TRACE("buffer: freed TX/RX buffer; num free: %d", oc_memb_numfree(pool));
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX*/
}

bool
oc_message_unref2(oc_message_t *message)
{
  if (message == NULL) {
    return false;
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
    OC_TRACE("buffer: message(%p) unreferenced, ref_count=%d", (void *)message,
             (int)new_count);
    return false;
  }
  oc_message_deallocate(message);
  return true;
}

void
oc_message_unref(oc_message_t *message)
{
  oc_message_unref2(message);
}

#ifdef OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER
void
oc_message_shrink_buffer(oc_message_t *message, size_t size)
{
  size_t old_size = oc_message_buffer_size(message);
  if (size == old_size) {
    return;
  }
  uint8_t *new_data = (uint8_t *)realloc(message->data, size);
  if (new_data == NULL && size > 0) {
    OC_ERR("Out of memory, cannot shrink message buffer");
    return;
  }
  message->data = new_data;
  message->size = size;
  if (message->length > size) {
    message->length = size;
  }
}
#endif /* OC_HAS_FEATURE_MESSAGE_DYNAMIC_BUFFER */

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

#ifndef OC_BUFFER_H
#define OC_BUFFER_H

#include "port/oc_connectivity.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

OC_PROCESS_NAME(message_buffer_handler);
/* create incomming message with buffer alloc as much as OC_PDU_SIZE */
oc_message_t *oc_allocate_message(void);

void oc_set_buffers_avail_cb(oc_memb_buffers_avail_callback_t cb);

oc_message_t *oc_allocate_message_from_pool(struct oc_memb *pool);

/* create outgoing message with buffer alloc as much as OC_PDU_SIZE */
oc_message_t *oc_internal_allocate_outgoing_message(void);

#ifdef OC_DYNAMIC_ALLOCATION
/* create incomming message with buffer size setting,
  in case of 0 size, do not alloc buffer for later relloc */
oc_message_t *oc_allocate_message_by_size(size_t size);
/* create outgoing message with buffer size setting,
  in case of 0 size, do not alloc buffer now for later relloc */
oc_message_t *oc_internal_allocate_outgoing_message_by_size(size_t size);
/* rellocate message buffer for resize or late alloc */
oc_message_t *oc_reallocate_message_by_size(oc_message_t *message, size_t size);
#endif

void oc_message_add_ref(oc_message_t *message);
void oc_message_unref(oc_message_t *message);

void oc_recv_message(oc_message_t *message);
void oc_send_message(oc_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* OC_BUFFER_H */

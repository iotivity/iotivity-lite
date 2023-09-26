/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifndef OC_PORT_ALLOCATOR_INTERNAL_H
#define OC_PORT_ALLOCATOR_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \defgroup allocator Allocation synchronization
 *
 * If a struct is allocated and deallocated in multiple threads, it must be
 * protected by a mutex.
 *
 * Known cases of multithreaded allocation:
 *
 * - oc_message_t when allocated by oc_memb pool (oc_allocate_message)
 * - oc_endpoint_t when allocated by oc_memb pool (oc_new_endpoint)
 * - oc_tcp_on_connect_event_t when allocated by oc_memb pool
 * (oc_tcp_on_connect_event_create
 *
 * Struct oc_memb pool needs synchronization when dynamic allocation is
 * disabled. Since all known cases are allocated by oc_memb pool with static
 * allocation, we ifdef out the mutexes when dynamic allocation is disabled.
 *
 * @{
 */

#ifndef OC_DYNAMIC_ALLOCATION

/** @brief initialize the allocator mutex */
void oc_allocator_mutex_init(void);

/** @brief lock the allocator mutex */
void oc_allocator_mutex_lock(void);

/** @brief unlock the allocator mutex */
void oc_allocator_mutex_unlock(void);

/** @brief destroy the network event handler mutex */
void oc_allocator_mutex_destroy(void);

#endif /* !OC_DYNAMIC_ALLOCATION */

/** @} */

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_ALLOCATOR_INTERNAL_H */

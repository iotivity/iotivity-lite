/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#ifndef OC_PING_INTERNAL_H
#define OC_PING_INTERNAL_H

#if defined(OC_CLIENT) && defined(OC_TCP)

#include "oc_ri.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OC_PING_URI "/ping"

/** Ping timeout callback */
oc_event_callback_retval_t oc_remove_ping_handler_async(void *data);

#ifdef __cplusplus
}
#endif

#endif /* OC_CLIENT && OC_TCP */

#endif /* OC_PING_INTERNAL_H */

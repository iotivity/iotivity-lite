/****************************************************************************
 *
 * Copyright (c) 2022 plgd.dev s.r.o.
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

#ifndef OC_UDP_INTERNAL_H
#define OC_UDP_INTERNAL_H

#include "port/oc_connectivity.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Check if the message is a valid CoAP/TLS header */
bool oc_udp_is_valid_message(oc_message_t *message);

#ifdef __cplusplus
}
#endif

#endif /* OC_UDP_INTERNAL_H */

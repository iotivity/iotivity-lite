/****************************************************************************
 *
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#ifndef PLGD_WOT_INTERNAL_H
#define PLGD_WOT_INTERNAL_H

#include <stddef.h>
#include <oc_ri.h>

#ifdef __cplusplus
extern "C" {
#endif

void plgd_wot_init(void);

void plgd_wot_get_handler(oc_request_t *request, oc_interface_mask_t iface_mask, void *data);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_WOT_INTERNAL_H */

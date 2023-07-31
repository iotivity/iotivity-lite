/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#ifndef OC_MAIN_INTERNAL_H
#define OC_MAIN_INTERNAL_H

#include "oc_api.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_factory_presets_t
{
  oc_factory_presets_cb_t cb;
  void *data;
} oc_factory_presets_t;

oc_factory_presets_t *oc_get_factory_presets_cb(void);

/** @brief Check if the IoT stack is initialized. */
bool oc_main_initialized(void);

/**
 * Set acceptance of new commands(GET/PUT/POST/DELETE) for logical device
 *
 * The device drops/accepts new commands when the drop is set to true/false.
 *
 * @note If OC_SECURITY is set, this call is used to drop all new incoming
 *       commands during closing TLS sessions (CLOSE_ALL_TLS_SESSIONS).
 *
 * @param[in] device index of the logical device
 * @param[in] drop set whether all new commands will be accepted/dropped
 */
void oc_set_drop_commands(size_t device, bool drop);

/**
 * Get status of dropping of logical device.
 *
 * @param[in] device the index of the logical device
 *
 * @return true if the device dropping new commands
 */
bool oc_drop_command(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_MAIN_INTERNAL_H */

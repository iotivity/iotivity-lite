/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

#ifndef OC_PSTAT_INTERNAL_H
#define OC_PSTAT_INTERNAL_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Reset all devices in RFOTM state for shutdown.
 */
void oc_reset_devices_in_RFOTM(void);

/**
 * @brief Checks whether a command should be discarded when a TLS connection is
 * scheduled to be closed.
 *
 * This function evaluates whether it is appropriate to discard a command when a
 * TLS connection is scheduled to be closed. It returns true if the command
 * should be discarded, indicating that it's not suitable for execution in the
 * context of a closing TLS connection, and false otherwise.
 *
 * @param[in] device the index of the logical device
 *
 * @return True if the command should be discarded, false otherwise.
 */
bool oc_should_drop_command_on_reset(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_PSTAT_H */

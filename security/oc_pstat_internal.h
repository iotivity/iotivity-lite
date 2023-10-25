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

#include "oc_ri.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  OC_DOS_RESET = 0,
  OC_DOS_RFOTM,
  OC_DOS_RFPRO,
  OC_DOS_RFNOP,
  OC_DOS_SRESET
} oc_dostype_t;

typedef enum {
  OC_DPM_SVV = 64,
  OC_DPM_SSV = 128,
  OC_DPM_NSA = 256
} oc_dpmtype_t;

typedef struct
{
  oc_dostype_t s;         ///< Device Onboarding State
  bool p;                 ///< Pending state
  bool isop;              ///< Is Device Operational oc_dpmtype_t cm;
  oc_dpmtype_t cm;        ///< Current Mode
  oc_dpmtype_t tm;        ///< Target Mode
  int om;                 ///< Operational Mode
  int sm;                 ///< Supported Mode
  oc_uuid_t rowneruuid;   ///< Resource Owner ID
  bool reset_in_progress; ///< Reset in progress runtime flag
} oc_sec_pstat_t;

#define OC_PSTAT_RESET_DELAY_MS (2000)

void oc_sec_pstat_init(void);
void oc_sec_pstat_free(void);
bool oc_sec_is_operational(size_t device);
bool oc_sec_decode_pstat(const oc_rep_t *rep, bool from_storage, size_t device);
void oc_sec_encode_pstat(size_t device, oc_interface_mask_t iface_mask,
                         bool to_storage);

oc_sec_pstat_t *oc_sec_get_pstat(size_t device);
void oc_sec_pstat_default(size_t device);
void oc_sec_pstat_copy(oc_sec_pstat_t *dst, const oc_sec_pstat_t *src);

/**
 * @brief Reset pstat to default values.
 *
 * @param pstat the pstat to reset (cannot be NULL)
 * @param resetToDefault use values set by reset operation as the default
 * (otherwise all values are set to 0)
 */
void oc_sec_pstat_clear(oc_sec_pstat_t *pstat, bool resetToDefault)
  OC_NONNULL();

void get_pstat(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *data);
void post_pstat(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *data);

#ifdef OC_SOFTWARE_UPDATE

void oc_sec_pstat_set_current_mode(size_t device, oc_dpmtype_t cm);
oc_dpmtype_t oc_sec_pstat_current_mode(size_t device);

#endif /* OC_SOFTWARE_UPDATE */

#define OC_PSTAT_DOS_ID_FLAG(id) (1 << (id))

/**
 * @brief Check if device is in one of the DOS states.
 *
 * @param device device index
 * @param dos_mask mask of DOS states to check (created by OR-ing values from
 * OC_PSTAT_DOS_ID_FLAG(oc_dostype_t))
 * @return true if device is in one of the DOS states
 * @return false otherwise
 */
bool oc_sec_pstat_is_in_dos_state(size_t device, unsigned dos_mask);

/**
 * @brief Reset all devices in RFOTM state for shutdown.
 */
void oc_reset_devices_in_RFOTM(void);

/**
 * @brief Checks if reset is in progress.
 *
 * @param[in] device the index of the logical device
 *
 * @return True if the reset is in progress, false otherwise.
 */
bool oc_reset_in_progress(size_t device);

/**
 * @brief Initialize pstat for num devices.
 *
 * @param[in] num_device the number of devices
 */
void oc_sec_pstat_init_for_devices(size_t num_device);

#ifdef OC_TEST

/**
 * @brief Set interval in milliseconds before delayed reset is performed.
 *
 * @param delay_ms the interval in milliseconds
 *
 * @sa oc_reset_device_v1
 */
void oc_pstat_set_reset_delay_ms(uint64_t delay_ms);

/** @brief Get reset delay interval in milliseconds. */
uint64_t oc_pstat_get_reset_delay_ms(void);

#endif /* OC_TEST */

#ifdef __cplusplus
}
#endif

#endif /* OC_PSTAT_H */

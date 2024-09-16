/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifndef PLGD_DPS_DHCP_INTERNAL_H
#define PLGD_DPS_DHCP_INTERNAL_H

#include "util/oc_compiler.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  uint8_t option_code_dps_endpoint;
  uint8_t option_code_dps_certificate_fingerprint;
  uint8_t option_code_dps_certificate_fingerprint_md_type;
} plgd_dps_dhcp_t;

/**
 * @brief Initialize the DHCP configuration.
 *
 * @param[out] dhcp pointer to DHCP configuration to initialize (cannot be NULL)
 */
void plgd_dps_dhcp_init(plgd_dps_dhcp_t *dhcp) OC_NONNULL();

typedef struct
{
  const plgd_dps_dhcp_t *dhcp; ///< pointer to the DHCP configuration
  const uint8_t *endpoint; ///< offset from DHCP vendor encapsulated options to
                           ///< the DPS endpoint
  size_t
    endpoint_size; ///< parsed from DHCP vendor encapsulated options DPS
                   ///< endpoint size (without the terminating null character)
  const uint8_t
    *certificate_fingerprint; ///< offset from DHCP vendor encapsulated options
                              ///< to the DPS certificate fingerprint
  size_t
    certificate_fingerprint_size; ///< parsed from DHCP vendor encapsulated
                                  ///< options DPS certificate fingerprint size
  const uint8_t
    *certificate_fingerprint_md_type; ///< offset from DHCP vendor encapsulated
                                      ///< options to the DPS certificate
                                      ///< fingerprint MD type
  size_t certificate_fingerprint_md_type_size; ///< parsed from DHCP vendor
                                               ///< encapsulated options DPS
                                               ///< certificate fingerprint MD
                                               ///< type size
} dhcp_parse_data_t;

/**
 * @brief Parse the DPS configuration from the DHCP vendor encapsulated options.
 *
 * The parsed data are stored in the dhcp_parse_data_t structure. The data
 * are not copied.
 *
 * @param[out] dhcp_parse_data pointer to the structure where the parsed data
 * are stored (cannot be NULL)
 * @param[in] vendor_encapsulated_options pointer to the DHCP vendor
 * encapsulated options (cannot be NULL)
 * @param[in] vendor_encapsulated_options_size size of the DHCP vendor
 * encapsulated options
 * @return true if the parsing was successful
 */
bool dps_dhcp_parse_vendor_encapsulated_options(
  dhcp_parse_data_t *dhcp_parse_data,
  const uint8_t *vendor_encapsulated_options,
  size_t vendor_encapsulated_options_size) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_DHCP_INTERNAL_H */

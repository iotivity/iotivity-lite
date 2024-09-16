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

#ifndef PLGD_DPS_RESOURCE_INTERNAL_H
#define PLGD_DPS_RESOURCE_INTERNAL_H

#include "plgd/plgd_dps.h"

#include "api/oc_helpers_internal.h"
#include "oc_api.h"
#include "oc_config.h"
#include "util/oc_compiler.h"
#include "util/oc_endpoint_address_internal.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Create /plgd/dps resource
oc_resource_t *dps_create_dpsconf_resource(size_t device);

/// @brief Delete /plgd/dps resource
void dps_delete_dpsconf_resource(oc_resource_t *res);

/// @brief Convert DPS status to provisioning status
oc_string_view_t dps_status_to_str(uint32_t status);

#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES

enum { DPS_CLOUD_RETRY_TIMEOUTS_SIZE = 6 };

typedef struct
{
  uint16_t retry_timeout[DPS_CLOUD_RETRY_TIMEOUTS_SIZE];
} dps_resource_iotivity_data_t;

typedef struct
{
  plgd_cloud_status_observer_configuration_t cloud_status_observer;
  dps_resource_iotivity_data_t iotivity;
} dps_resource_test_data_t;

#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */

typedef struct
{
  plgd_dps_error_t last_error;
  const char *provision_status;
  size_t provision_status_length;
  const oc_endpoint_addresses_t *endpoints;
  bool forceReprovision;
#ifdef PLGD_DPS_RESOURCE_TEST_PROPERTIES
  dps_resource_test_data_t test;
#endif /* PLGD_DPS_RESOURCE_TEST_PROPERTIES */
} dps_resource_data_t;

/// @brief Encode DPS data to root payload
void dps_resource_encode(oc_interface_mask_t interface,
                         const oc_resource_t *resource,
                         const dps_resource_data_t *data);

/// @brief Initialize DPS update data list
void dps_update_list_init(void);

/// @brief Clean-up DPS update data list
void dps_update_list_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_RESOURCE_INTERNAL_H */

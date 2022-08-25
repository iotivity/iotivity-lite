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

#ifndef OC_ESP_H
#define OC_ESP_H

#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_ESP_MAC_ADDRESS_SIZE (18)

typedef struct
{
  char address[OC_ESP_MAC_ADDRESS_SIZE];
} oc_esp_mac_address_t;

/**
 * @brief Get MAC address of the device.
 *
 * @param[out] address output variable to store the obtained address (cannot be
 * NULL)
 * @return true on success
 * @return false otherwise
 */
bool oc_esp_get_mac_address(oc_esp_mac_address_t *mac) OC_NONNULL();

/**
 * @brief Get application version from runtime.
 *
 * The application version value is taken from PROJECT_VER variable in the
 * CMakeLists.txt, or from CONFIG_APP_PROJECT_VER value if
 * CONFIG_APP_PROJECT_VER_FROM_CONFIG is set, or from
 * $(PROJECT_PATH)/version.txt file.
 *
 * @return application version
 *
 * @see
 * https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-reference/system/misc_system_api.html#app-version
 */
const char *oc_esp_get_application_version(void) OC_RETURNS_NONNULL;

#ifdef __cplusplus
}
#endif

#endif /* OC_ESP_H */

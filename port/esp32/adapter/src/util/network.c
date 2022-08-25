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

#include "oc_esp.h"
#include "port/oc_log_internal.h"

#include <esp_err.h>
#include <esp_mac.h>
#include <assert.h>
#include <stdio.h>

bool
oc_esp_get_mac_address(oc_esp_mac_address_t *mac)
{
  assert(mac != NULL);
  uint8_t mac_addr[8] = { 0 };
  esp_err_t err = esp_efuse_mac_get_default(mac_addr);
  if (err != ESP_OK) {
    OC_ERR("failed to get MAC address: %s", esp_err_to_name(err));
    return false;
  }
  char address[OC_ESP_MAC_ADDRESS_SIZE];
  int ret = snprintf(address, sizeof(address), "%02x:%02x:%02x:%02x:%02x:%02x",
                     mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
                     mac_addr[4], mac_addr[5]);
  if (ret < 0 || ret >= OC_ESP_MAC_ADDRESS_SIZE) {
    return false;
  }
  memcpy(mac->address, address, sizeof(address));
  return true;
}

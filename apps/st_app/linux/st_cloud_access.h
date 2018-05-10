/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "easysetup.h"
#include "samsung/sc_easysetup.h"
#include <stdbool.h>

typedef enum {
  CLOUD_ACCESS_INITIALIZE,
  CLOUD_ACCESS_PROCRESSING,
  CLOUD_ACCESS_FINISH,
  CLOUD_ACCESS_PING,
  CLOUD_ACCESS_PING_FAIL,
  CLOUD_ACCESS_FAIL,
  CLOUD_ACCESS_DISCONNECTED,
  CLOUD_ACCESS_RE_CONNECTING
} st_cloud_access_status_t;

typedef void (*st_cloud_access_cb_t)(st_cloud_access_status_t status);

bool st_cloud_access_start(es_coap_cloud_conf_data *cloud_info,
                           oc_link_t *publish_resources, int device_index,
                           st_cloud_access_cb_t cb);
void st_cloud_access_stop(int device_index);

st_cloud_access_status_t get_cloud_access_status(int device_index);

bool st_cloud_access_check_connection(const char *ci_server);
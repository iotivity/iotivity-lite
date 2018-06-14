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

#ifndef ST_CLOUD_MANAGER_H
#define ST_CLOUD_MANAGER_H

#include "st_store.h"

typedef enum {
  CLOUD_MANAGER_INITIALIZE = 0,
  CLOUD_MANAGER_SIGNED_UP = 1 << 0,
  CLOUD_MANAGER_SIGNED_IN = 1 << 1,
  CLOUD_MANAGER_PUBLISHED = 1 << 2,
  CLOUD_MANAGER_FINISH = 1 << 3,
  CLOUD_MANAGER_FAIL = 1 << 4,
  CLOUD_MANAGER_RE_CONNECTING = 1 << 5,
  CLOUD_MANAGER_RESET = 1 << 6
} st_cloud_manager_status_t;

typedef void (*st_cloud_manager_cb_t)(st_cloud_manager_status_t status);

int st_cloud_manager_start(st_store_t *cloud_info, int device_index,
                           st_cloud_manager_cb_t cb);
void st_cloud_manager_stop(int device_index);

int st_cloud_manager_check_connection(oc_string_t *ci_server);

#endif /* ST_CLOUD_MANAGER_H */
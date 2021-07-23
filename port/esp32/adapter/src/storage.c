/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include <oc_config.h>
#include "port/oc_storage.h"

#ifdef OC_STORAGE
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include "nvs_flash.h"
#include "debug_print.h"

#define STORE_PATH_SIZE 64

static char store_path[STORE_PATH_SIZE];
static int store_path_len;
static bool path_set = false;

int oc_storage_config(const char *store)
{
  store_path_len = strlen(store);
  if (store_path_len >= STORE_PATH_SIZE)
    return -ENOENT;

  memcpy(store_path, store, store_path_len);
  store_path[store_path_len] = '\0';
  path_set = true;

  return 0;
}

long oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  APP_DBG("oc_storage_read: %s", store);
  if (!path_set)
  {
    return -ENOENT;
  }
  nvs_handle_t handle;
  esp_err_t err = nvs_open(store_path, NVS_READONLY, &handle);
  if (err != ESP_OK)
  {
    APP_DBG("oc_storage_read cannot nvs_open %s: %d", store, err);
    return -EINVAL;
  }

  err = nvs_get_blob(handle, store, buf, &size);
  if (err != ESP_OK)
  {
    APP_DBG("oc_storage_read cannot nvs_get_blob  %s: %d", store, err);
    nvs_close(handle);
    return -EINVAL;
  }

  nvs_close(handle);
  return size;
}

long oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
  //APP_DBG("oc_storage_write: %s", store);
  if (!path_set)
  {
    return -ENOENT;
  }
  nvs_handle_t handle;
  esp_err_t err = nvs_open(store_path, NVS_READWRITE, &handle);
  if (err != ESP_OK)
  {
    APP_DBG("oc_storage_write cannot nvs_open  %s: %d", store, err);
    return -EINVAL;
  }

  err = nvs_set_blob(handle, store, buf, size);
  if (err != ESP_OK)
  {
    APP_DBG("oc_storage_write cannot nvs_set_blob  %s: %d", store, err);
    nvs_close(handle);
    return -EINVAL;
  }

  err = nvs_commit(handle);
  if (err != ESP_OK)
  {
    APP_DBG("oc_storage_write cannot nvs_commit  %s: %d", store, err);
    nvs_close(handle);
    return -EINVAL;
  }

  return size;
}
#endif /* OC_SECURITY */

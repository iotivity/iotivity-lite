/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include <oc_config.h>

#ifdef OC_STORAGE
#include "nvs_flash.h"
#include "port/oc_log_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "util/oc_secure_string_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#define OC_STORE_PATH_SIZE 64

#define NVS_PARTITION "appdata"
// takes 4.94s

static char g_store_path[OC_STORE_PATH_SIZE] = { 0 };
static bool g_path_set = false;

int
oc_storage_config(const char *store)
{
  if (store == NULL || store[0] == '\0') {
    return -EINVAL;
  }

  size_t store_len = strlen(store);
  if (store_len >= OC_STORE_PATH_SIZE) {
    return -ENOENT;
  }

  esp_err_t err = nvs_flash_init_partition(NVS_PARTITION);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_config cannot nvs_flash_init_partition %s: %s",
           NVS_PARTITION, esp_err_to_name(err));
    return -EINVAL;
  }
  memcpy(g_store_path, store, store_len);
  g_store_path[store_len] = '\0';
  g_path_set = true;
  return 0;
}

bool
oc_storage_path(char *buffer, size_t buffer_size)
{
  if (!g_path_set) {
    return false;
  }
  if (buffer != NULL) {
    size_t store_len = oc_strnlen(g_store_path, OC_STORE_PATH_SIZE);
    if (store_len == OC_STORE_PATH_SIZE || store_len >= buffer_size) {
      return false;
    }
    memcpy(buffer, g_store_path, store_len + 1);
  }
  return true;
}

int
oc_storage_reset(void)
{
  esp_err_t err = nvs_flash_deinit_partition(NVS_PARTITION);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_config cannot nvs_flash_deinit_partition %s: %s",
           NVS_PARTITION, esp_err_to_name(err));
    return -EINVAL;
  }
  g_path_set = false;
  g_store_path[0] = '\0';
  return 0;
}

static int
storage_open(const char *store, nvs_handle_t *handle)
{
  if (!g_path_set) {
    return -ENOENT;
  }

  esp_err_t err =
    nvs_open_from_partition(NVS_PARTITION, g_store_path, NVS_READWRITE, handle);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_read cannot nvs_open_from_partition %s: %s", store,
           esp_err_to_name(err));
    return -EINVAL;
  }
  return 0;
}

long
oc_storage_size(const char *store)
{
  nvs_handle_t handle;
  int ret = storage_open(store, &handle);
  if (ret < 0) {
    return ret;
  }

  size_t required_size;
  esp_err_t err = nvs_get_blob(handle, store, NULL, &required_size);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_read cannot nvs_get_blob  %s: %s", store,
           esp_err_to_name(err));
    nvs_close(handle);
    return -EINVAL;
  }
  nvs_close(handle);
  return (long)required_size;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  OC_DBG("oc_storage_read: %s", store);
  nvs_handle_t handle;
  int ret = storage_open(store, &handle);
  if (ret < 0) {
    return ret;
  }

  esp_err_t err = nvs_get_blob(handle, store, buf, &size);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_read cannot nvs_get_blob  %s: %s", store,
           esp_err_to_name(err));
    nvs_close(handle);
    return -EINVAL;
  }
  nvs_close(handle);
  return size;
}

long
oc_storage_write(const char *store, const uint8_t *buf, size_t size)
{
  OC_DBG("oc_storage_write: %s, %d", store, size);
  if (!g_path_set) {
    return -ENOENT;
  }

  nvs_handle_t handle;
  esp_err_t err = nvs_open_from_partition(NVS_PARTITION, g_store_path,
                                          NVS_READWRITE, &handle);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_write cannot nvs_open_from_partition %s: %s", store,
           esp_err_to_name(err));
    return -EINVAL;
  }

  err = nvs_set_blob(handle, store, buf, size);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_write cannot nvs_set_blob  %s: %s", store,
           esp_err_to_name(err));
    nvs_close(handle);
    return -EINVAL;
  }

  err = nvs_commit(handle);
  if (err != ESP_OK) {
    OC_ERR("oc_storage_write cannot nvs_commit  %s: %s", store,
           esp_err_to_name(err));
    nvs_close(handle);
    return -EINVAL;
  }

  nvs_close(handle);

  return size;
}
#endif /* OC_STORAGE */

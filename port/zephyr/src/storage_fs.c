/*
// Copyright (c) 2022 Kistler Instruments AG, Winterthur, Switzerland
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

#include "port/oc_storage.h"
#include <oc_config.h>

#ifdef OC_STORAGE
#include <logging/log.h>
LOG_MODULE_REGISTER(oc_storage, LOG_LEVEL_DBG);
#include <fs/fs.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#define STORE_PATH_SIZE 64

static char store_path[STORE_PATH_SIZE];
static int store_path_len;
static bool path_set = false;

int
oc_storage_config(const char *store)
{
  LOG_DBG("oc_storage_config: %s", store);
  store_path_len = strlen(store);
  if (store_path_len >= STORE_PATH_SIZE)
    return -ENOENT;

  memcpy(store_path, store, store_path_len);
  store_path[store_path_len] = '\0';
  path_set = true;
  return 0;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  LOG_DBG("oc_storage_read: %s", store);
  size_t store_len = strlen(store);
  if (!path_set || (1 + store_len + store_path_len >= STORE_PATH_SIZE)) {
    return -ENOENT;
  }

  store_path[store_path_len] = '/';
  strncpy(store_path + store_path_len + 1, store, store_len);
  store_path[1 + store_path_len + store_len] = '\0';

  struct fs_file_t file;
  fs_file_t_init(&file);

  int rc = fs_open(&file, store_path, FS_O_READ);
  if (rc < 0) {
      LOG_ERR("oc_storage_read: Cannot open %s: %d", store_path, rc);
      return -EINVAL;
  }
  rc = fs_read(&file, buf, size);
  if (rc < 0) {
      LOG_ERR("oc_storage_read: Cannot read %s: %d", store_path, rc);
      fs_close(&file);
      return -EINVAL;
  }
  rc = fs_close(&file);
  if (rc < 0) {
      LOG_ERR("oc_storage_read: Cannot close %s: %d", store_path, rc);
  }
  return size;
}

long
oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
  LOG_DBG("oc_storage_read: %s", store);
  size_t store_len = strlen(store);
  if (!path_set || (1 + store_len + store_path_len >= STORE_PATH_SIZE)) {
    return -ENOENT;
  }

  store_path[store_path_len] = '/';
  strncpy(store_path + store_path_len + 1, store, store_len);
  store_path[1 + store_path_len + store_len] = '\0';

  struct fs_file_t file;
  fs_file_t_init(&file);

  int rc = fs_open(&file, store_path, FS_O_CREATE | FS_O_RDWR);
  if (rc < 0) {
      LOG_ERR("oc_storage_read: Cannot open %s: %d", store_path, rc);
      return -EINVAL;
  }
  rc = fs_write(&file, buf, size);
  if (rc < 0) {
      LOG_ERR("oc_storage_read: Cannot write %s: %d", store_path, rc);
      fs_close(&file);
      return -EINVAL;
  }
  rc = fs_close(&file);
  if (rc < 0) {
      LOG_ERR("oc_storage_read: Cannot close %s: %d", store_path, rc);
  }
  return size;
}
#endif /* OC_STORAGE */

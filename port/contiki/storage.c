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

#ifdef OC_SECURITY

#include "port/oc_storage.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <cfs/cfs.h>

#define STORE_PATH_SIZE 64

static char store_path[STORE_PATH_SIZE];
static int store_path_len;
static bool path_set = false;

int
oc_storage_config(const char *store)
{
  store_path_len = strlen(store);
  if (store_path_len >= STORE_PATH_SIZE)
    return -ENOENT;

  strncpy(store_path, store, store_path_len);
  path_set = true;

  return 0;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  int fd;
  size_t store_len = strlen(store);

  if (!path_set || (store_len + store_path_len >= STORE_PATH_SIZE))
    return -ENOENT;

  strncpy(store_path + store_path_len, store, store_len);
  store_path[store_path_len + store_len] = '\0';
  fd = cfs_open(store_path, CFS_READ);
  if (!fd)
    return -EINVAL;

  size = cfs_read(fd, buf, size);
  cfs_close(fd);
  return size;
}

long
oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
  int fd;
  size_t store_len = strlen(store);

  if (!path_set || (store_len + store_path_len >= STORE_PATH_SIZE))
    return -ENOENT;

  strncpy(store_path + store_path_len, store, store_len);
  store_path[store_path_len + store_len] = '\0';
  fd = cfs_open(store_path, CFS_WRITE);
  if (!fd)
    return -EINVAL;

  size = cfs_write(fd, buf, size);
  cfs_close(fd);
  return size;
}

#endif /* OC_SECURITY */

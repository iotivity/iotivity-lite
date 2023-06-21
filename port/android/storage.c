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

#include "oc_config.h"

#ifdef OC_STORAGE
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define STORE_PATH_SIZE 128

static char g_store_path[STORE_PATH_SIZE] = { 0 };
static size_t g_store_path_len = 0;
static bool g_path_set = false;

int
oc_storage_config(const char *store)
{
  size_t store_len = strlen(store);
  if (store_len >= STORE_PATH_SIZE) {
    return -ENOENT;
  }

  g_store_path_len = store_len;
  strncpy(g_store_path, store, g_store_path_len);
  g_path_set = true;

  return 0;
}

int
oc_storage_reset(void)
{
  g_path_set = false;
  g_store_path_len = 0;
  g_store_path[0] = '\0';
  return 0;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  FILE *fp = 0;
  size_t store_len = strlen(store);

  if (!g_path_set || (1 + store_len + g_store_path_len >= STORE_PATH_SIZE)) {
    return -ENOENT;
  }

  g_store_path[g_store_path_len] = '/';
  strncpy(g_store_path + g_store_path_len + 1, store, store_len);
  g_store_path[1 + g_store_path_len + store_len] = '\0';
  fp = fopen(g_store_path, "rb");
  if (fp == NULL) {
    return -EINVAL;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    goto error;
  }
  long fsize = ftell(fp);
  if (fsize < 0) {
    goto error;
  }
  if ((size_t)fsize > size) {
    errno = EINVAL;
    goto error;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    goto error;
  }

  size = fread(buf, 1, size, fp);
  fclose(fp);
  return (long)size;

error:
  fclose(fp);
  return -errno;
}

long
oc_storage_write(const char *store, const uint8_t *buf, size_t size)
{
  size_t store_len = strlen(store);
  if (!g_path_set || (store_len + g_store_path_len >= STORE_PATH_SIZE)) {
    return -ENOENT;
  }

  g_store_path[g_store_path_len] = '/';
  strncpy(g_store_path + g_store_path_len + 1, store, store_len);
  g_store_path[1 + g_store_path_len + store_len] = '\0';
  FILE *fp = fopen(g_store_path, "wb");
  if (!fp)
    return -EINVAL;

  size = fwrite(buf, 1, size, fp);
  fclose(fp);
  return size;
}
#endif /* OC_STORAGE */

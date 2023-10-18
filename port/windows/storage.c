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
#include "storage.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static char g_store_path[OC_STORE_PATH_SIZE] = { 0 };
static uint8_t g_store_path_len = 0;

int
oc_storage_config(const char *store)
{
  if (store == NULL || store[0] == '\0') {
    return -EINVAL;
  }

  size_t store_len = oc_strnlen(store, OC_STORE_PATH_SIZE);
  if (store_len >= OC_STORE_PATH_SIZE) {
    return -ENOENT;
  }

  // remove multiple trailing slashes
  while (store_len > 1 &&
         (store[store_len - 2] == '/' || store[store_len - 2] == '\\')) {
    --store_len;
  }

  assert(store_len < UINT8_MAX);
  g_store_path_len = (uint8_t)store_len;
  memcpy(g_store_path, store, g_store_path_len);
  if (g_store_path[g_store_path_len - 1] != '/' &&
      g_store_path[g_store_path_len - 1] != '\\') {
    if (g_store_path_len + 1 >= OC_STORE_PATH_SIZE) {
      oc_storage_reset();
      return -ENOENT;
    }
    g_store_path[g_store_path_len] = '\\';
    ++g_store_path_len;
  }
  g_store_path[g_store_path_len] = '\0';
  return 0;
}

bool
oc_storage_path(char *buffer, size_t buffer_size)
{
  if (g_store_path_len == 0) {
    return false;
  }
  if (buffer != NULL) {
    if (buffer_size < (size_t)(g_store_path_len + 1)) {
      return false;
    }
    memcpy(buffer, g_store_path, g_store_path_len);
    buffer[g_store_path_len] = '\0';
  }
  return true;
}

int
oc_storage_reset(void)
{
  g_store_path_len = 0;
  g_store_path[0] = '\0';
  return 0;
}

static int
storage_open(const char *store, FILE **fp)
{
  if (g_store_path_len == 0) {
    return -ENOENT;
  }

  size_t store_len = oc_strnlen_s(store, OC_STORE_PATH_SIZE);
  if ((store_len == 0) ||
      (store_len + g_store_path_len >= OC_STORE_PATH_SIZE)) {
    return -ENOENT;
  }
  memcpy(g_store_path + g_store_path_len, store, store_len);
  g_store_path[g_store_path_len + store_len] = '\0';

  FILE *file = fopen(g_store_path, "rb");
  if (file == NULL) {
    return -EINVAL;
  }
  *fp = file;
  return 0;
}

long
oc_storage_size(const char *store)
{
  FILE *fp = NULL;
  int ret = storage_open(store, &fp);
  if (ret != 0) {
    return ret;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return -errno;
  }
  long fsize = ftell(fp);
  if (fsize < 0) {
    fclose(fp);
    return -errno;
  }
  fclose(fp);
  return fsize;
}

long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  FILE *fp = NULL;
  int ret = storage_open(store, &fp);
  if (ret != 0) {
    return ret;
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
  if (g_store_path_len == 0) {
    return -ENOENT;
  }

  size_t store_len = oc_strnlen_s(store, OC_STORE_PATH_SIZE);
  if ((store_len == 0) ||
      (store_len + g_store_path_len >= OC_STORE_PATH_SIZE)) {
    return -ENOENT;
  }
  memcpy(g_store_path + g_store_path_len, store, store_len);
  g_store_path[g_store_path_len + store_len] = '\0';

  FILE *fp = fopen(g_store_path, "wb");
  if (fp == NULL) {
    return -EINVAL;
  }

  size = fwrite(buf, 1, size, fp);
  fclose(fp);
  return (long)size;
}
#endif /* OC_STORAGE */

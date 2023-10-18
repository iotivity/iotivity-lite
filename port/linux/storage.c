/****************************************************************************
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
#include "port/oc_log_internal.h"
#include "port/oc_storage.h"
#include "port/oc_storage_internal.h"
#include "storage.h"
#include "util/oc_secure_string_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static char g_store_path[OC_STORE_PATH_SIZE] = { 0 };
static uint8_t g_store_path_len = 0;

int
oc_storage_config(const char *store)
{
  if (store == NULL || store[0] == '\0') {
    OC_ERR("failed to configure storage: store path is empty");
    return -EINVAL;
  }

  size_t store_len = oc_strnlen(store, OC_STORE_PATH_SIZE);
  if (store_len >= OC_STORE_PATH_SIZE) {
    OC_ERR("failed to configure storage: store path length is greater "
           "than %d",
           (int)OC_STORE_PATH_SIZE);
    return -ENOENT;
  }

  // remove multiple trailing slashes
  while (store_len > 1 && store[store_len - 2] == '/') {
    --store_len;
  }

  assert(store_len < UINT8_MAX);
  g_store_path_len = (uint8_t)store_len;
  memcpy(g_store_path, store, g_store_path_len);
  if (g_store_path[g_store_path_len - 1] != '/') {
    if (g_store_path_len + 1 >= OC_STORE_PATH_SIZE) {
      OC_ERR("failed to append '/' to store path: store path length is greater "
             "than %d",
             (int)OC_STORE_PATH_SIZE);
      oc_storage_reset();
      return -ENOENT;
    }
    g_store_path[g_store_path_len] = '/';
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
    OC_ERR("failed to open storage: store path is empty");
    return -ENOENT;
  }

  size_t store_len = oc_strnlen_s(store, OC_STORE_PATH_SIZE);
  if ((store_len == 0) ||
      (store_len + g_store_path_len >= OC_STORE_PATH_SIZE)) {
    OC_ERR("failed to open storage: %s",
           store_len == 0
             ? "store path is empty"
             : "store path length is greater than " OC_EXPAND_TO_STR(
                 OC_STORE_PATH_SIZE));
    return -ENOENT;
  }
  memcpy(g_store_path + g_store_path_len, store, store_len);
  g_store_path[g_store_path_len + store_len] = '\0';

  FILE *file = fopen(g_store_path, "rb");
  if (file == NULL) {
    int err = errno;
#if OC_ERR_IS_ENABLED
    if (err != ENOENT) {
      OC_ERR("failed to open %s for read: %d", g_store_path, err);
      return -err;
    }
#endif /* OC_ERR_IS_ENABLED */
    OC_DBG("failed to open %s for read: %d", g_store_path, err);
    return -err;
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

  int err = -1;
  if (fseek(fp, 0, SEEK_END) != 0) {
    err = errno;
    OC_ERR("failed to fseek to the end of file %s: %d", g_store_path, err);
    goto error;
  }
  long fsize = ftell(fp);
  if (fsize < 0) {
    err = errno;
    OC_ERR("failed to ftell file %s: %d", g_store_path, errno);
    goto error;
  }
  if ((size_t)fsize > size) {
    err = EINVAL;
    OC_ERR("file %s is bigger (%u) than the provided buffer size(%u)",
           g_store_path, (unsigned)fsize, (unsigned)size);
    goto error;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    err = errno;
    OC_ERR("failed to fseek to the start of file %s: %d", g_store_path, err);
    goto error;
  }

  size = fread(buf, 1, size, fp);
  if (size != (size_t)fsize) {
    err = errno;
    OC_ERR("failed to fread file %s: %d", g_store_path, err);
    goto error;
  }
  fclose(fp);
  return (long)size;

error:
  fclose(fp);
  return -err;
}

static long
write_and_flush(FILE *fp, const char *file, const uint8_t *buf, size_t size)
{
  assert(fp != NULL);
#if !OC_ERR_IS_ENABLED
  (void)file;
#endif /* !OC_ERR_IS_ENABLED */
  errno = 0;
  int err = 0;
  size_t wsize = fwrite(buf, 1, size, fp);
  if (wsize < size && ferror(fp) != 0) {
    err = errno;
    OC_ERR("failed to write to the storage file %s: %d", file, err);
    return -err;
  }
  if (fflush(fp) != 0) {
    err = errno;
    OC_ERR("failed to flush the storage file %s: %d", file, err);
    return -err;
  }
  if (fsync(fileno(fp)) != 0) {
    err = errno;
    OC_ERR("failed to sync the storage file %s: %d", file, err);
    return -err;
  }
  return (long)wsize;
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
    OC_ERR("failed to write to storage: %s",
           store_len == 0
             ? "store path is empty"
             : "store path length is greater than " OC_EXPAND_TO_STR(
                 OC_STORE_PATH_SIZE));
    return -ENOENT;
  }
  memcpy(g_store_path + g_store_path_len, store, store_len);
  g_store_path[g_store_path_len + store_len] = '\0';

  while (true) {
    FILE *fp = fopen(g_store_path, "wb");
    if (fp == NULL) {
      int err = errno;
      OC_ERR("failed to open %s for write: %d", g_store_path, err);
      return -err;
    }

    long ret = write_and_flush(fp, g_store_path, buf, size);
    if (fclose(fp) != 0) {
      OC_ERR("failed to close the storage file %s: %d", g_store_path, errno);
    }
    if (ret < 0 && (ret == -EAGAIN || ret == -EINTR)) {
      continue;
    }
    return ret;
  }
}
#endif /* OC_STORAGE */

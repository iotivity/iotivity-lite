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

#include <zephyr.h>
#include <flash.h>
#include <device.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "port/oc_storage.h"

struct device *flash_device;
size_t flash_sector_size, max_rw_size;

static unsigned int
align_power2(unsigned int value)
{
  unsigned int left_zeros;

  if (value <= 1)
    return value;

  left_zeros = __builtin_clz(value - 1);
  if (left_zeros <= 1)
    return UINT_MAX;

  return (unsigned int)1 << ((sizeof(value) * 8) - left_zeros);
}

/*
 * It expects the device name, flash sector size and
 * maximum read/write size separated by comma:
 *
 * device_name,flash_sector_size,max_rw_size
 *
 * For arduino 101 internal flash it will be:
 * W25QXXDV,4096,256
 */
int
oc_storage_config(const char *path)
{
  char *aux, device_name[16];
  unsigned int size;

  aux = strstr(path, ",");
  if (!aux)
    return -EINVAL;

  if (aux - path > sizeof(device_name) -1)
    return -EINVAL;

  memcpy(device_name, path, aux - path);
  device_name[aux - path] = '\0';

  flash_device = device_get_binding((char *)path);
  if (!flash_device)
    return -EINVAL;

#define PARSE_VALUE(_var) \
  do { \
    if (!aux) \
      goto err; \
    errno = 0; \
    size = strtoul(aux + 1, NULL, 0); \
    if (errno) \
      goto err; \
    _var = align_power2(size / 2 + 1); \
    path = aux + 1; \
    aux = strstr(path, ","); \
  } while (0)

  PARSE_VALUE(flash_sector_size);
  PARSE_VALUE(max_rw_size);
#undef PARSE_VALUE

  return 0;

err:
  flash_device = NULL;
  return -errno;
}

/*
 * store should contains the memory position to read.
 * The value should be multiple of the flash sector size.
 */
long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  int r;
  size_t mem_offset, times = 0, extra = 0;

  errno = 0;
  mem_offset = strtoul(store, NULL, 0);
  if (errno != 0)
    return -errno;

  times = size / max_rw_size;
  extra = size % max_rw_size;

  if (!(times || extra)) {
    r = flash_read(flash_device, mem_offset, buf, size);
    if (r < 0)
      return r;
  } else {
    size_t off = 0;

    while (times) {
      r = flash_read(flash_device, mem_offset + off,
        buf + off, max_rw_size);
      if (r < 0)
        return r;
      off += max_rw_size;
      times--;
    }

    if (extra) {
      r = flash_read(flash_device, mem_offset + off,
        buf + off, extra);
      if (r < 0)
        return r;
    }
  }

  return size;
}

/*
 * store should contains the memory position to write.
 * The value should be multiple of the flash sector size.
 */
long
oc_storage_write(const char *store, uint8_t *buf, size_t size)
{
  int r = 0;
  size_t mem_offset, times = 0, extra = 0, erase_value = flash_sector_size;

  errno = 0;
  mem_offset = strtoul(store, NULL, 0);
  if (errno != 0)
    return -errno;

  r = flash_write_protection_set(flash_device, false);
  if (r < 0)
    return r;

  times = size / max_rw_size;
  extra = size % max_rw_size;

  if (times) {
    erase_value *= times;
    if (extra)
      erase_value += flash_sector_size;
  }

  r = flash_erase(flash_device, mem_offset, erase_value);
  if (r < 0)
    return r;

  if (!(times || extra)) {
    r = flash_write_protection_set(flash_device, false);
    if (r < 0)
      return r;

    r = flash_write(flash_device, mem_offset, buf, size);
    if (r < 0)
      return r;
  } else {
    size_t off = 0;

    while (times) {
      r = flash_write_protection_set(flash_device, false);
      if (r < 0)
        return r;

      r = flash_write(flash_device, mem_offset + off, buf + off, max_rw_size);
      if (r < 0)
        return r;
      off += max_rw_size;
      times--;
    }

    if (extra) {
      r = flash_write_protection_set(flash_device, false);
      if (r < 0)
        return r;

      r = flash_write(flash_device, mem_offset + off, buf + off, extra);
      if (r < 0)
        return r;
    }
  }

  return size;
}

#endif /* OC_SECURITY */

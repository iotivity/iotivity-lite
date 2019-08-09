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

#include "oc_config.h"

#ifdef OC_STORAGE

#include <device.h>
#include <flash.h>
#include <zephyr.h>

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "port/oc_storage.h"

#ifndef OC_MEMORY_KEY_NUMBER
#define OC_MEMORY_KEY_NUMBER 4
#endif

#ifndef OC_MEMORY_KEY_SIZE
#define OC_MEMORY_KEY_SIZE 1
#endif

#ifndef OC_MEMORY_KEY_NAME_SIZE
#define OC_MEMORY_KEY_NAME_SIZE 64
#endif

#define OC_MEMMAP_KEY                                                          \
  {                                                                            \
    0xab, 0xcd, 0xef                                                           \
  }

#define OC_MEMMAP_CLOSER_ERASABLE_SECTOR(_pos)                                 \
  (_pos * (_pos / memmap.sector_size))

struct memmap_key
{
  uint8_t key[OC_MEMORY_KEY_SIZE];
  size_t offset;
  size_t size;
};

static struct
{
  struct device *flash;
  size_t sector_size, max_rw_size;
  struct memmap_key keys[OC_MEMORY_KEY_NUMBER];
} memmap;

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

static size_t
find_next_available_sector(void)
{
  size_t times;
  uint8_t key[] = OC_MEMMAP_KEY;

  times = (sizeof(memmap.keys) + sizeof(key)) / memmap.sector_size;
  if ((sizeof(memmap.keys) + sizeof(key)) % memmap.sector_size)
    times++;

  return times * memmap.sector_size;
}

static int
storage_init(size_t initial_offset)
{
  int r;
  uint8_t key[] = OC_MEMMAP_KEY;
  size_t times, extra, off = 0;
  size_t first_available_sector = find_next_available_sector();

  for (r = 0; r < sizeof(memmap.keys) / sizeof(memmap.keys[0]); r++) {
    memmap.keys[r].offset = first_available_sector + (r * memmap.sector_size);
    memmap.keys[r].size = memmap.sector_size * OC_MEMORY_KEY_SIZE;
  }

  r = flash_write_protection_set(memmap.flash, false);
  if (r < 0)
    return r;

  r =
    flash_erase(memmap.flash, OC_MEMMAP_CLOSER_ERASABLE_SECTOR(initial_offset),
                memmap.sector_size);
  if (r < 0)
    return r;

  times = (sizeof(memmap.keys) + sizeof(key)) / memmap.max_rw_size;
  extra = (sizeof(memmap.keys) + sizeof(key)) % memmap.max_rw_size;

  while (times) {
    r = flash_write_protection_set(memmap.flash, false);
    if (r < 0)
      return r;

    if (!off) {
      uint8_t buf[memmap.max_rw_size];

      memcpy(buf, key, sizeof(key));
      memcpy(buf + sizeof(key), memmap.keys, memmap.max_rw_size - sizeof(key));

      r = flash_write(memmap.flash, initial_offset, buf, memmap.max_rw_size);
    } else {
      r = flash_write(memmap.flash, initial_offset + off,
                      (uint8_t *)memmap.keys + off - sizeof(key),
                      memmap.max_rw_size);
    }

    off += memmap.max_rw_size;
    if (r < 0)
      return r;
    times--;
  }

  if (extra) {
    r = flash_write_protection_set(memmap.flash, false);
    if (r < 0)
      return r;
    r = flash_write(memmap.flash, initial_offset + off,
                    (uint8_t *)memmap.keys + off - sizeof(key), extra);
    if (r < 0)
      return r;
  }

  return 0;
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
  size_t initial_offset;
  uint8_t key[] = OC_MEMMAP_KEY;
  int r;

  aux = strstr(path, ",");
  if (!aux)
    return -EINVAL;

  if (aux - path > sizeof(device_name) - 1)
    return -EINVAL;

  memcpy(device_name, path, aux - path);
  device_name[aux - path] = '\0';

  memmap.flash = device_get_binding((char *)device_name);
  if (!memmap.flash)
    return -EINVAL;

#define PARSE_VALUE(_var)                                                      \
  do {                                                                         \
    if (!aux)                                                                  \
      goto err;                                                                \
    errno = 0;                                                                 \
    size = strtoul(aux + 1, NULL, 0);                                          \
    if (errno)                                                                 \
      goto err;                                                                \
    _var = size;                                                               \
    path = aux + 1;                                                            \
    aux = strstr(path, ",");                                                   \
  } while (0)

#define PARSE_VALUE_ALIGNED(_var)                                              \
  do {                                                                         \
    PARSE_VALUE(_var);                                                         \
    _var = align_power2(size / 2 + 1);                                         \
  } while (0)

  PARSE_VALUE_ALIGNED(memmap.sector_size);
  PARSE_VALUE_ALIGNED(memmap.max_rw_size);
  PARSE_VALUE(initial_offset);
#undef PARSE_VALUE
#undef PARSE_VALUE_ALIGNED

  /*
   * Read the initial record to check the position
   * and size of the keys.
   */
  r = flash_read(memmap.flash, initial_offset, &key, sizeof(key));
  if (r < 0)
    goto err;

  if (memcmp(key, (void *)&((uint8_t[])OC_MEMMAP_KEY), sizeof(key))) {
    r = storage_init(initial_offset);
    if (r < 0)
      goto err;
  } else {
    size_t times, extra, off = 0;

    times = sizeof(memmap.keys) / memmap.max_rw_size;
    extra = sizeof(memmap.keys) % memmap.max_rw_size;

    while (times) {
      r = flash_read(memmap.flash, initial_offset + sizeof(key) + off,
                     (uint8_t *)memmap.keys + off, memmap.max_rw_size);
      if (r < 0)
        goto err;
      off += memmap.max_rw_size;
      times--;
    }
    if (extra) {
      r = flash_read(memmap.flash, initial_offset + sizeof(key) + off,
                     (uint8_t *)memmap.keys + off, extra);
      if (r < 0)
        goto err;
    }
  }

  return 0;

err:
  memmap.flash = NULL;
  return -errno;
}

static struct memmap_key *
find_key(const char *store)
{
  int i, empty_pos = -1;

  for (i = 0; i < sizeof(memmap.keys) / sizeof(memmap.keys[0]); i++) {
    if (!strcmp(memmap.keys[i].key, store)) {
      return &memmap.keys[i];
    } else if (memmap.keys[i].key[0] == '0') {
      empty_pos = i;
    }
  }

  if (empty_pos != -1) {
    strncpy(memmap.keys[empty_pos].key, store, OC_MEMORY_KEY_SIZE);
    return &memmap.keys[empty_pos];
  }

  return NULL;
}

/*
 * store should contains the memory position to read.
 * The value should be multiple of the flash sector size.
 */
long
oc_storage_read(const char *store, uint8_t *buf, size_t size)
{
  int r;
  struct memmap_key *key;
  size_t times = 0, extra = 0;

  times = size / memmap.max_rw_size;
  extra = size % memmap.max_rw_size;

  key = find_key(store);
  if (!key)
    return -ENOENT;

  if (!(times || extra)) {
    r = flash_read(memmap.flash, key->offset, buf, size);
    if (r < 0)
      return r;
  } else {
    size_t off = 0;

    while (times) {
      r = flash_read(memmap.flash, key->offset + off, buf + off,
                     memmap.max_rw_size);
      if (r < 0)
        return r;
      off += memmap.max_rw_size;
      times--;
    }

    if (extra) {
      r = flash_read(memmap.flash, key->offset + off, buf + off, extra);
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
  struct memmap_key *key;
  size_t times = 0, extra = 0, erase_value = memmap.sector_size;

  key = find_key(store);
  if (!key)
    return -ENOENT;

  times = size / memmap.max_rw_size;
  extra = size % memmap.max_rw_size;

  if (times) {
    erase_value *= times;
    if (extra)
      erase_value += memmap.sector_size;
  }

  r = flash_write_protection_set(memmap.flash, false);
  if (r < 0) {
    return r;
  }

  r = flash_erase(memmap.flash, key->offset, erase_value);
  if (r < 0)
    return r;

  if (!(times || extra)) {
    r = flash_write_protection_set(memmap.flash, false);
    if (r < 0)
      return r;

    r = flash_write(memmap.flash, key->offset, buf, size);
    if (r < 0)
      return r;
  } else {
    size_t off = 0;

    while (times) {
      r = flash_write_protection_set(memmap.flash, false);
      if (r < 0)
        return r;

      r = flash_write(memmap.flash, key->offset + off, buf + off,
                      memmap.max_rw_size);
      if (r < 0)
        return r;
      off += memmap.max_rw_size;
      times--;
    }

    if (extra) {
      r = flash_write_protection_set(memmap.flash, false);
      if (r < 0)
        return r;

      r = flash_write(memmap.flash, key->offset + off, buf + off, extra);
      if (r < 0)
        return r;
    }
  }

  return size;
}

#endif /* OC_STORAGE */

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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "port/oc_random.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* This module implements the generation of type-4 UUIDs
 * based on its specification in RFC 4122, along with routines
 * to convert between their string and binary representations.
 */

void
oc_str_to_uuid(const char *str, oc_uuid_t *uuid)
{
  if (str == NULL) {
    return;
  }
  size_t str_len = oc_strnlen(str, OC_UUID_LEN);
  memset(uuid, 0, sizeof(*uuid));
  if (str[0] == '*' && str_len == 1) {
    uuid->id[0] = '*';
    return;
  }
  size_t k = 1;
  uint8_t c = 0;
  for (size_t i = 0, j = 0; i < (OC_UUID_LEN - 1) && i < str_len; ++i) {
    if (str[i] == '-') {
      continue;
    }
    if (isalpha((int)str[i])) {
      switch (str[i]) {
      case 65:
      case 97:
        c |= 0x0a;
        break;
      case 66:
      case 98:
        c |= 0x0b;
        break;
      case 67:
      case 99:
        c |= 0x0c;
        break;
      case 68:
      case 100:
        c |= 0x0d;
        break;
      case 69:
      case 101:
        c |= 0x0e;
        break;
      case 70:
      case 102:
        c |= 0x0f;
        break;
      }
    } else {
      c |= str[i] - 48;
    }
    if ((j + 1) * 2 == k) {
      uuid->id[j++] = c;
      c = 0;
    } else {
      c = (uint8_t)(c << 4);
    }
    k++;
  }
}

int
oc_uuid_to_str_v1(const oc_uuid_t *uuid, char *buffer, size_t buflen)
{
  if (uuid->id[0] == '*') {
    uint8_t zeros[OC_ARRAY_SIZE(uuid->id) - 1] = { 0 };
    if (memcmp(&uuid->id[1], zeros, OC_ARRAY_SIZE(zeros)) == 0) {
      if (buflen < 2) {
        OC_ERR("cannot encode uuid to string: buffer too small");
        return -1;
      }
      memset(buffer, 0, buflen);
      buffer[0] = '*';
      buffer[1] = '\0';
      return 1;
    }
  }
  int j = 0;
  for (size_t i = 0; i < OC_ARRAY_SIZE(uuid->id); ++i) {
    switch (i) {
    case 4:
    case 6:
    case 8:
    case 10: {
      int len = snprintf(&buffer[j], buflen, "-");
      if (len < 0 || (size_t)len >= buflen) {
        OC_ERR("cannot encode uuid to string: buffer too small");
        return -1;
      }
      j += len;
      buflen -= (size_t)len;
      break;
    }
    }
    int len = snprintf(&buffer[j], buflen, "%02x", uuid->id[i]);
    if (len < 0 || (size_t)len >= buflen) {
      OC_ERR("cannot encode uuid to string: buffer too small");
      return -1;
    }
    j += len;
    buflen -= (size_t)len;
  }
  return j;
}

void
oc_uuid_to_str(const oc_uuid_t *uuid, char *buffer, size_t buflen)
{
  if (buflen < OC_UUID_LEN || uuid == NULL) {
    OC_ERR("oc_uuid_to_str: invalid inputs (buffer=%s, uuid=%s)",
           buflen < OC_UUID_LEN ? "too small" : "ok",
           uuid == NULL ? "null" : "ok");
    return;
  }
  oc_uuid_to_str_v1(uuid, buffer, buflen);
}

void
oc_gen_uuid(oc_uuid_t *uuid)
{
  uint32_t r;

  for (unsigned i = 0; i < 4; i++) {
    r = oc_random_value();
    memcpy(&uuid->id[i * 4UL], (uint8_t *)&r, sizeof(r));
  }

  /*  From RFC 4122
      Set the two most significant bits of the
      clock_seq_hi_and_reserved (8th octect) to
      zero and one, respectively.
  */
  uuid->id[8] &= 0x3f;
  uuid->id[8] |= 0x40;

  /*  From RFC 4122
      Set the four most significant bits of the
      time_hi_and_version field (6th octect) to the
      4-bit version number from (0 1 0 0 => type 4)
      Section 4.1.3.
  */
  uuid->id[6] &= 0x0f;
  uuid->id[6] |= 0x40;
}

bool
oc_uuid_is_equal(oc_uuid_t first, oc_uuid_t second)
{
  return memcmp(first.id, second.id, OC_UUID_ID_SIZE) == 0;
}

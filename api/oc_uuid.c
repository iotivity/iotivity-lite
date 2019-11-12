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

#include "oc_uuid.h"
#include "port/oc_random.h"
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
  if (str[0] == '*' && strlen(str) == 1) {
    memset(uuid->id, 0, 16);
    uuid->id[0] = '*';
    return;
  }
  int i, j = 0, k = 1;
  uint8_t c = 0;

  for (i = 0; i < 36; i++) {
    if (str[i] == '-')
      continue;
    else if (isalpha((int)str[i])) {
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
    } else
      c |= str[i] - 48;
    if ((j + 1) * 2 == k) {
      uuid->id[j++] = c;
      c = 0;
    } else
      c = c << 4;
    k++;
  }
}

void
oc_uuid_to_str(const oc_uuid_t *uuid, char *buffer, int buflen)
{
  int i, j = 0;
  if (buflen < OC_UUID_LEN || !uuid)
    return;
  if (uuid->id[0] == '*') {
    uint8_t zeros[15] = { 0 };
    if (memcmp(&uuid->id[1], zeros, 15) == 0) {
      memset(buffer, 0, buflen);
      buffer[0] = '*';
      buffer[1] = '\0';
      return;
    }
  }
  for (i = 0; i < 16; i++) {
    switch (i) {
    case 4:
    case 6:
    case 8:
    case 10:
      snprintf(&buffer[j], 2, "-");
      j++;
      break;
    }
    snprintf(&buffer[j], 3, "%02x", uuid->id[i]);
    j += 2;
  }
}

void
oc_gen_uuid(oc_uuid_t *uuid)
{
  int i;
  uint32_t r;

  for (i = 0; i < 4; i++) {
    r = oc_random_value();
    memcpy((uint8_t *)&uuid->id[i * 4], (uint8_t *)&r, sizeof(r));
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

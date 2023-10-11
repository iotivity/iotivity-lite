/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER

#include "util/oc_crc_internal.h"

#include <stddef.h>
#include <stdint.h>

// ECMA-182, reflected form polynomial
#define CRC64_POLYNOMIAL (0xC96C5795D7870F42ULL)

static uint64_t
crc64_update(uint64_t crc, uint8_t byte)
{
  crc ^= (uint64_t)byte;
  for (int i = 0; i < 8; ++i) {
    if (crc & 1) {
      crc = (crc >> 1) ^ CRC64_POLYNOMIAL;
    } else {
      crc >>= 1;
    }
  }
  return crc;
}

uint64_t
oc_crc64(uint64_t crc, const uint8_t *buffer, size_t size)
{
  for (size_t i = 0; i < size; i++) {
    crc = crc64_update(crc, buffer[i]);
  }
  return crc;
}

#endif /* OC_HAS_FEATURE_CRC_ENCODER */

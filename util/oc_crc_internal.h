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

#ifndef OC_CRC_INTERNAL_H
#define OC_CRC_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Calculate CRC64 for a buffer of data.
 *
 * @param crc The initial CRC64 value (use 0 to start a new CRC64 calculation).
 * @param buffer The buffer of data to calculate CRC64 for.
 * @param size The size of the buffer of data to calculate CRC64 for.
 *
 * @return The CRC64 value.
 */
uint64_t oc_crc64(uint64_t crc, const uint8_t *buffer, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_CRC_ENCODER */

#endif /* OC_CRC_INTERNAL_H */

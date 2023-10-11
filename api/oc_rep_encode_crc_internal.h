/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifndef OC_REP_ENCODE_CRC_INTERNAL_H
#define OC_REP_ENCODE_CRC_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_CRC_ENCODER

#ifdef __cplusplus
extern "C" {
#endif

#include "api/oc_rep_encode_internal.h"

#define OC_CRC_REP_FALSE (0x0)
#define OC_CRC_REP_TRUE (0x1)

#define OC_CRC_OPEN_CONTAINER (0x0)
#define OC_CRC_CLOSE_CONTAINER (0x1)

/** Return an initialized CRC encoder. */
oc_rep_encoder_implementation_t oc_rep_crc_encoder(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_HAS_FEATURE_CRC_ENCODER */

#endif /* OC_REP_ENCODE_CRC_INTERNAL_H */

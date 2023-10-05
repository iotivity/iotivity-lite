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

#ifndef OC_REP_ENCODE_JSON_INTERNAL_H
#define OC_REP_ENCODE_JSON_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_JSON_ENCODER

#include "api/oc_rep_encode_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OC_REP_JSON_INT_MAX (1LL << 53)
#define OC_REP_JSON_INT_MIN ~(1LL << 52)
#define OC_REP_JSON_UINT_MAX (1ULL << 53)

/** Return an initialized JSON encoder. */
oc_rep_encoder_t oc_rep_json_encoder(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_JSON_ENCODER */

#endif /* OC_REP_ENCODE_JSON_INTERNAL_H */

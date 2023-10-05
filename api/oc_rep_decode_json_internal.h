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

#ifndef OC_REP_DECODE_JSON_INTERNAL_H
#define OC_REP_DECODE_JSON_INTERNAL_H

#include "util/oc_features.h"

#ifdef OC_JSON_ENCODER

#include "oc_rep.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Parse a JSON root object or root array */
int oc_rep_parse_json(const uint8_t *json, size_t json_len, oc_rep_t **out_rep);

#ifdef __cplusplus
}
#endif

#endif /* OC_JSON_ENCODER */

#endif /* OC_REP_DECODE_JSON_INTERNAL_H */

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

#ifndef OC_REP_DECODE_CBOR_INTERNAL_H
#define OC_REP_DECODE_CBOR_INTERNAL_H

#include "api/oc_rep_internal.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Parse a CBOR root object, root array or NULL object */
int oc_rep_parse_cbor(const uint8_t *json, size_t json_len,
                      oc_rep_parse_result_t *result) OC_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_DECODE_CBOR_INTERNAL_H */

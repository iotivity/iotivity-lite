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

#ifndef OC_REP_DECODE_INTERNAL_H
#define OC_REP_DECODE_INTERNAL_H

#include "oc_ri.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum oc_rep_decoder_type_t {
  OC_REP_CBOR_DECODER = 0 /* default decoder */,
#ifdef OC_JSON_ENCODER
  OC_REP_JSON_DECODER = 1,
#endif /* OC_JSON_ENCODER */
} oc_rep_decoder_type_t;

/** Parse payload to oc_rep_t */
typedef CborError (*oc_rep_parse_payload_t)(const uint8_t *payload,
                                            size_t payload_size,
                                            oc_rep_t **out_rep);

typedef struct
{
  oc_rep_decoder_type_t type;
  oc_rep_parse_payload_t parse;
} oc_rep_decoder_t;

/** Get decoder. */
oc_rep_decoder_t oc_rep_decoder(oc_rep_decoder_type_t type);

/**
 * @brief Set the global decoder used to decode the request payload to oc_rep_t.
 *
 * @param type decoder type
 */
void oc_rep_decoder_set_type(oc_rep_decoder_type_t type);

/**
 * @brief Get the decoder type to decode the request payload to oc_rep_t.
 *
 * @return decoder
 */
oc_rep_decoder_type_t oc_rep_decoder_get_type(void);

/**
 * @brief Set the decoder type to decode the request payload to oc_rep_t
 * according to the content format.
 *
 * @param content_format the content format
 * @return true if the decoder type was set
 * @return false otherwise
 */
bool oc_rep_decoder_set_by_content_format(oc_content_format_t content_format);

#ifdef __cplusplus
}
#endif

#endif /* OC_REP_DECODE_INTERNAL_H */

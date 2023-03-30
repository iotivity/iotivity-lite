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

#include <stddef.h>
#include "jsmn.h"
#include <cbor.h>
#include <stdlib.h>
#include "oc_rep.h"
#include "oc_json_to_cbor_internal.h"

typedef struct {
    CborEncoder buf[32];
    CborEncoder *use;
    bool embedded;
    size_t idx_container;
} cbor_encode_token_data_t;


static bool
cbor_encode_token(const jsmntok_t *token, const char *js, void *data) {
    printf("token->type: %d token->start: %d token->end: %d", token->type, token->start, token->end);
    if (token->start >= 0 && token->end >= 0) {
        printf(" token: %.*s", token->end - token->start, js + token->start);
    }
    printf("\n");
    cbor_encode_token_data_t* d = (cbor_encode_token_data_t*) data;
    switch (token->type) {
        case JSMN_PRIMITIVE:
            if (js[token->start] == 't') {
                oc_rep_encode_boolean(d->use, true);
            } else if (js[token->start] == 'f') {
                oc_rep_encode_boolean(d->use, false);
            } else {
                oc_rep_encode_int(d->use, atoll(js + token->start));
            }
            break;
        case JSMN_STRING:
            oc_rep_encode_text_string(d->use, js + token->start, token->end - token->start);
            break;
        case JSMN_OBJECT_STARTED:
            if (d->embedded && d->idx_container == 0) {
                d->idx_container++;
                break;
            }
            if (d->use == &d->buf[sizeof(d->buf) / sizeof(d->buf[0]) - 1]) {
                return false;
            }
            memset(d->use+1, 0, sizeof(d->buf[0]));
            oc_rep_encoder_create_map(d->use, d->use+1, CborIndefiniteLength);
            d->use++;
            d->idx_container++;
            break;
        case JSMN_ARRAY_END:
        case JSMN_OBJECT_END:
            if (d->use == d->buf) {
                if (d->embedded && d->idx_container == 1) {
                    d->idx_container--;
                    break;
                }
                return false;
            }
            oc_rep_encoder_close_container(d->use-1, d->use);
            d->use--;
            d->idx_container--;
            break;
        case JSMN_ARRAY_STARTED:
            if (d->embedded && d->idx_container == 0) {
                d->idx_container++;
                break;
            }
            if (d->use == &d->buf[sizeof(d->buf) / sizeof(d->buf[0]) - 1]) {
                return false;
            }
            oc_rep_encoder_create_array(d->use, d->use+1, CborIndefiniteLength);
            d->use++;
            d->idx_container++;
            break;
        default:
            break;
    }
    return true;
}

bool oc_json_to_cbor(const char *json, size_t json_len, bool embedded, CborEncoder *encoder_map) {
    (void) json_len;
    (void) json;
    
    jsmn_parser parser;
    jsmn_init(&parser);
    cbor_encode_token_data_t data = {
        .embedded = embedded,
        .use = data.buf,
        .idx_container = 0,
    };
    memcpy(&data.buf[0], encoder_map, sizeof(*encoder_map));
    int r = jsmn_parse(&parser, json, json_len, cbor_encode_token, &data);
    if (r < 1) {
        return false;
    }
    memcpy(encoder_map, &data.buf[0], sizeof(*encoder_map));
    return true;
}
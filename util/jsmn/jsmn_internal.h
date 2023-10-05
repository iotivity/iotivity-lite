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
/*
 * MIT License
 *
 * Copyright (c) 2010 Serge Zaitsev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef JSMN_INTERNAL_H
#define JSMN_INTERNAL_H

#ifdef OC_JSON_ENCODER

#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * JSON type identifier. Basic types are:
 * 	o Object
 * 	o Array
 * 	o String
 * 	o Other primitive: number, boolean (true/false) or null
 */
typedef enum {
  JSMN_UNDEFINED = 0,
  JSMN_OBJECT = 1 << 0,
  JSMN_ARRAY = 1 << 2,
  JSMN_STRING = 1 << 3,
  JSMN_PRIMITIVE = 1 << 4,
} jsmntype_t;

enum jsmnerr {
  /* Not enough tokens were provided */
  JSMN_ERROR_NOMEM = -1,
  /* Invalid character inside JSON string */
  JSMN_ERROR_INVAL = -2,
  /* The string is not a full JSON packet, more bytes expected */
  JSMN_ERROR_PART = -3
};

/**
 * JSON token description.
 * type		type (object, array, string etc.)
 * start	start position in JSON data string
 * end		end position in JSON data string
 */
typedef struct
{
  jsmntype_t type;
  int start;
  int end;
} jsmntok_t;

/**
 * JSON parser. Contains an array of token blocks available. Also stores
 * the string being parsed now and current position in that string.
 */
typedef struct
{
  unsigned pos;           /* offset in the JSON string */
  unsigned depth;         /* nesting depth for arrays/objects */
  bool parsing_container; /* true if we are parsing a container */
} jsmn_parser_t;

/** Create JSON parser over an array of tokens */
void jsmn_init(jsmn_parser_t *parser) OC_NONNULL();

typedef bool (*jsmn_parsed_token_cb_t)(const jsmntok_t *token, const char *js,
                                       void *data);
/**
 * Run JSON parser. It parses a JSON data string into and array of tokens, each
 * describing a single JSON object.
 */
int jsmn_parse(jsmn_parser_t *parser, const char *js, const size_t len,
               jsmn_parsed_token_cb_t cb, void *data) OC_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* OC_JSON_ENCODER */

#endif /* JSMN_INTERNAL_H */

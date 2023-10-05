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

#include "jsmn_internal.h"

#ifdef OC_JSON_ENCODER

#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <string.h>

/**
 * Allocates a fresh unused token from the token pool.
 */
static jsmntok_t *
jsmn_init_token(jsmntok_t *tok)
{
  tok->type = JSMN_UNDEFINED;
  tok->start = tok->end = -1;
  return tok;
}
/**
 * Fills token type and boundaries.
 */
static void
jsmn_fill_token(jsmntok_t *token, const jsmntype_t type, const int start,
                const int end)
{
  token->type = type;
  token->start = start;
  token->end = end;
}

/**
 * Fills next available token with JSON primitive.
 */
static int
jsmn_parse_primitive(jsmn_parser_t *parser, const char *js, const size_t len,
                     jsmn_parsed_token_cb_t cb, void *data)
{
  assert(js[parser->pos] != '\0');
  jsmntok_t token;
  unsigned start = parser->pos;
  for (; parser->pos < len; parser->pos++) {
    switch (js[parser->pos]) {
    /* In strict mode primitive must be followed by "," or "}" or "]" */
    case ':':
    case '\t':
    case '\r':
    case '\n':
    case ' ':
    case ',':
    case ']':
    case '}':
      goto found;
    default:
      /* to quiet a warning from gcc*/
      break;
    }
    if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
      parser->pos = start;
      return JSMN_ERROR_INVAL;
    }
  }

found:

  jsmn_init_token(&token);
  jsmn_fill_token(&token, JSMN_PRIMITIVE, (int)start, (int)parser->pos);
  if (!parser->parsing_container && cb != NULL && !cb(&token, js, data)) {
    return JSMN_ERROR_INVAL;
  }
  parser->pos--;
  return 0;
}

static int
jsmn_parse_hex_char(jsmn_parser_t *parser, const char *js, const size_t len,
                    uint8_t max_digits)
{
  parser->pos++;
  for (int i = 0;
       i < max_digits && parser->pos < len && js[parser->pos] != '\0'; i++) {
    /* If it isn't a hex character we have an error */
    if (!isxdigit(js[parser->pos])) {
      return JSMN_ERROR_INVAL;
    }
    parser->pos++;
  }
  parser->pos--;
  return 0;
}

static int
jsmn_parse_escaped_char(jsmn_parser_t *parser, const char *js, const size_t len)
{
  if (js[parser->pos] != '\\' || parser->pos + 1 >= len) {
    return 0;
  }

  /* Backslash: Quoted symbol expected */
  parser->pos++;
  switch (js[parser->pos]) {
  /* Allowed escaped symbols */
  case '\"':
  case '/':
  case '\\':
  case 'b':
  case 'f':
  case 'r':
  case 'n':
  case 't':
    break;
  /* Allows escaped symbol \uXXXX */
  case 'u':
    if (jsmn_parse_hex_char(parser, js, len, 4) < 0) {
      return JSMN_ERROR_INVAL;
    }
    break;
  /* Unexpected symbol */
  default:
    return JSMN_ERROR_INVAL;
  }
  return 0;
}

/**
 * Fills next token with JSON string.
 */
static int
jsmn_parse_string(jsmn_parser_t *parser, const char *js, const size_t len,
                  jsmn_parsed_token_cb_t cb, void *data)
{
  unsigned start = parser->pos;

  /* Skip starting quote */
  parser->pos++;

  jsmntok_t token;
  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    /* Quote: end of string */
    if (js[parser->pos] == '\"') {
      jsmn_init_token(&token);
      jsmn_fill_token(&token, JSMN_STRING, (int)start + 1, (int)parser->pos);
      if (!parser->parsing_container && cb != NULL && !cb(&token, js, data)) {
        return JSMN_ERROR_INVAL;
      }
      return 0;
    }
    if (jsmn_parse_escaped_char(parser, js, len) < 0) {
      parser->pos = start;
      return JSMN_ERROR_INVAL;
    }
  }
  parser->pos = start;
  return JSMN_ERROR_PART;
}

static void
jsmn_open_container(jsmn_parser_t *parser, jsmntok_t *token, bool is_object)
{
  if (!parser->parsing_container) {
    token->start = (int)(parser->pos + 1);
    token->type = is_object ? JSMN_OBJECT : JSMN_ARRAY;
    parser->parsing_container = true;
  }
  parser->depth++;
}

static int
jsmn_close_container(jsmn_parser_t *parser, jsmntok_t *token, const char *js,
                     jsmn_parsed_token_cb_t cb, void *data, bool is_object)
{
  if (!parser->parsing_container) {
    return JSMN_ERROR_INVAL;
  }
  parser->depth--;
  if (parser->depth == 0) {
    parser->parsing_container = false;
  }
  if (parser->parsing_container) {
    return 0;
  }
  if (token->type != (is_object ? JSMN_OBJECT : JSMN_ARRAY)) {
    return JSMN_ERROR_INVAL;
  }
  token->end = (int)parser->pos;
  if (cb != NULL && !cb(token, js, data)) {
    return JSMN_ERROR_INVAL;
  }
  return 1;
}

static int
jsmn_parse_next_char(jsmn_parser_t *parser, jsmntok_t *token, const char *js,
                     const size_t len, jsmn_parsed_token_cb_t cb, void *data)
{
  int count = 0;
  char c = js[parser->pos];
  switch (c) {
  case '{':
  case '[':
    jsmn_open_container(parser, token, c == '{');
    break;
  case '}':
  case ']': {
    int r = jsmn_close_container(parser, token, js, cb, data, c == '}');
    if (r < 0) {
      return r;
    }
    count += r;
    break;
  }
  case '\"': {
    int r = jsmn_parse_string(parser, js, len, cb, data);
    if (r < 0) {
      return r;
    }
    if (!parser->parsing_container) {
      count++;
    }
    break;
  }
  case '\t':
  case '\r':
  case '\n':
  case ' ':
  case ':':
  case ',':
    break;
  /* In non-strict mode every unquoted value is a primitive */
  default: {
    int r = jsmn_parse_primitive(parser, js, len, cb, data);
    if (r < 0) {
      return r;
    }
    if (!parser->parsing_container) {
      count++;
    }
    break;
  }
  }

  return count;
}

int
jsmn_parse(jsmn_parser_t *parser, const char *js, const size_t len,
           jsmn_parsed_token_cb_t cb, void *data)
{
  jsmntok_t token;
  jsmn_init_token(&token);
  unsigned count = 0;
  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    int r = jsmn_parse_next_char(parser, &token, js, len, cb, data);
    if (r < 0) {
      return r;
    }
    count += r;
  }

  if (parser->depth > 0) {
    return JSMN_ERROR_PART;
  }

  return (int)count;
}

void
jsmn_init(jsmn_parser_t *parser)
{
  parser->pos = 0;
  parser->depth = 0;
  parser->parsing_container = false;
}

#endif /* OC_JSON_ENCODER */

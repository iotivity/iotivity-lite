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
#ifndef JSMN_H
#define JSMN_H

#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef JSMN_STATIC
#define JSMN_API static
#else
#define JSMN_API extern
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
typedef struct jsmntok
{
  jsmntype_t type;
  int start;
  int end;
} jsmntok_t;

/**
 * JSON parser. Contains an array of token blocks available. Also stores
 * the string being parsed now and current position in that string.
 */
typedef struct jsmn_parser
{
  unsigned int pos;       /* offset in the JSON string */
  unsigned int toknext;   /* number of tokens */
  bool parsing_container; /* true if we are parsing a container */
} jsmn_parser;

/**
 * Create JSON parser over an array of tokens
 */
JSMN_API void jsmn_init(jsmn_parser *parser);

typedef bool (*jsmn_parsed_token_cb_t)(const jsmntok_t *token, const char *js,
                                       void *data);
/**
 * Run JSON parser. It parses a JSON data string into and array of tokens, each
 * describing
 * a single JSON object.
 */
JSMN_API int jsmn_parse(jsmn_parser *parser, const char *js, const size_t len,
                        jsmn_parsed_token_cb_t cb, void *data);

#ifndef JSMN_HEADER
/**
 * Allocates a fresh unused token from the token pool.
 */
static jsmntok_t *
jsmn_init_token(jsmn_parser *parser, jsmntok_t *tok)
{
  parser->toknext++;
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
jsmn_parse_primitive(jsmn_parser *parser, const char *js, const size_t len,
                     jsmn_parsed_token_cb_t cb, void *data)
{
  int start;
  jsmntok_t token;
  start = parser->pos;

  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
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

  jsmn_init_token(parser, &token);
  jsmn_fill_token(&token, JSMN_PRIMITIVE, start, parser->pos);
  if (cb != NULL && !parser->parsing_container) {
    if (!cb(&token, js, data)) {
      return JSMN_ERROR_INVAL;
    }
  }
  parser->pos--;
  return 0;
}

/**
 * Fills next token with JSON string.
 */
static int
jsmn_parse_string(jsmn_parser *parser, const char *js, const size_t len,
                  jsmn_parsed_token_cb_t cb, void *data)
{
  jsmntok_t token;

  int start = parser->pos;

  if (js[parser->pos] != '\"' && js[parser->pos + 1] == '\"') {
    printf("jsmn_parse_string: \"\"\n");
  }

  /* Skip starting quote */
  parser->pos++;

  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    char c = js[parser->pos];

    /* Quote: end of string */
    if (c == '\"') {
      jsmn_init_token(parser, &token);
      jsmn_fill_token(&token, JSMN_STRING, start + 1, parser->pos);
      if (cb != NULL && !parser->parsing_container) {
        if (!cb(&token, js, data)) {
          return JSMN_ERROR_INVAL;
        }
      }
      return 0;
    }

    /* Backslash: Quoted symbol expected */
    if (c == '\\' && parser->pos + 1 < len) {
      int i;
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
        parser->pos++;
        for (i = 0; i < 4 && parser->pos < len && js[parser->pos] != '\0';
             i++) {
          /* If it isn't a hex character we have an error */
          if (!((js[parser->pos] >= 48 && js[parser->pos] <= 57) ||   /* 0-9 */
                (js[parser->pos] >= 65 && js[parser->pos] <= 70) ||   /* A-F */
                (js[parser->pos] >= 97 && js[parser->pos] <= 102))) { /* a-f */
            parser->pos = start;
            return JSMN_ERROR_INVAL;
          }
          parser->pos++;
        }
        parser->pos--;
        break;
      /* Unexpected symbol */
      default:
        parser->pos = start;
        return JSMN_ERROR_INVAL;
      }
    }
  }
  parser->pos = start;
  return JSMN_ERROR_PART;
}

/**
 * Parse JSON string and fill tokens.
 */
JSMN_API int
jsmn_parse(jsmn_parser *parser, const char *js, const size_t len,
           jsmn_parsed_token_cb_t cb, void *data)
{
  int r;
  jsmntok_t token;
  int count = parser->toknext;
  int depth = 0;
  for (; parser->pos < len && js[parser->pos] != '\0'; parser->pos++) {
    char c;

    c = js[parser->pos];
    switch (c) {
    case '{':
    case '[':
      if (!parser->parsing_container) {
        count++;
        jsmn_init_token(parser, &token);
        token.start = parser->pos + 1;
        token.type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
        parser->parsing_container = true;
        depth = 1;
      } else {
        depth++;
      }
      break;
    case '}':
    case ']':
      if (!parser->parsing_container) {
        return JSMN_ERROR_INVAL;
      }
      depth--;
      if (depth < 0) {
        return JSMN_ERROR_INVAL;
      }
      if (depth == 0) {
        parser->parsing_container = false;
      }
      if (!parser->parsing_container) {
        if (token.type != (c == '}' ? JSMN_OBJECT : JSMN_ARRAY)) {
          return JSMN_ERROR_INVAL;
        }
        token.end = parser->pos;
        if (cb) {
          if (!cb(&token, js, data)) {
            return JSMN_ERROR_INVAL;
          }
        }
        count++;
      }
      break;
    case '\"':
      r = jsmn_parse_string(parser, js, len, cb, data);
      if (r < 0) {
        return r;
      }
      if (!parser->parsing_container) {
        count++;
      }
      break;
    case '\t':
    case '\r':
    case '\n':
    case ' ':
      break;
    case ':':
      break;
    case ',':
      break;
    /* In non-strict mode every unquoted value is a primitive */
    default:
      r = jsmn_parse_primitive(parser, js, len, cb, data);
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

/**
 * Creates a new parser based over a given buffer with an array of tokens
 * available.
 */
JSMN_API void
jsmn_init(jsmn_parser *parser)
{
  parser->pos = 0;
  parser->toknext = 0;
}

#endif /* JSMN_HEADER */

#ifdef __cplusplus
}
#endif

#endif /* JSMN_H */

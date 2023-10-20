/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include "oc_api.h"
#include "oc_base64.h"
#include "oc_rep.h"
#include "port/oc_log_internal.h"
#include "util/oc_buffer_internal.h"
#include "util/oc_compiler.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * This macro assumes that four variables are already avalible to be changed.
 *
 *  - total_char_printed = running total of characters printed to buf
 *  - num_char_printed = the number of characters the command just before the
 *                       macro is called reports is printed typically the return
 *                       value of snprintf function but not always.
 *  - buf = the character buffer being updated
 *  - buf_size = the size of the character buffer being updated.
 *
 * Tracking the total number characters and moving the pointer forward in the
 * buffer so it the addition of each string looks like concatenation means
 * moving the buf pointer forward and reducing the buf_size after every function
 * that adds to the buffer.
 *
 * In addition it will update the total character count that would be printed
 * regardless of the buf_size. (total_char_print is expected to be larger than
 * or equal to buf_size if the buffer is too small.)
 */
#define OC_JSON_UPDATE_BUFFER_AND_TOTAL                                        \
  do {                                                                         \
    total_char_printed += num_char_printed;                                    \
    if (num_char_printed < buf_size && buf != NULL) {                          \
      buf += num_char_printed;                                                 \
      buf_size -= num_char_printed;                                            \
    } else {                                                                   \
      buf += buf_size;                                                         \
      buf_size = 0;                                                            \
    }                                                                          \
  } while (0)

/*
 * Internal function used to complete the oc_rep_to_json function
 *
 * This function is used when pretty_print param of the oc_rep_to_json function
 * is set to true. It helps produce output with reasonably human readable
 * white-space.
 */
static size_t
oc_rep_to_json_tab(char *buf, size_t buf_size, int tab_depth)
{
  oc_write_buffer_t b = {
    .buffer = buf,
    .buffer_size = buf_size,
    .total = 0,
  };
  for (int i = 0; i < tab_depth; i++) {
    if (oc_buffer_write(&b, "%s", OC_PRETTY_PRINT_TAB_CHARACTER) < 0) {
      return (size_t)-1;
    }
  }
  return b.total;
}

/*
 * Internal function used to complete the oc_rep_to_json function
 *
 * This function is called when the data type is an OC_REP_BYTE_STRING or
 * an OC_REP_BYTE_STRING_ARRAY. If uses the base64 encoded to encode the
 * byte_string to a base64 string.
 */
static size_t
oc_rep_to_json_base64_encoded_byte_string(char *buf, size_t buf_size,
                                          char *byte_str, size_t byte_str_size)
{
  size_t num_char_printed = 0;
  size_t total_char_printed = 0;
  // calculate the b64 encoded string size
  size_t b64_buf_size = (byte_str_size / 3) * 4;
  if (byte_str_size % 3 != 0) {
    b64_buf_size += 4;
  }
  // one extra byte for terminating NUL character.
  b64_buf_size++;
  num_char_printed = snprintf(buf, buf_size, "\"");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;

  if (buf_size > b64_buf_size) {
    int output_len = oc_base64_encode((uint8_t *)byte_str, byte_str_size,
                                      (uint8_t *)buf, b64_buf_size);
    num_char_printed = output_len;
    OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  } else {
    buf += buf_size;
    buf_size = 0;
    total_char_printed += (b64_buf_size - 1);
  }
  num_char_printed = snprintf(buf, buf_size, "\"");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  return total_char_printed;
}

/*
 * Internal function called by oc_rep_to_json function
 *
 * oc_rep_to_json_format will take any oc_rep_t and print out the json
 * equivalent of that value.  This function will be called recursively for
 * nested objects.
 *
 * Currently does not handle OC_REP_ARRAY data type.
 */
static size_t
oc_rep_to_json_format(const oc_rep_t *rep, char *buf, size_t buf_size,
                      int tab_depth, bool pretty_print)
{
  size_t num_char_printed = 0;
  size_t total_char_printed = 0;
  while (rep != NULL) {
    if (pretty_print) {
      num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }

    if (oc_string_len(rep->name) > 0) {
      num_char_printed =
        pretty_print
          ? snprintf(buf, buf_size, "\"%s\" : ", oc_string(rep->name))
          : snprintf(buf, buf_size, "\"%s\":", oc_string(rep->name));
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }
    switch (rep->type) {
    case OC_REP_NIL: {
      num_char_printed = snprintf(buf, buf_size, "null");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_INT: {
      num_char_printed =
        snprintf(buf, buf_size, "%" PRId64, rep->value.integer);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_DOUBLE: {
      num_char_printed = snprintf(buf, buf_size, "%f", rep->value.double_p);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BOOL: {
      num_char_printed =
        snprintf(buf, buf_size, "%s", (rep->value.boolean) ? "true" : "false");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BYTE_STRING: {
      char *byte_string = NULL;
      size_t byte_string_size;
      const char *name = oc_string(rep->name);
      if (!oc_rep_get_byte_string(rep, name, &byte_string, &byte_string_size)) {
        OC_ERR("failed to encode byte string(%s)",
               name != NULL ? name : "NULL");
        break;
      }
      num_char_printed = oc_rep_to_json_base64_encoded_byte_string(
        buf, buf_size, byte_string, byte_string_size);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_STRING: {
      num_char_printed =
        snprintf(buf, buf_size, "\"%s\"", oc_string(rep->value.string));
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_OBJECT: {
      num_char_printed = pretty_print ? snprintf(buf, buf_size, "{\n")
                                      : snprintf(buf, buf_size, "{");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      num_char_printed = oc_rep_to_json_format(rep->value.object, buf, buf_size,
                                               tab_depth + 1, pretty_print);
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "}");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_INT_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      int64_t *int_array;
      size_t int_array_size = 0;
      oc_rep_get_int_array(rep, oc_string(rep->name), &int_array,
                           &int_array_size);
      for (size_t i = 0; i < int_array_size; i++) {
        num_char_printed = snprintf(buf, buf_size, "%" PRId64, int_array[i]);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < int_array_size - 1) {
          num_char_printed = pretty_print ? snprintf(buf, buf_size, ", ")
                                          : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_DOUBLE_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      double *double_array;
      size_t double_array_size = 0;
      oc_rep_get_double_array(rep, oc_string(rep->name), &double_array,
                              &double_array_size);
      for (size_t i = 0; i < double_array_size; i++) {
        num_char_printed = snprintf(buf, buf_size, "%f", double_array[i]);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < double_array_size - 1) {
          num_char_printed = pretty_print ? snprintf(buf, buf_size, ", ")
                                          : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BOOL_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      bool *bool_array;
      size_t bool_array_size = 0;
      oc_rep_get_bool_array(rep, oc_string(rep->name), &bool_array,
                            &bool_array_size);
      for (size_t i = 0; i < bool_array_size; i++) {
        num_char_printed =
          snprintf(buf, buf_size, "%s", (bool_array[i]) ? "true" : "false");
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < bool_array_size - 1) {
          num_char_printed = pretty_print ? snprintf(buf, buf_size, ", ")
                                          : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_BYTE_STRING_ARRAY: {
      num_char_printed = pretty_print ? snprintf(buf, buf_size, "[\n")
                                      : snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      oc_string_array_t byte_str_array;
      size_t byte_str_array_size = 0;
      oc_rep_get_byte_string_array(rep, oc_string(rep->name), &byte_str_array,
                                   &byte_str_array_size);
      for (size_t i = 0; i < byte_str_array_size; i++) {
        if (pretty_print) {
          num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
        char *byte_string = oc_byte_string_array_get_item(byte_str_array, i);
        size_t byte_string_size =
          (size_t)oc_byte_string_array_get_item_size(byte_str_array, i);
        num_char_printed = oc_rep_to_json_base64_encoded_byte_string(
          buf, buf_size, byte_string, byte_string_size);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < byte_str_array_size - 1) {
          num_char_printed = pretty_print ? snprintf(buf, buf_size, ",\n")
                                          : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        } else {
          if (pretty_print) {
            num_char_printed = snprintf(buf, buf_size, "\n");
            OC_JSON_UPDATE_BUFFER_AND_TOTAL;
          }
        }
      }
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_STRING_ARRAY: {
      num_char_printed = pretty_print ? snprintf(buf, buf_size, "[\n")
                                      : snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      oc_string_array_t str_array;
      size_t str_array_size = 0;
      oc_rep_get_string_array(rep, oc_string(rep->name), &str_array,
                              &str_array_size);
      for (size_t i = 0; i < str_array_size; i++) {
        if (pretty_print) {
          num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
        num_char_printed = snprintf(buf, buf_size, "\"%s\"",
                                    oc_string_array_get_item(str_array, i));
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        if (i < str_array_size - 1) {
          num_char_printed = pretty_print ? snprintf(buf, buf_size, ",\n")
                                          : snprintf(buf, buf_size, ",");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        } else {
          if (pretty_print) {
            num_char_printed = snprintf(buf, buf_size, "\n");
            OC_JSON_UPDATE_BUFFER_AND_TOTAL;
          }
        }
      }
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 1);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    case OC_REP_OBJECT_ARRAY: {
      num_char_printed = snprintf(buf, buf_size, "[");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      const oc_rep_t *rep_array = rep->value.object_array;
      if (pretty_print) {
        num_char_printed = snprintf(buf, buf_size, "\n");
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      do {
        const oc_rep_t *rep_item = rep_array->value.object;
        if (pretty_print) {
          num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
        num_char_printed = pretty_print ? snprintf(buf, buf_size, "{\n")
                                        : snprintf(buf, buf_size, "{");
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        num_char_printed = oc_rep_to_json_format(rep_item, buf, buf_size,
                                                 tab_depth + 2, pretty_print);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        rep_array = rep_array->next;
        if (rep_array) {
          if (pretty_print) {
            num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
            OC_JSON_UPDATE_BUFFER_AND_TOTAL;
          }
          num_char_printed = pretty_print ? snprintf(buf, buf_size, "},\n")
                                          : snprintf(buf, buf_size, "},");
          OC_JSON_UPDATE_BUFFER_AND_TOTAL;
        }
      } while (rep_array);
      if (pretty_print) {
        num_char_printed = oc_rep_to_json_tab(buf, buf_size, tab_depth + 2);
        OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      }
      num_char_printed = snprintf(buf, buf_size, "}]");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
      break;
    }
    default:
      break;
    }
    rep = rep->next;
    if (rep != NULL) {
      num_char_printed = snprintf(buf, buf_size, ",");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }
    if (pretty_print) {
      num_char_printed = snprintf(buf, buf_size, "\n");
      OC_JSON_UPDATE_BUFFER_AND_TOTAL;
    }
  }
  return total_char_printed;
}

size_t
oc_rep_to_json(const oc_rep_t *rep, char *buf, size_t buf_size,
               bool pretty_print)
{
  size_t total_char_printed = 0;
  bool object_array =
    (rep && (rep->type == OC_REP_OBJECT) && (oc_string_len(rep->name) == 0));
  size_t num_char_printed = snprintf(buf, buf_size, object_array ? "[" : "{");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  if (pretty_print) {
    num_char_printed = snprintf(buf, buf_size, "\n");
    OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  }

  num_char_printed = oc_rep_to_json_format(rep, buf, buf_size, 0, pretty_print);
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;

  num_char_printed = snprintf(buf, buf_size, object_array ? "]" : "}");
  OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  if (pretty_print) {
    num_char_printed = snprintf(buf, buf_size, "\n");
    OC_JSON_UPDATE_BUFFER_AND_TOTAL;
  }
  return total_char_printed;
}

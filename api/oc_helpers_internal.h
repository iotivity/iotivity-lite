/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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

#ifndef OC_HELPERS_INTERNAL_H
#define OC_HELPERS_INTERNAL_H

#include "oc_helpers.h"
#include "util/oc_compiler.h"
#include "util/oc_macros_internal.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Non-mutable view into a C-string or an oc_string_t.
 *
 * @note It is the programmer's responsibility to ensure that oc_string_view_t
 * does not outlive the pointed-to string.
 * This is especially important with dynamic allocation disabled. Because
 * then oc_string_t values are taken from a preallocated pool and when an
 * oc_string_t is "deallocated" then data is returned to the pool and
 * oc_string_t values allocated after this value are reallocated so that the
 * pool is always contiguous. This means that the data pointer might become
 * invalid after a call to oc_free_string.
 */
typedef struct oc_string_view_t
{
  const char *data;
  size_t length;
} oc_string_view_t;

#ifdef __cplusplus

#define OC_STRING_VIEW(str)                                                    \
  oc_string_view_t                                                             \
  {                                                                            \
    (str), OC_CHAR_ARRAY_LEN(str),                                             \
  }

/** Create empty oc_string_view_t. */
#define OC_STRING_VIEW_NULL()                                                  \
  oc_string_view_t                                                             \
  {                                                                            \
    NULL, 0,                                                                   \
  }

#else /* !__cplusplus */

#define OC_STRING_VIEW(str)                                                    \
  (oc_string_view_t)                                                           \
  {                                                                            \
    .data = (str), .length = OC_CHAR_ARRAY_LEN(str),                           \
  }

/** Create empty oc_string_view_t. */
#define OC_STRING_VIEW_NULL()                                                  \
  (oc_string_view_t)                                                           \
  {                                                                            \
    .data = NULL, .length = 0,                                                 \
  }

#endif /* __cplusplus */

/** Create an oc_string_view_t from a C-string. */
oc_string_view_t oc_string_view(const char *data, size_t length);

/** Create an oc_string_view_t from an oc_string_t. */
oc_string_view_t oc_string_view2(const oc_string_t *str);

/**
 * @brief Compare two oc_string_view_t values.
 *
 * @param str1 first oc_string_view_t
 * @param str2 second oc_string_view_t
 * @return true strings are equal
 * @return false strings are not equal
 */
bool oc_string_view_is_equal(oc_string_view_t str1, oc_string_view_t str2);

/**
 * @brief Compare two oc_strings.
 *
 * @param str1 first oc_string (cannot be NULL)
 * @param str2 second oc_string (cannot be NULL)
 * @return true strings are equal
 * @return false strings are not equal
 */
bool oc_string_is_equal(const oc_string_t *str1, const oc_string_t *str2)
  OC_NONNULL();

/**
 * @brief Compare an oc_string with a C-string
 *
 * @param str1 oc_string
 * @param str2 C-string
 * @param str2_len length of \p str2
 * @return true strings are equal
 * @return false strings are not equal
 */
bool oc_string_is_cstr_equal(const oc_string_t *str1, const char *str2,
                             size_t str2_len);

/**
 * @brief Fill buffer with random values.
 *
 * @param buffer output buffer (cannot be NULL)
 * @param buffer_size size of the output buffer
 */
void oc_random_buffer(uint8_t *buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* OC_HELPERS_INTERNAL_H */

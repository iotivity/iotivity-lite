/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_SECURE_STRING_INTERNAL_H
#define OC_SECURE_STRING_INTERNAL_H

#include "util/oc_compiler.h"
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximal allowed length (including null-terminator) of C-strings, strings
 * with greater length are considered invalid.  */
#ifndef OC_MAX_STRING_LENGTH
#define OC_MAX_STRING_LENGTH (4096)
#endif /* !OC_MAX_STRING_LENGTH */

/**
 * @brief Get the number of characters in the string, not including the
 * terminating null character.
 *
 * @param str pointer to the null-terminated byte string to be examined (cannot
 * be NULL)
 * @param strsz maximum number of characters to examine
 * @return length of the null-terminated byte string str on success
 * @return strsz if the null character was not found
 */
size_t oc_strnlen(const char *str, size_t strsz) OC_NONNULL();

/**
 * @brief Get the number of characters in the string, not including the
 * terminating null character.
 *
 * @param str pointer to the null-terminated byte string to be examined
 * @param strsz maximum number of characters to examine
 * @return 0 if str is a null pointer
 * @return length of the null-terminated byte string str on success
 * @return strsz if the null character was not found
 */
size_t oc_strnlen_s(const char *str, size_t strsz);

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURE_STRING_INTERNAL_H */

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

#include "oc_secure_string_internal.h"

// on _WIN32 with __STDC_WANT_SECURE_LIB__ set to 1 following functions are
// available from string.h:
//   strnlen_s

size_t
oc_strnlen(const char *str, size_t strsz)
{
#if defined(_WIN32) && defined(__STDC_WANT_SECURE_LIB__) &&                    \
  (__STDC_WANT_SECURE_LIB__ == 1)
  return strnlen(str, strsz);
#else /* !_WIN32 || __STDC_WANT_SECURE_LIB__ != 1 */
#if defined(_POSIX_C_SOURCE) && (_POSIX_C_SOURCE >= 200809L)
  return strnlen(str, strsz);
#else  /* !_POSIX_C_SOURCE || _POSIX_C_SOURCE < 200809L */
  size_t count = 0;
  while (strsz > 0 && *str != '\0') {
    ++str;
    --strsz;
    ++count;
  }
  return count;
#endif /* _POSIX_C_SOURCE >= 200809L */
#endif /* _WIN32 && __STDC_WANT_SECURE_LIB__ == 1  */
}

size_t
oc_strnlen_s(const char *str, size_t strsz)
{
#if defined(_WIN32) && defined(__STDC_WANT_SECURE_LIB__) &&                    \
  (__STDC_WANT_SECURE_LIB__ == 1)
  return strnlen_s(str, strsz);
#else  /* !_WIN32 || __STDC_WANT_SECURE_LIB__ != 1 */
  if (str == NULL) {
    return 0;
  }
  return oc_strnlen(str, strsz);
#endif /* _WIN32 && __STDC_WANT_SECURE_LIB__ == 1 */
}

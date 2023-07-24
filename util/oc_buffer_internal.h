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

#ifndef OC_BUFFER_INTERNAL_H
#define OC_BUFFER_INTERNAL_H

#include "util/oc_compiler.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_write_buffer_t
{
  char *buffer;       // the character buffer being updated
  size_t buffer_size; // the size of the character buffer being updated.
  size_t total;       // running total of characters printed to buf
} oc_write_buffer_t;

/**
 * @brief Write a formatted string to a buffer.
 *
 * @param wb The buffer to write to (cannot be NULL)
 * @param fmt The format string (cannot be NULL)
 * @param ... The format arguments
 *
 * @return The number of characters written to the buffer
 * @return -1 if the buffer is too small
 */
long oc_buffer_write(oc_write_buffer_t *wb, const char *fmt, ...)
  OC_PRINTF_FORMAT(2, 3) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_BUFFER_INTERNAL_H */

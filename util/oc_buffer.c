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

#include "oc_buffer_internal.h"

#include <stdarg.h>
#include <stdio.h>

long
oc_buffer_write(oc_write_buffer_t *wb, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  int num_char_printed = vsnprintf(wb->buffer, wb->buffer_size, fmt, args);
  va_end(args);
  if (num_char_printed < 0) {
    return -1;
  }
  wb->total += num_char_printed;
  if (wb->buffer == NULL) {
    return (long)wb->total;
  }
  if ((size_t)num_char_printed >= wb->buffer_size) {
    wb->buffer += wb->buffer_size;
    wb->buffer_size = 0;
    return -1;
  }
  wb->buffer += num_char_printed;
  wb->buffer_size -= num_char_printed;
  return (long)wb->total;
}

/****************************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#include "hawkbit_buffer.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */
#include <string.h>

bool
hawkbit_buffer_init(hawkbit_buffer_t *hb, size_t size)
{
#ifdef OC_DYNAMIC_ALLOCATION
  hb->buffer = (char *)calloc(1, size);
  if (hb->buffer == NULL) {
    return false;
  }
  hb->buffer_size = size;
  return true;
#else  /* !OC_DYNAMIC_ALLOCATION */
  (void)size;
  memset(hb, 0, sizeof(*hb));
  return true;
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
hawkbit_buffer_free(hawkbit_buffer_t *hb)
{
  if (hb == NULL) {
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(hb->buffer);
#endif /* OC_DYNAMIC_ALLOCATION */
}

size_t
hawkbit_buffer_size(const hawkbit_buffer_t *hb)
{
#ifdef OC_DYNAMIC_ALLOCATION
  return hb->buffer_size;
#else  /* !OC_DYNAMIC_ALLOCATION */
  return HAWKBIT_BUFFER_SIZE;
#endif /* OC_DYNAMIC_ALLOCATION */
}

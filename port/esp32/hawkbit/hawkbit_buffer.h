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

#ifndef HAWKBIT_BUFFER_H
#define HAWKBIT_BUFFER_H

#include "util/oc_compiler.h"

#include <stdbool.h>
#include <stddef.h>

#ifndef OC_DYNAMIC_ALLOCATION
#define HAWKBIT_BUFFER_SIZE (2048)
#endif /* OC_DYNAMIC_ALLOCATION */

typedef struct
{
#ifdef OC_DYNAMIC_ALLOCATION
  char *buffer;
  size_t buffer_size;
#else  /* !OC_DYNAMIC_ALLOCATION */
  char buffer[HAWKBIT_BUFFER_SIZE];
#endif /* OC_DYNAMIC_ALLOCATION */
} hawkbit_buffer_t;

/**
 * @brief Initialize buffer
 *
 * @param hb buffer to initialize (cannot be NULL)
 * @param size size of the allocated buffer (only relevant if dynamic allocation
 * is enabled, otherwise the buffer is static with size HAWKBIT_BUFFER_SIZE)
 * @return hawkbit_buffer_t
 */
bool hawkbit_buffer_init(hawkbit_buffer_t *hb, size_t size) OC_NONNULL();

/** Deallocate buffer */
void hawkbit_buffer_free(hawkbit_buffer_t *hb);

/** Get size of the buffer */
size_t hawkbit_buffer_size(const hawkbit_buffer_t *hb) OC_NONNULL();

#endif /* HAWKBIT_BUFFER_H */

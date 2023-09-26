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

#include "port/oc_allocator_internal.h"
#include "port/oc_assert.h"

#ifndef OC_DYNAMIC_ALLOCATION

#include <pthread.h>

static pthread_mutex_t g_allocator_mutex;

void
oc_allocator_mutex_init(void)
{
  if (pthread_mutex_init(&g_allocator_mutex, NULL) != 0) {
    oc_abort("error initializing allocator mutex");
  }
}

void
oc_allocator_mutex_lock(void)
{
  if (pthread_mutex_lock(&g_allocator_mutex) != 0) {
    oc_abort("error locking allocator mutex");
  }
}

void
oc_allocator_mutex_unlock(void)
{
  if (pthread_mutex_unlock(&g_allocator_mutex) != 0) {
    oc_abort("error unlocking allocator mutex");
  }
}

void
oc_allocator_mutex_destroy(void)
{
  if (pthread_mutex_destroy(&g_allocator_mutex) != 0) {
    oc_abort("error destroying allocator mutex");
  }
}

#endif /* !OC_DYNAMIC_ALLOCATION */

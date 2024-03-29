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

#include "mutex.h"
#include "port/oc_allocator_internal.h"

#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX

static mutex_t g_allocator_mutex;

void
oc_allocator_mutex_init(void)
{
  mutex_init(&g_allocator_mutex);
}

void
oc_allocator_mutex_lock(void)
{
  mutex_lock(&g_allocator_mutex);
}

void
oc_allocator_mutex_unlock(void)
{
  mutex_unlock(&g_allocator_mutex);
}

void
oc_allocator_mutex_destroy(void)
{
  mutex_destroy(&g_allocator_mutex);
}

#endif /* !OC_DYNAMIC_ALLOCATION || OC_INOUT_BUFFER_POOL */

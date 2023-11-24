/****************************************************************************
 *
 * Copyright 2023 plgd.dev s.r.o, All Rights Reserved.
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

#include "api/oc_rep_internal.h"
#include "oc_runtime_internal.h"
#include "port/oc_allocator_internal.h"
#include "port/oc_random.h"
#include "port/oc_clock.h"
#include "util/oc_features.h"

void
oc_runtime_init(void)
{
  oc_random_init();
  oc_clock_init();
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  oc_allocator_mutex_init();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
}

void
oc_runtime_shutdown(void)
{
#ifdef OC_HAS_FEATURE_ALLOCATOR_MUTEX
  oc_allocator_mutex_destroy();
#endif /* OC_HAS_FEATURE_ALLOCATOR_MUTEX */
  oc_random_destroy();
}

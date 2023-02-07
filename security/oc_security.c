/******************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifdef OC_SECURITY

#include "oc_security_internal.h"

#include <mbedtls/debug.h>
#include <mbedtls/memory_buffer_alloc.h>

#ifndef OC_DYNAMIC_ALLOCATION
#include <mbedtls/platform.h>
#define MBEDTLS_ALLOC_BUF_SIZE (20000)
static unsigned char g_alloc_buf[MBEDTLS_ALLOC_BUF_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

void
oc_mbedtls_init(void)
{
#ifndef OC_DYNAMIC_ALLOCATION
  mbedtls_memory_buffer_alloc_init(g_alloc_buf, sizeof(g_alloc_buf));
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_DEBUG
#if defined(_WIN32) || defined(_WIN64)
  // mbedtls debug logs fail if snprintf is not specified
  mbedtls_platform_set_snprintf(snprintf);
#endif /* _WIN32 or _WIN64 */
  mbedtls_debug_set_threshold(4);
#endif /* OC_DEBUG */
}

#endif /* OC_SECURITY */

/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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

#ifdef OC_SECURITY

#include "oc_entropy_internal.h"
#include "port/oc_random.h"

#include "mbedtls/entropy.h"

#include <string.h>

#define OC_ENTROPY_MIN 32

void
oc_entropy_add_source(mbedtls_entropy_context *ctx)
{
  mbedtls_entropy_add_source(ctx, oc_entropy_poll, NULL, OC_ENTROPY_MIN,
                             MBEDTLS_ENTROPY_SOURCE_STRONG);
}

int
oc_entropy_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
  (void)data;
  *olen = 0;
  do {
    unsigned int val = oc_random_value();
    size_t l = (len > sizeof(val)) ? sizeof(val) : len;
    memcpy(output + *olen, &val, l);
    len -= l;
    *olen += l;
  } while (len > 0);

  return 0;
}

#endif /* OC_SECURITY */

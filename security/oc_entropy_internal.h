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

#ifndef OC_ENTROPY_INTERNAL_H
#define OC_ENTROPY_INTERNAL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/build_info.h>
#include <mbedtls/entropy.h>
#include <stddef.h>

/// @brief Add oc_entropy_poll to data sources
void oc_entropy_add_source(mbedtls_entropy_context *ctx);

/// @brief Use oc_random_value to generate data
int oc_entropy_poll(void *data, unsigned char *output, size_t len,
                    size_t *olen);

#ifdef __cplusplus
}
#endif

#endif /* OC_ENTROPY_INTERNAL_H */

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

#ifndef OC_PLATFORM_INTERNAL_H
#define OC_PLATFORM_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_core_res.h"
#include "util/oc_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_PLATFORM_URI "/oic/p"
#define OCF_PLATFORM_RT "oic.wk.p"

/**
 * @brief Initialize the platform
 *
 * @param mfg_name the manufactorer name (cannot be NULL)
 * @param init_cb the callback
 * @param data  the user data
 * @return oc_platform_info_t* the platform information
 */
oc_platform_info_t *oc_platform_init(const char *mfg_name,
                                     oc_core_init_platform_cb_t init_cb,
                                     void *data) OC_NONNULL(1);

/** @brief Deinitialize the platform */
void oc_platform_deinit(void);

/** @brief Check if the URI matches the platform resource URI (with or without
 * the leading slash)
 */
bool oc_is_platform_resource_uri(oc_string_view_t uri);

#ifdef __cplusplus
}
#endif

#endif /* OC_PLATFORM_INTERNAL_H */

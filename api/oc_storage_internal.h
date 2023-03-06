/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#ifndef OC_STORAGE_INTERNAL_H
#define OC_STORAGE_INTERNAL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_STORAGE_SVR_TAG_MAX (32)

/**
 * @brief Generate a name in the format "${name}_${device_index}".
 *
 * @param name tag name
 * @param device_index device index
 * @param[out] svr_tag output buffer (cannot be NULL)
 * @param svr_tag_size size of the output buffer
 * @return >= 0 number of written bytes
 * @return -1 on error
 */
int oc_storage_gen_svr_tag(const char *name, size_t device_index, char *svr_tag,
                           size_t svr_tag_size);

#ifdef __cplusplus
}
#endif

#endif /* OC_STORAGE_INTERNAL_H */

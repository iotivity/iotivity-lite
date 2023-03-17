/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#ifndef OC_CLOUD_ACCESS_INTERNAL_H
#define OC_CLOUD_ACCESS_INTERNAL_H

#include "oc_client_state.h"
#include "oc_endpoint.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate URI query for deregister request.
 *
 * @return URI query, must be freed by caller
 */
oc_string_t cloud_access_deregister_query(const char *uid,
                                          const char *access_token,
                                          size_t device);
#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */

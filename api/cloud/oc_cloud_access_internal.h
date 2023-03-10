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
 * The format of the generated string is uid=${uid}&di={device
 * uuid}&at=${access_token} or uid=${uid}&di={device uuid} based on whether
 * access token is NULL or not.
 *
 * @param uid uid (cannot be NULL)
 * @param access_token access token
 * @param device device index
 * @param query output variable (cannot be NULL)
 */
void cloud_access_deregister_query(const char *uid, const char *access_token,
                                   size_t device, oc_string_t *query);
#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_INTERNAL_H */

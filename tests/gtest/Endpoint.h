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

#pragma once

#include "oc_endpoint.h"
#include "oc_helpers.h"

#include <string>

namespace oc::endpoint {

/**
 * @brief Parse endpoint from string.
 */
oc_endpoint_t FromString(const std::string &ep_str);

/**
 * @brief Parse endpoint and uri from string
 *
 * @param addr address to parse
 * @param[out] ep parsed endpoint (cannot be NULL)
 * @param[out] uri parsed uri
 * @return int 0 on success
 * @return int -1 on failure
 */
int FromString(const std::string &addr, oc_endpoint_t *ep, oc_string_t *uri);

} // oc::endpoint

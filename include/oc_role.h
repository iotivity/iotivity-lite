/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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

/**
 * @file
 */

#ifndef OC_ROLE_H
#define OC_ROLE_H

#include "oc_client_state.h"
#include "oc_helpers.h"
#include "oc_endpoint.h"
#include "util/oc_compiler.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
  @defgroup doc_module_tag_asserting_roles Asserting roles
  Asserting roles support functions
  @{
*/
typedef struct oc_role_t
{
  struct oc_role_t *next;
  oc_string_t role;
  oc_string_t authority;
} oc_role_t;

/**
 * @brief retrieve all roles
 *
 * @return oc_role_t*
 */
oc_role_t *oc_get_all_roles(void);

/**
 * @brief assert the specific role
 *
 * @param role the role (cannot be NULL)
 * @param authority the authority
 * @param endpoint endpoint identifying the connection (cannot be NULL)
 * @param handler the response handler (cannot be NULL)
 * @param user_data the user data to be conveyed to the response handler
 * @return true request was initialized and sent
 * @return false otherwise
 */
bool oc_assert_role(const char *role, const char *authority,
                    const oc_endpoint_t *endpoint,
                    oc_response_handler_t handler, void *user_data)
  OC_NONNULL(1, 3, 4);

/**
 * @brief set automatic role assertion (e.g. for all endpoints with a
 * connection)
 *
 * @param auto_assert set to true to enable automatic role assertion
 */
void oc_auto_assert_roles(bool auto_assert);

/**
 * @brief assert all the roles for a specific endpoint
 *
 * @param endpoint identifying the connection
 * @param handler the response handler
 * @param user_data the user data to be conveyed to the response handler
 */
void oc_assert_all_roles(const oc_endpoint_t *endpoint,
                         oc_response_handler_t handler, void *user_data);
/** @} */ // end of doc_module_tag_asserting_roles

#ifdef __cplusplus
}
#endif

#endif /* OC_ROLE_H */

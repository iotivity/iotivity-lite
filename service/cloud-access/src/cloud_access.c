/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "cloud_access.h"
#include "oc_api.h"
#include "oc_log.h"

bool
oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
           const char *auth_code, oc_response_handler_t handler,
           void *user_data)
{
  if (!endpoint || !auth_provider || !auth_code) {
    OC_ERR("Error of input parameters");
    return false;
  }
  (void)handler;
  (void)user_data;

  return true;
}

static bool
oc_sign_inout(oc_endpoint_t *endpoint, const char *uid,
              const char *access_token, bool is_sign_in,
              oc_response_handler_t handler, void *user_data)
{
  if (!endpoint || (is_sign_in && !uid) || !access_token) {
    OC_ERR("Error of input parameters");
    return false;
  }
  (void)handler;
  (void)user_data;

  return true;
}

bool
oc_sign_in(oc_endpoint_t *endpoint, const char *uid, const char *access_token,
           oc_response_handler_t handler, void *user_data)
{
  return oc_sign_inout(endpoint, uid, access_token, true, handler, user_data);
}

bool
oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
            oc_response_handler_t handler, void *user_data)
{
  return oc_sign_inout(endpoint, NULL, access_token, false, handler, user_data);
}

bool
oc_refresh_access_token(oc_endpoint_t *endpoint, const char *uid,
                        const char *refresh_token,
                        oc_response_handler_t handler, void *user_data)
{
  if (!endpoint || !uid || !refresh_token) {
    OC_ERR("Error of input parameters");
    return false;
  }
  (void)handler;
  (void)user_data;

  return true;
}

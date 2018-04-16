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

bool
oc_sign_up(const char *host, const char *auth_provider, const char *auth_code,
           oc_response_handler_t handler, void *user_data)
{
  (void)host;
  (void)auth_provider;
  (void)auth_code;
  (void)handler;
  (void)user_data;
  return false;
}

bool
oc_sign_in(const char *host, const char *uid, const char *access_token,
           oc_response_handler_t handler, void *user_data)
{
  (void)host;
  (void)uid;
  (void)access_token;
  (void)handler;
  (void)user_data;
  return false;
}

bool
oc_sign_out(const char *host, const char *access_token,
            oc_response_handler_t handler, void *user_data)
{
  (void)host;
  (void)access_token;
  (void)handler;
  (void)user_data;
  return false;
}

bool
oc_refresh_access_token(const char *host, const char *uid,
                        const char *refresh_token,
                        oc_response_handler_t handler, void *user_data)
{
  (void)host;
  (void)uid;
  (void)refresh_token;
  (void)handler;
  (void)user_data;
  return false;
}
/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
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

#include "cloud_internal.h"
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_core_res.h"
#include "port/oc_log.h"

/** Account URI.*/
#ifdef OC_SPEC_VER_OIC
#define OC_RSRVD_ACCOUNT_URI "/oic/account"
#else
#define OC_RSRVD_ACCOUNT_URI "/oic/sec/account"
#endif

/** Account session URI.*/
#ifdef OC_SPEC_VER_OIC
#define OC_RSRVD_ACCOUNT_SESSION_URI "/oic/account/session"
#else
#define OC_RSRVD_ACCOUNT_SESSION_URI "/oic/sec/session"
#endif

/** Account token refresh URI.*/
#ifdef OC_SPEC_VER_OIC
#define OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI "/oic/account/tokenrefresh"
#else
#define OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI "/oic/sec/tokenrefresh"
#endif

/** Device URI.*/
#define OC_RSRVD_DEVICE_URI "/oic/device"

/** To represent grant type with refresh token. */
#define OC_RSRVD_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

static bool
_oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
            const char *auth_code, const char *uid, const char *access_token,
            size_t device_index, oc_response_handler_t handler, void *user_data)
{
  if (!endpoint || ((!auth_provider || !auth_code) && !access_token) ||
      !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(OC_RSRVD_ACCOUNT_URI, endpoint, NULL, handler, LOW_QOS,
                   user_data)) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, di, uuid);
    if (auth_provider)
      oc_rep_set_text_string(root, authprovider, auth_provider);
    if (auth_code) {
      oc_rep_set_text_string(root, accesstoken, auth_code);
    } else {
      if (uid)
        oc_rep_set_text_string(root, uid, uid);
      oc_rep_set_text_string(root, accesstoken, access_token);
    }
    oc_rep_set_text_string(root, devicetype, "device");
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for sign up");
    return false;
  }

  return oc_do_post();
}

bool
cloud_access_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
                     const char *uid, const char *access_token,
                     size_t device_index, oc_response_handler_t handler,
                     void *user_data)
{
  return _oc_sign_up(endpoint, auth_provider, NULL, uid, access_token,
                     device_index, handler, user_data);
}

static bool
oc_sign_inout(oc_endpoint_t *endpoint, const char *uid,
              const char *access_token, size_t device_index, bool is_sign_in,
              oc_response_handler_t handler, void *user_data)
{
  if (!endpoint || (!uid) || !access_token || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(OC_RSRVD_ACCOUNT_SESSION_URI, endpoint, NULL, handler,
                   LOW_QOS, user_data)) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, uid, uid);
    oc_rep_set_text_string(root, di, uuid);
    oc_rep_set_text_string(root, accesstoken, access_token);
    oc_rep_set_boolean(root, login, is_sign_in);
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for sign in/out");
    return false;
  }

  return oc_do_post();
}

bool
cloud_access_sign_in(oc_endpoint_t *endpoint, const char *uid,
                     const char *access_token, size_t device_index,
                     oc_response_handler_t handler, void *user_data)
{
  return oc_sign_inout(endpoint, uid, access_token, device_index, true, handler,
                       user_data);
}

bool
cloud_access_sign_out(oc_endpoint_t *endpoint, const char *access_token,
                      size_t device_index, oc_response_handler_t handler,
                      void *user_data)
{
  return oc_sign_inout(endpoint, NULL, access_token, device_index, false,
                       handler, user_data);
}

bool
cloud_access_refresh_access_token(oc_endpoint_t *endpoint, const char *uid,
                                  const char *refresh_token,
                                  size_t device_index,
                                  oc_response_handler_t handler,
                                  void *user_data)
{
  if (!endpoint || !uid || !refresh_token || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

  if (oc_init_post(OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI, endpoint, NULL, handler,
                   LOW_QOS, user_data)) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device_index), uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, uid, uid);
    oc_rep_set_text_string(root, di, uuid);
    oc_rep_set_text_string(root, granttype, OC_RSRVD_GRANT_TYPE_REFRESH_TOKEN);
    oc_rep_set_text_string(root, refreshtoken, refresh_token);
    oc_rep_end_root_object();
  } else {
    OC_ERR("Could not init POST request for refresh access token");
    return false;
  }

  return oc_do_post();
}

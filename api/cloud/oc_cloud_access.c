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

#include "oc_config.h"

#ifdef OC_CLOUD

#include "oc_cloud_access_internal.h"
#include "oc_cloud_internal.h"
#include "oc_core_res.h"

#ifdef OC_SECURITY
#include "security/oc_pstat.h"
#include "security/oc_tls.h"
#endif /* OC_SECURITY */

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

/** To represent grant type with refresh token. */
#define OC_RSRVD_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

#ifdef OC_SECURITY

static bool
cloud_tls_peer_connected(const oc_tls_peer_t *peer)
{
  return (peer->role == MBEDTLS_SSL_IS_CLIENT &&
          peer->ssl_ctx.state == MBEDTLS_SSL_HANDSHAKE_OVER);
}

static bool
cloud_tls_add_peer(const oc_endpoint_t *endpoint, int selected_identity_cred_id)
{
  const oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (peer != NULL) {
    if (cloud_tls_peer_connected(peer)) {
      return true;
    }
    OC_DBG("cloud need to initialized from the device");
    oc_tls_close_connection(endpoint);
  }
  oc_tls_select_cloud_ciphersuite();
  oc_tls_select_identity_cert_chain(selected_identity_cred_id);
  peer = oc_tls_add_peer(endpoint, MBEDTLS_SSL_IS_CLIENT);
  return peer != NULL;
}

#endif /* OC_SECURITY */

/* Internal APIs for accessing the OCF Cloud */
bool
cloud_access_register(oc_cloud_access_conf_t conf, const char *auth_provider,
                      const char *auth_code, const char *uid,
                      const char *access_token)
{
  if (conf.endpoint == NULL || conf.handler == NULL ||
      ((auth_provider == NULL || auth_code == NULL) && access_token == NULL)) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(conf.device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

#ifdef OC_SECURITY
  if (!cloud_tls_add_peer(conf.endpoint, conf.selected_identity_cred_id)) {
    OC_ERR("cannot connect to cloud");
    return false;
  }
#endif /* OC_SECURITY */

  if (!oc_init_post(OC_RSRVD_ACCOUNT_URI, conf.endpoint, NULL, conf.handler,
                    LOW_QOS, conf.user_data)) {
    OC_ERR("Could not init POST request for sign up");
    return false;
  }

  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(conf.device), uuid, OC_UUID_LEN);

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, di, uuid);
  if (auth_provider != NULL) {
    oc_rep_set_text_string(root, authprovider, auth_provider);
  }
  if (auth_code != NULL) {
    oc_rep_set_text_string(root, accesstoken, auth_code);
  } else {
    if (uid != NULL) {
      oc_rep_set_text_string(root, uid, uid);
    }
    oc_rep_set_text_string(root, accesstoken, access_token);
  }
  oc_rep_set_text_string(root, devicetype, "device");
  oc_rep_end_root_object();

  return oc_do_post();
}

oc_string_t
cloud_access_deregister_query(const char *uid, const char *access_token,
                              size_t device)
{
  oc_string_t q_uid;
  oc_concat_strings(&q_uid, "uid=", uid);

  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(device), uuid, OC_UUID_LEN);
  oc_string_t q_di;
  oc_concat_strings(&q_di, "&di=", uuid);
  oc_string_t q_uid_di;
  oc_concat_strings(&q_uid_di, oc_string(q_uid), oc_string(q_di));
  oc_free_string(&q_uid);
  oc_free_string(&q_di);

  oc_string_t q_uid_di_at;
  if (access_token != NULL) {
    oc_string_t q_at;
    oc_concat_strings(&q_at, "&accesstoken=", access_token);
    oc_concat_strings(&q_uid_di_at, oc_string(q_uid_di), oc_string(q_at));
    oc_free_string(&q_at);
  } else {
    oc_new_string(&q_uid_di_at, oc_string(q_uid_di), oc_string_len(q_uid_di));
  }

  oc_free_string(&q_uid_di);
  return q_uid_di_at;
}

bool
cloud_access_deregister(oc_cloud_access_conf_t conf, const char *uid,
                        const char *access_token)
{
  if (conf.endpoint == NULL || conf.handler == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(conf.device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

#ifdef OC_SECURITY
  if (!cloud_tls_add_peer(conf.endpoint, conf.selected_identity_cred_id)) {
    OC_ERR("cannot connect to cloud");
    return false;
  }
#endif /* OC_SECURITY */

  oc_string_t query =
    cloud_access_deregister_query(uid, access_token, conf.device);
  bool s = oc_do_delete(OC_RSRVD_ACCOUNT_URI, conf.endpoint, oc_string(query),
                        conf.handler, HIGH_QOS, conf.user_data);
  oc_free_string(&query);
  return s;
}

static bool
cloud_access_login_out(oc_cloud_access_conf_t conf, const char *uid,
                       const char *access_token, bool is_sign_in)
{
  if (conf.endpoint == NULL || conf.handler == NULL || uid == NULL ||
      access_token == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(conf.device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

#ifdef OC_SECURITY
  if (!cloud_tls_add_peer(conf.endpoint, conf.selected_identity_cred_id)) {
    OC_ERR("cannot connect to cloud");
    return false;
  }
#endif /* OC_SECURITY */

  if (!oc_init_post(OC_RSRVD_ACCOUNT_SESSION_URI, conf.endpoint, NULL,
                    conf.handler, LOW_QOS, conf.user_data)) {
    OC_ERR("Could not init POST request for sign in/out");
    return false;
  }
  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(conf.device), uuid, OC_UUID_LEN);

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, uid, uid);
  oc_rep_set_text_string(root, di, uuid);
  oc_rep_set_text_string(root, accesstoken, access_token);
  oc_rep_set_boolean(root, login, is_sign_in);
  oc_rep_end_root_object();

  return oc_do_post();
}

bool
cloud_access_login(oc_cloud_access_conf_t conf, const char *uid,
                   const char *access_token)
{
  return cloud_access_login_out(conf, uid, access_token, /*is_sign_in*/ true);
}

bool
cloud_access_logout(oc_cloud_access_conf_t conf, const char *uid,
                    const char *access_token)
{
  return cloud_access_login_out(conf, uid, access_token, /*is_sign_in*/ false);
}

bool
cloud_access_refresh_access_token(oc_cloud_access_conf_t conf, const char *uid,
                                  const char *refresh_token)
{
  if (conf.endpoint == NULL || conf.handler == NULL || uid == NULL ||
      refresh_token == NULL) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(conf.device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

#ifdef OC_SECURITY
  if (!cloud_tls_add_peer(conf.endpoint, conf.selected_identity_cred_id)) {
    OC_ERR("cannot connect to cloud");
    return false;
  }
#endif /* OC_SECURITY */

  if (!oc_init_post(OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI, conf.endpoint, NULL,
                    conf.handler, LOW_QOS, conf.user_data)) {
    OC_ERR("Could not init POST request for refresh access token");
    return false;
  }
  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(conf.device), uuid, OC_UUID_LEN);

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, uid, uid);
  oc_rep_set_text_string(root, di, uuid);
  oc_rep_set_text_string(root, granttype, OC_RSRVD_GRANT_TYPE_REFRESH_TOKEN);
  oc_rep_set_text_string(root, refreshtoken, refresh_token);
  oc_rep_end_root_object();

  return oc_do_post();
}

#endif /* OC_CLOUD */

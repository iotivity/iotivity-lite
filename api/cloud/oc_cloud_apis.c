/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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
#ifdef OC_CLOUD

#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_cloud.h"
#include "oc_cloud_internal.h"
#include "oc_core_res.h"
#include "port/oc_log.h"
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

OC_MEMB(api_params, cloud_api_param_t, 1);

cloud_api_param_t *
alloc_api_param(void)
{
  return (cloud_api_param_t *)oc_memb_alloc(&api_params);
}

void
free_api_param(cloud_api_param_t *p)
{
  oc_memb_free(&api_params, p);
}

int
conv_cloud_endpoint(oc_cloud_context_t *ctx)
{
  int ret = 0;
  oc_endpoint_t ep;
  memset(&ep, 0, sizeof(oc_endpoint_t));
  if (memcmp(&ep, ctx->cloud_ep, sizeof(oc_endpoint_t)) == 0) {
    ret = oc_string_to_endpoint(&ctx->store.ci_server, ctx->cloud_ep, NULL);
#ifdef OC_DNS_CACHE
    oc_dns_clear_cache();
#endif /* OC_DNS_CACHE */
  }
  return ret;
}

int
oc_cloud_register(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (ctx->store.status & OC_CLOUD_REGISTERED) {
    cb(ctx, ctx->store.status, data);
    return 0;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p) {
    p->ctx = ctx;
    p->cb = cb;
    p->data = data;

    if (ctx->store.status == OC_CLOUD_INITIALIZED) {
      OC_DBG("try register\n");
      bool cannotConnect = true;
      if (oc_string(ctx->store.ci_server) && conv_cloud_endpoint(ctx) == 0 &&
          cloud_access_register(
            ctx->cloud_ep, oc_string(ctx->store.auth_provider), NULL,
            oc_string(ctx->store.uid), oc_string(ctx->store.access_token),
            ctx->device, oc_cloud_register_handler, p)) {
        cannotConnect = false;
        ctx->store.cps = OC_CPS_REGISTERING;
      }
      if (cannotConnect) {
        cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
        free_api_param(p);
        return -1;
      }
      return 0;
    }
    free_api_param(p);
  }
  return -1;
}

int
oc_cloud_login(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (ctx->store.status & OC_CLOUD_LOGGED_IN) {
    cb(ctx, ctx->store.status, data);
    return 0;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p) {
    p->ctx = ctx;
    p->cb = cb;
    p->data = data;

    if (ctx->store.status & OC_CLOUD_REGISTERED) {
      OC_DBG("try login");
      bool cannotConnect = true;
      if (conv_cloud_endpoint(ctx) == 0 &&
          cloud_access_login(ctx->cloud_ep, oc_string(ctx->store.uid),
                             oc_string(ctx->store.access_token), ctx->device,
                             oc_cloud_login_handler, p)) {
        cannotConnect = false;
      }
      if (cannotConnect) {
        cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
        free_api_param(p);
        return -1;
      }
      return 0;
    }
    free_api_param(p);
  }
  return -1;
}

int
oc_cloud_get_token_expiry(oc_cloud_context_t *ctx)
{
  return (int)ctx->expires_in;
}

static void
cloud_logout_internal(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  if (data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
    cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
    ctx->store.status |= OC_CLOUD_FAILURE;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
    ctx->store.status |= OC_CLOUD_FAILURE;
  } else {
    ctx->store.status &= ~OC_CLOUD_LOGGED_IN;
    ctx->store.status |= OC_CLOUD_LOGGED_OUT;
  }

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_LOGGED_OUT);
}

int
oc_cloud_logout(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return -1;
  }
  cloud_api_param_t *p = alloc_api_param();
  if (p) {
    p->ctx = ctx;
    p->cb = cb;
    p->data = data;

    OC_DBG("try logout");
    bool cannotConnect = true;
    if (conv_cloud_endpoint(ctx) == 0 &&
        cloud_access_logout(ctx->cloud_ep, oc_string(ctx->store.uid),
                            oc_string(ctx->store.access_token), 0,
                            cloud_logout_internal, p)) {
      cannotConnect = false;
    }
    if (cannotConnect) {
      cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
      free_api_param(p);
      return -1;
    }
    return 0;
  }
  return -1;
}

static void
cloud_deregistered_internal(oc_client_response_t *data)
{
  cloud_api_param_t *p = (cloud_api_param_t *)data->user_data;
  oc_cloud_context_t *ctx = p->ctx;
  if (data->code < OC_STATUS_BAD_REQUEST ||
      data->code >= OC_STATUS_SERVICE_UNAVAILABLE) {
    ctx->store.status = OC_CLOUD_DEREGISTERED;
  } else if (data->code >= OC_STATUS_BAD_REQUEST) {
    cloud_set_last_error(ctx, CLOUD_ERROR_RESPONSE);
    ctx->store.status |= OC_CLOUD_FAILURE;
  }

  ctx->store.cps = OC_CPS_READYTOREGISTER;

  if (p->cb) {
    p->cb(ctx, ctx->store.status, p->data);
  }
  free_api_param(p);

  ctx->store.status &= ~(OC_CLOUD_FAILURE | OC_CLOUD_DEREGISTERED);

  cloud_store_dump_async(&ctx->store);
}

int
oc_cloud_deregister(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    return -1;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p) {
    p->ctx = ctx;
    p->cb = cb;
    p->data = data;

    OC_DBG("try deregister");
    bool cannotConnect = true;
    if (oc_string(ctx->store.ci_server) && conv_cloud_endpoint(ctx) == 0 &&
        cloud_access_deregister(ctx->cloud_ep, oc_string(ctx->store.uid),
                                oc_string(ctx->store.access_token), 0,
                                cloud_deregistered_internal, p)) {
      cannotConnect = false;
    }
    if (cannotConnect) {
      cloud_set_last_error(ctx, CLOUD_ERROR_CONNECT);
      free_api_param(p);
      return -1;
    }
    return 0;
  }
  return -1;
}

int
oc_cloud_refresh_token(oc_cloud_context_t *ctx, oc_cloud_cb_t cb, void *data)
{
  if (!ctx || !cb) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_REGISTERED)) {
    return -1;
  }

  cloud_api_param_t *p = alloc_api_param();
  if (p) {
    p->ctx = ctx;
    p->cb = cb;
    p->data = data;

    OC_DBG("try refresh token\n");
    bool cannotConnect = true;
    if (conv_cloud_endpoint(ctx) == 0 &&
        cloud_access_refresh_access_token(
          ctx->cloud_ep, oc_string(ctx->store.uid),
          oc_string(ctx->store.refresh_token), ctx->device,
          oc_cloud_refresh_token_handler, p)) {
      cannotConnect = false;
    }
    if (cannotConnect) {
      cloud_set_last_error(ctx, CLOUD_ERROR_REFRESH_ACCESS_TOKEN);
      free_api_param(p);
      return -1;
    }
    return 0;
  }
  return -1;
}

int
oc_cloud_discover_resources(oc_cloud_context_t *ctx,
                            oc_discovery_all_handler_t handler, void *user_data)
{
  if (!ctx) {
    return -1;
  }

  if (!(ctx->store.status & OC_CLOUD_LOGGED_IN)) {
    return -1;
  }

  if (oc_do_ip_discovery_all_at_endpoint(handler, ctx->cloud_ep, user_data)) {
    return 0;
  }

  return -1;
}

/* Internal APIs for accessing the OCF Cloud */
bool
cloud_access_register(oc_endpoint_t *endpoint, const char *auth_provider,
                      const char *auth_code, const char *uid,
                      const char *access_token, size_t device,
                      oc_response_handler_t handler, void *user_data)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

  if (!endpoint || ((!auth_provider || !auth_code) && !access_token) ||
      !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  if (!oc_tls_connected(endpoint)) {
    oc_tls_select_cloud_ciphersuite();
  }
#endif /* OC_SECURITY */

  if (oc_init_post(OC_RSRVD_ACCOUNT_URI, endpoint, NULL, handler, LOW_QOS,
                   user_data)) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device), uuid, OC_UUID_LEN);

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
cloud_access_deregister(oc_endpoint_t *endpoint, const char *uid,
                        const char *access_token, size_t device,
                        oc_response_handler_t handler, void *user_data)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

  if (!endpoint || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }
  oc_string_t at_uid;
  oc_string_t at;
  oc_concat_strings(&at, "accesstoken=", access_token);
  oc_string_t u_id;
  oc_concat_strings(&u_id, "&uid=", uid);
  oc_concat_strings(&at_uid, oc_string(at), oc_string(u_id));

  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(oc_core_get_device_id(device), uuid, OC_UUID_LEN);
  oc_string_t di;
  oc_concat_strings(&di, "&di=", uuid);
  oc_string_t at_uid_di;
  oc_concat_strings(&at_uid_di, oc_string(at_uid), oc_string(di));
#ifdef OC_SECURITY
  if (!oc_tls_connected(endpoint)) {
    oc_tls_select_cloud_ciphersuite();
  }
#endif /* OC_SECURITY */

  bool s = oc_do_delete(OC_RSRVD_ACCOUNT_URI, endpoint, oc_string(at_uid_di),
                        handler, HIGH_QOS, user_data);
  oc_free_string(&at_uid);
  oc_free_string(&at);
  oc_free_string(&u_id);
  oc_free_string(&di);
  oc_free_string(&at_uid_di);
  return s;
}

static bool
cloud_access_login_out(oc_endpoint_t *endpoint, const char *uid,
                       const char *access_token, size_t device, bool is_sign_in,
                       oc_response_handler_t handler, void *user_data)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

  if (!endpoint || (!uid) || !access_token || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  if (!oc_tls_connected(endpoint)) {
    oc_tls_select_cloud_ciphersuite();
  }
#endif /* OC_SECURITY */

  if (oc_init_post(OC_RSRVD_ACCOUNT_SESSION_URI, endpoint, NULL, handler,
                   LOW_QOS, user_data)) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device), uuid, OC_UUID_LEN);

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
cloud_access_login(oc_endpoint_t *endpoint, const char *uid,
                   const char *access_token, size_t device,
                   oc_response_handler_t handler, void *user_data)
{
  return cloud_access_login_out(endpoint, uid, access_token, device, true,
                                handler, user_data);
}

bool
cloud_access_logout(oc_endpoint_t *endpoint, const char *uid,
                    const char *access_token, size_t device,
                    oc_response_handler_t handler, void *user_data)
{
  return cloud_access_login_out(endpoint, uid, access_token, device, false,
                                handler, user_data);
}

bool
cloud_access_refresh_access_token(oc_endpoint_t *endpoint, const char *uid,
                                  const char *refresh_token, size_t device,
                                  oc_response_handler_t handler,
                                  void *user_data)
{
#ifdef OC_SECURITY
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  if (pstat->s != OC_DOS_RFNOP) {
    return false;
  }
#endif /* OC_SECURITY */

  if (!endpoint || !uid || !refresh_token || !handler) {
    OC_ERR("Error of input parameters");
    return false;
  }

#ifdef OC_SECURITY
  if (!oc_tls_connected(endpoint)) {
    oc_tls_select_cloud_ciphersuite();
  }
#endif /* OC_SECURITY */

  if (oc_init_post(OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI, endpoint, NULL, handler,
                   LOW_QOS, user_data)) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(oc_core_get_device_id(device), uuid, OC_UUID_LEN);

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
#else  /* OC_CLOUD*/
typedef int dummy_declaration;
#endif /* !OC_CLOUD */

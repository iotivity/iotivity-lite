/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_log_internal.h" // DPS_DBG, DPS_ERR
#include "plgd_dps_security_internal.h"
#include "plgd_dps_verify_certificate_internal.h"

#include "api/oc_endpoint_internal.h"
#include "api/oc_tcp_internal.h"  // oc_tcp_get_new_session_id, ...
#include "oc_api.h"               // oc_close_session
#include "oc_endpoint.h"          // oc_endpoint_t, oc_string_to_endpoint
#include "port/oc_connectivity.h" // oc_dns_clear_cache
#include "security/oc_tls_internal.h" // oc_tls_peer_t, oc_tls_select_cloud_ciphersuite, ...

#include "mbedtls/ssl.h" // MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_IS_CLIENT

#include <assert.h>
#include <inttypes.h> // PRId64

int
dps_endpoint_init(plgd_dps_context_t *ctx, const oc_string_t *ep_str)
{
  assert(ctx != NULL);
  int ret = 0;
  if ((ctx->endpoint != NULL) && dps_endpoint_is_empty(ctx->endpoint)) {
    ret = oc_string_to_endpoint(ep_str, ctx->endpoint, NULL);
    if (ret != 0) {
      memset(ctx->endpoint, 0, sizeof(oc_endpoint_t));
    }
#ifdef OC_DNS_CACHE
    oc_dns_clear_cache();
#endif /* OC_DNS_CACHE */
  }
  return ret;
}

#if DPS_DBG_IS_ENABLED

void
dps_endpoint_print_peers(const oc_endpoint_t *endpoint)
{
  // GCOVR_EXCL_START
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  DPS_DBG("peers for endpoint:");
  if (peer == NULL) {
    DPS_DBG("\tno peers were found");
    return;
  }

  while (peer != NULL) {
#define ENDPOINT_STR_LEN 256
    char ep_str[ENDPOINT_STR_LEN] = { 0 };
#undef ENDPOINT_STR_LEN
    bool valid =
      dps_endpoint_log_string(&peer->endpoint, ep_str, sizeof(ep_str));
    int is_server = valid && peer->role == MBEDTLS_SSL_IS_SERVER ? 1 : 0;
    DPS_DBG("\t%s, server: %d", valid ? ep_str : "NULL", is_server);
    peer = peer->next;
  }
  // GCOVR_EXCL_STOP
}
#endif /* DPS_DBG_IS_ENABLED */

oc_tls_peer_t *
dps_endpoint_add_peer(const oc_endpoint_t *endpoint)
{
#if DPS_DBG_IS_ENABLED
// GCOVR_EXCL_START
#define ENDPOINT_STR_LEN 256
  char ep_str[ENDPOINT_STR_LEN] = { 0 };
#undef ENDPOINT_STR_LEN
  bool valid = dps_endpoint_log_string(endpoint, ep_str, sizeof(ep_str));
  DPS_DBG("add peer %s", valid ? ep_str : "NULL");
// GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */

  oc_tls_select_cloud_ciphersuite();
  // force to use mfg cert
  oc_tls_select_identity_cert_chain(
    PLGD_DPS_DISABLE_SELECT_IDENTITY_CERT_CHAIN);

  dps_verify_certificate_data_t *vcd = dps_verify_certificate_data_new(
    oc_tls_peer_pki_default_verification_params());
  if (vcd == NULL) {
    return NULL;
  }
  oc_tls_new_peer_params_t new_peer = {
    .endpoint = endpoint,
    .role = MBEDTLS_SSL_IS_CLIENT,
    .user_data = {
      .data = vcd,
      .free = dps_verify_certificate_data_free,
    },
    .verify_certificate = dps_verify_certificate,
  };
  oc_tls_peer_t *peer = oc_tls_add_new_peer(new_peer);
  if (peer == NULL) {
    DPS_ERR("cannot add endpoint peer: oc_tls_add_new_peer peer failed");
    dps_verify_certificate_data_free(vcd);
    return NULL;
  }
#if DPS_DBG_IS_ENABLED
  dps_endpoint_print_peers(endpoint);
#endif /* DPS_DBG_IS_ENABLED */

  return peer;
}

void
dps_endpoint_close(const oc_endpoint_t *endpoint)
{
  assert(endpoint != NULL);
  if (!dps_endpoint_is_empty(endpoint)) {
    DPS_DBG("dps_endpoint_close");
    oc_close_session(endpoint);
  }
}

void
dps_endpoint_disconnect(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  DPS_DBG("dps_endpoint_disconnect");
  if (ctx->endpoint != NULL) {
    dps_endpoint_close(ctx->endpoint);
    memset(ctx->endpoint, 0, sizeof(oc_endpoint_t));
  }
  ctx->endpoint_state = OC_SESSION_DISCONNECTED;
}

bool
dps_endpoint_is_empty(const oc_endpoint_t *endpoint)
{
  assert(endpoint != NULL);
  return oc_endpoint_is_empty(endpoint);
}

bool
dps_endpoint_log_string(const oc_endpoint_t *endpoint, char *buffer,
                        size_t buffer_size)
{
  oc_string_t ep_str;
  memset(&ep_str, 0, sizeof(oc_string_t));
  if (oc_endpoint_to_string(endpoint, &ep_str) != 0) {
    return false;
  }
  size_t ep_str_len = oc_string_len_unsafe(ep_str);
  if ((ep_str_len == 0) || (ep_str_len >= buffer_size)) {
    oc_free_string(&ep_str);
    return false;
  }

#if DPS_DBG_IS_ENABLED
  // include session_id in debug
  int64_t session_id = oc_endpoint_session_id(endpoint);
  int len =
    snprintf(buffer, buffer_size, "endpoint(addr=%s, session_id=%" PRId64 ")",
             oc_string(ep_str), session_id);
#else  /* !DPS_DBG_IS_ENABLED */
  int len = snprintf(buffer, buffer_size, "endpoint(%s)", oc_string(ep_str));
#endif /* DPS_DBG_IS_ENABLED */
  if (len < 0 || (size_t)len >= buffer_size) {
    oc_free_string(&ep_str);
    return false;
  }

  oc_free_string(&ep_str);
  return true;
}

void
dps_setup_tls(const plgd_dps_context_t *ctx)
{
  if (oc_tls_get_peer(ctx->endpoint) != NULL) {
    return;
  }
  if (dps_endpoint_add_peer(ctx->endpoint) == NULL) {
    DPS_ERR("add peer failed");
    return;
  }
  DPS_DBG("setup tls with cloud cipher suite and manufacturer certificates");
}

void
dps_reset_tls(void)
{
  oc_tls_reset_ciphersuite();
  oc_tls_select_identity_cert_chain(PLGD_DPS_ENABLE_SELECT_IDENTITY_CERT_CHAIN);
  DPS_DBG("reset tls to use default cipher suite and default certificates");
}

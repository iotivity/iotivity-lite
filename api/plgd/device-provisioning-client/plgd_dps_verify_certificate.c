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

#include "plgd_dps_apis_internal.h"
#include "plgd_dps_context_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_verify_certificate_internal.h"

#include "oc_config.h"
#include "util/oc_memb.h"

OC_MEMB(g_dps_verify_certificate_data_pool, dps_verify_certificate_data_t,
        OC_MAX_NUM_DEVICES);

dps_verify_certificate_data_t *
dps_verify_certificate_data_new(oc_tls_pki_verification_params_t orig_verify)
{
  dps_verify_certificate_data_t *vcd =
    (dps_verify_certificate_data_t *)oc_memb_alloc(
      &g_dps_verify_certificate_data_pool);
  if (vcd == NULL) {
    DPS_ERR("oc_memb_alloc verify_certificate_data failed");
    return NULL;
  }
  vcd->fingerprint_verified = false;
  vcd->orig_verify = orig_verify;
  return vcd;
}

void
dps_verify_certificate_data_free(void *data)
{
  if (data == NULL) {
    return;
  }
  dps_verify_certificate_data_t *verify_data =
    (dps_verify_certificate_data_t *)data;
  if (verify_data->orig_verify.user_data.free != NULL) {
    verify_data->orig_verify.user_data.free(
      verify_data->orig_verify.user_data.data);
  }
  oc_memb_free(&g_dps_verify_certificate_data_pool, verify_data);
}

#if DPS_DBG_IS_ENABLED

void
dps_print_fingerprint(mbedtls_md_type_t md_type,
                      const unsigned char *fingerprint, size_t fingerprint_size)
{
  // GCOVR_EXCL_START
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  if (md_info == NULL) {
    DPS_ERR("dps_print_fingerprint - failed to get md_info from type %d",
            md_type);
    return;
  }

#define MD_NAME_SIZE 100
  char md_name[MD_NAME_SIZE] = { 0 };
  const char *md_name_tmp = mbedtls_md_get_name(md_info);
  if (md_name_tmp == NULL) {
    DPS_ERR("dps_print_fingerprint - failed to get md_name from md_info");
    return;
  }
  size_t md_name_tmp_len = strlen(md_name_tmp);
  size_t md_name_len = md_name_tmp_len > sizeof(md_name) - 1
                         ? sizeof(md_name) - 1
                         : md_name_tmp_len;
  memcpy(md_name, md_name_tmp, md_name_len);
  md_name[md_name_len] = '\0';

#define BUFFER_SIZE                                                            \
  (sizeof(md_name) - 1 + (size_t)(3 * MBEDTLS_MD_MAX_SIZE) + 1)
  char buffer[BUFFER_SIZE] = { 0 };
  size_t buffer_size = sizeof(buffer);
  snprintf(buffer, buffer_size, "%s", md_name);
  char prefix = ' ';
  for (size_t i = 0, j = md_name_len; i < fingerprint_size; i++, j += 3) {
    snprintf(buffer + j, buffer_size - j, "%c%02X", prefix, fingerprint[i]);
    prefix = ':';
  }
  DPS_DBG("fingerprint: %s", buffer);
  // GCOVR_EXCL_STOP
}

#endif /* DPS_DBG_IS_ENABLED */

static bool
calculate_fingerprint(const plgd_dps_context_t *ctx,
                      const mbedtls_x509_crt *crt, unsigned char *fingerprint,
                      size_t *fingerprint_size)
{
  assert(ctx);
  assert(crt);
  assert(fingerprint);
  assert(fingerprint_size);

  if (ctx->certificate_fingerprint.md_type == MBEDTLS_MD_NONE) {
    return true;
  }
  const mbedtls_md_info_t *md_info =
    mbedtls_md_info_from_type(ctx->certificate_fingerprint.md_type);
  if (md_info == NULL) {
    DPS_ERR("calculate certificate fingerprint algorithm not found");
    return false;
  }

  int ret = mbedtls_md(md_info, crt->raw.p, crt->raw.len, fingerprint);
  if (ret != 0) {
    DPS_ERR("calculate certificate fingerprint failed %x", ret);
    return false;
  }
  *fingerprint_size = mbedtls_md_get_size(md_info);
#if DPS_DBG_IS_ENABLED
  dps_print_fingerprint(ctx->certificate_fingerprint.md_type, fingerprint,
                        *fingerprint_size);
#endif /* DPS_DBG_IS_ENABLED */
  return true;
}

int
dps_verify_certificate(oc_tls_peer_t *peer, const mbedtls_x509_crt *crt,
                       int depth, uint32_t *flags)
{
  DPS_DBG("verifying certificate at depth %d, flags %u", depth, *flags);

  const plgd_dps_context_t *ctx = plgd_dps_get_context(peer->endpoint.device);
  if (ctx == NULL) {
    DPS_ERR("verifying certificate - context is NULL");
    return -1;
  }

  dps_verify_certificate_data_t *cb_data =
    (dps_verify_certificate_data_t *)peer->user_data.data;
  if (cb_data == NULL) {
    DPS_ERR("verifying certificate - cb_data is NULL");
    return -1;
  }

  unsigned char fingerprint[MBEDTLS_MD_MAX_SIZE] = { 0 };
  /* buffer is max length of returned hash, which is 64 in case we use sha-512
   */
  size_t fingerprint_size = 0;
  if (!calculate_fingerprint(ctx, crt, fingerprint, &fingerprint_size)) {
    return -1;
  }

  // check fingerprint every time
  if (ctx->certificate_fingerprint.md_type != MBEDTLS_MD_NONE &&
      dps_is_equal_string_len(ctx->certificate_fingerprint.data,
                              (const char *)fingerprint, fingerprint_size)) {
    DPS_DBG("verifying certificate - fingerprint matches");
    cb_data->fingerprint_verified = true;
  }

  oc_tls_pki_verification_params_t dps_verify = {
    .user_data = peer->user_data,
    .verify_certificate = peer->verify_certificate,
  };
  // set original parameters on the peer
  peer->verify_certificate = cb_data->orig_verify.verify_certificate;
  peer->user_data = cb_data->orig_verify.user_data;
  int ret = peer->verify_certificate(peer, crt, depth, flags);
  // restore dps configuration
  peer->verify_certificate = dps_verify.verify_certificate;
  peer->user_data = dps_verify.user_data;
  if (ret == 0 && (flags == NULL || *flags == 0)) {
    DPS_DBG("verifying certificate - orig_verify_certificate returned 0 and "
            "flags is 0 - accept connection");
    return 0;
  }
  if (ctx->certificate_fingerprint.md_type != MBEDTLS_MD_NONE) {
    DPS_DBG("verifying certificate - verifying fingerprint");
    if (depth > 0) {
      DPS_DBG("verifying certificate - continue check");
      *flags = 0;
      return 0;
    }
    if (cb_data->fingerprint_verified) {
      DPS_DBG("verifying certificate - fingerprint valid - accept connection");
      if (flags != NULL) {
        *flags = 0;
      }
      if (peer->user_data.free != NULL) {
        peer->user_data.free(peer->user_data.data);
      }
      peer->user_data.data = NULL;
      peer->user_data.free = NULL;
      return 0;
    }
    DPS_ERR(
      "verifying certificate - fingerprint is invalid - reject connection");
    return -1;
  }
  if (ctx->skip_verify) {
    DPS_DBG("verifying certificate - skip verify");
    if (flags != NULL) {
      *flags = 0;
    }
    return 0;
  }
  return ret;
}

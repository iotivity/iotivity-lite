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
#include "plgd_dps_endpoint_internal.h"
#include "plgd_dps_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_manager_internal.h"
#include "plgd_dps_pki_internal.h"
#include "plgd_dps_provision_internal.h"
#include "plgd_dps_retry_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_tag_internal.h"
#include "plgd_dps_time_internal.h"

#include "oc_api.h"
#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_csr.h"
#include "oc_ri.h"
#include "oc_store.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_tls_internal.h"

#include <assert.h>
#include <inttypes.h>

// NOLINTNEXTLINE(modernize-*)
#define SECONDS_PER_MINUTE (60)
// NOLINTNEXTLINE(modernize-*)
#define MINUTES_PER_HOUR (60)

void
dps_pki_init(dps_pki_configuration_t *pki)
{
  assert(pki != NULL);
  const uint16_t kDefaultExpiringLimit =
    UINT16_C(MINUTES_PER_HOUR * SECONDS_PER_MINUTE); // 1 hour
  pki->expiring_limit = kDefaultExpiringLimit;
}

bool
dps_pki_send_csr(plgd_dps_context_t *ctx, oc_response_handler_t handler)
{
  assert(ctx != NULL);
  assert(handler != NULL);

  // NOLINTNEXTLINE(readability-magic-numbers)
  unsigned char csr_data[1024];
  if (oc_sec_csr_generate(ctx->device, oc_sec_certs_md_signature_algorithm(),
                          csr_data, sizeof(csr_data)) != 0) {
    return false;
  }

  if (!oc_init_post(PLGD_DPS_CREDS_URI, ctx->endpoint, NULL, handler, LOW_QOS,
                    ctx)) {
    DPS_ERR("could not init POST request to %s", PLGD_DPS_CREDS_URI);
    return false;
  }

  const oc_uuid_t *device_id = oc_core_get_device_id(ctx->device);
  if (device_id == NULL) {
    DPS_ERR("failed to get device id for POST request to %s",
            PLGD_DPS_CREDS_URI);
    return false;
  }
  char uuid[OC_UUID_LEN] = { 0 };
  int uuid_len = oc_uuid_to_str_v1(device_id, uuid, OC_UUID_LEN);
  assert(uuid_len > 0);

  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, di, uuid, uuid_len);
  oc_rep_set_object(root, csr);
  oc_rep_set_text_string(csr, data, (const char *)csr_data);
  oc_rep_set_text_string(csr, encoding, "oic.sec.encoding.pem");
  oc_rep_close_object(root, csr);
  oc_rep_end_root_object();

  dps_setup_tls(ctx);
  if (!oc_do_post_with_timeout(dps_retry_get_timeout(&ctx->retry))) {
    dps_reset_tls();
    DPS_ERR("failed to dispatch POST request to %s", PLGD_DPS_CREDS_URI);
    return false;
  }
  return true;
}

static const char *g_dps_certificate_state_str[] = {
  "valid",
  "not yet valid",
  "expiring",
  "expired",
};

const char *
dps_pki_certificate_state_to_str(dps_certificate_state_t state)
{
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
  assert((size_t)state < ARRAY_SIZE(g_dps_certificate_state_str));
  return g_dps_certificate_state_str[(size_t)state];
}

static bool
dps_pki_certificate_is_expiring(dps_pki_configuration_t cfg, uint64_t valid_to,
                                uint64_t now_s)
{
  return now_s + cfg.expiring_limit > valid_to;
}

int
dps_pki_validate_certificate(dps_pki_configuration_t cfg, uint64_t valid_from,
                             uint64_t valid_to)
{
  oc_clock_time_t now = dps_time();
  if (now == (oc_clock_time_t)-1) {
    DPS_ERR("cannot validate certificate: %s", "failed to get current time");
    return -1;
  }

  uint64_t now_s = now / OC_CLOCK_SECOND;
  DPS_DBG("\tcheck certificate validity: now=%" PRIu64 " from=%" PRIu64
          " to=%" PRIu64 " expiring_limit:%u",
          now_s, valid_from, valid_to, (unsigned)cfg.expiring_limit);
  if (now_s < valid_from) {
    return DPS_CERTIFICATE_NOT_YET_VALID;
  }

  if (dps_pki_certificate_is_expiring(cfg, valid_to, now_s)) {
    return now_s > valid_to ? DPS_CERTIFICATE_EXPIRED
                            : DPS_CERTIFICATE_EXPIRING;
  }
  return DPS_CERTIFICATE_VALID;
}

static void
dps_on_apply_cred(oc_sec_on_apply_cred_data_t cred_data, void *user_data)
{
  if (cred_data.cred == NULL) {
    return;
  }
  bool *credentials_replaced = (bool *)user_data;
  *credentials_replaced = *credentials_replaced || (cred_data.replaced != NULL);
#if DPS_DBG_IS_ENABLED
  // GCOVR_EXCL_START
  DPS_DBG("apply cred:");
  bool duplicate = !cred_data.created && cred_data.replaced == NULL;
  int replaced_credid =
    cred_data.replaced != NULL ? cred_data.replaced->credid : -1;
  DPS_DBG("\tcreated:%d duplicate:%d replaced credid:%d", cred_data.created,
          duplicate, replaced_credid);
  char uuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&cred_data.cred->subjectuuid, uuid, sizeof(uuid));
  const char *tag = oc_string_len(cred_data.cred->tag) > 0
                      ? oc_string(cred_data.cred->tag)
                      : "";
  DPS_DBG("\tcredid:%d credtype:%d credusage:%d subjectuuid:%s tag:%s",
          cred_data.cred->credid, cred_data.cred->credtype,
          cred_data.cred->credusage, uuid, tag);
  // GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */
}

bool
dps_pki_replace_certificates(size_t device, const oc_rep_t *rep,
                             const oc_endpoint_t *endpoint)
{
  const oc_resource_t *sec_cred =
    oc_core_get_resource_by_index(OCF_SEC_CRED, device);
  if (sec_cred == NULL) {
    DPS_ERR("cannot find credential resource for device(%zu)", device);
    return false;
  }

  dps_credentials_set_stale_tag(device);
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  pstat->s = OC_DOS_RFPRO;
  oc_sec_on_apply_cred_cb_t on_apply_cred_cb = dps_on_apply_cred;
  bool credentials_replaced = false;
  int ret = oc_sec_apply_cred(rep, sec_cred, endpoint, on_apply_cred_cb,
                              &credentials_replaced);
  pstat->s = OC_DOS_RFNOP;
  if (ret != 0) {
    DPS_ERR("cannot apply credential resource update for device(%zu)", device);
    dps_credentials_remove_stale_tag(device);
    return false;
  }
  int credentials_removed = dps_remove_stale_credentials(device);

#if DPS_DBG_IS_ENABLED
  dps_print_certificates(device);
#endif /* DPS_DBG_IS_ENABLED */

  oc_sec_dump_cred(device);

  if (credentials_replaced || credentials_removed > 0) {
    DPS_DBG("credentials modification detected");
    // must be called after assignment pstat->s = OC_DOS_RFNOP
    oc_tls_close_peers(dps_endpoint_peer_is_server, NULL);
  }
  return true;
}

bool
dps_pki_can_replace_certificates(const plgd_dps_context_t *ctx)
{
  return dps_is_provisioned_with_cloud_started(ctx);
}

void
dps_pki_schedule_renew_certificates(plgd_dps_context_t *ctx, uint64_t valid_to,
                                    uint64_t min_interval)
{
  uint64_t interval =
    dps_pki_calculate_renew_certificates_interval(ctx->pki, valid_to);
  if (interval == (uint64_t)-1) {
    DPS_ERR("certificate renewal not scheduled: failed to calculate "
            "credentials check interval");
    return;
  }
  if (interval < min_interval) {
    DPS_DBG(
      "substituting minimal allowed interval for the calculated interval");
    interval = min_interval;
  }
  DPS_INFO("certificate renewal scheduled to run in %" PRIu64 " milliseconds",
           interval);
  dps_reset_delayed_callback_ms(ctx, dps_pki_renew_certificates_async,
                                interval);
}

uint64_t
dps_pki_calculate_renew_certificates_interval(dps_pki_configuration_t cfg,
                                              uint64_t valid_to)
{
  oc_clock_time_t now = dps_time();
  if (now == (oc_clock_time_t)-1) {
    return (uint64_t)-1;
  }

  uint64_t now_s = now / OC_CLOCK_SECOND;
  if (dps_pki_certificate_is_expiring(cfg, valid_to, now_s)) {
    return 0; // recheck the credentials right away
  }

  const uint64_t kMinInterval = UINT64_C(
    10); // use some minimal interval to prevent constant retries in case the
         // server issues certificates with short expiration time
  const uint64_t kLimit1 = UINT64_C(1) * SECONDS_PER_MINUTE;
  if (now_s + kLimit1 > valid_to) { // expiring within 1 minute
    return kMinInterval *
           MILLISECONDS_PER_SECOND; // recheck after some minimal interval
  }

  const uint64_t kLimit2 = UINT64_C(3) * SECONDS_PER_MINUTE;
  if (now_s + kLimit2 > valid_to) { // expiring within 3 minutes
    return UINT64_C(1) * SECONDS_PER_MINUTE *
           MILLISECONDS_PER_SECOND; // recheck in a minute
  }

  const uint64_t kLimit3 = UINT64_C(6) * SECONDS_PER_MINUTE;
  if (now_s + kLimit3 > valid_to) { // expiring within 6 minutes
    return UINT64_C(2) * SECONDS_PER_MINUTE *
           MILLISECONDS_PER_SECOND; // recheck in 2 minutes
  }

  return ((UINT64_C(2) * (valid_to - now_s)) / UINT64_C(3)) *
         MILLISECONDS_PER_SECOND; // try after 2/3 of the remaining time passes
}

static bool
dps_pki_replace_credentials_retry(plgd_dps_context_t *ctx)
{
  uint64_t retry = dps_retry_get_delay(&ctx->retry);
  dps_retry_increment(ctx, PLGD_DPS_RENEW_CREDENTIALS);
  DPS_DBG("retry certificates renewal");
  return dps_check_credentials_and_schedule_renewal(ctx, retry);
}

static void
dps_pki_replace_credentials_handler(oc_client_response_t *data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)data->user_data;
  oc_remove_delayed_callback(ctx, dps_pki_renew_certificates_retry_async);
  if (!dps_pki_can_replace_certificates(ctx) &&
      (ctx->status & PLGD_DPS_RENEW_CREDENTIALS) == 0) {
    DPS_DBG("replacing of certificates skipped");
    return;
  }

  plgd_dps_error_t err = dps_check_response(ctx, data->code, data->payload);
  if (err != PLGD_DPS_OK) {
    DPS_ERR("cannot replace certificates: invalid %s response(status=%d)",
            PLGD_DPS_CREDS_URI, data->code);
    goto retry;
  }

  if (!dps_pki_replace_certificates(ctx->device, data->payload,
                                    data->endpoint)) {
    goto retry;
  }

  if (!dps_check_credentials_and_schedule_renewal(ctx, 0)) {
    DPS_ERR("valid certificates not found");
    goto reprovision;
  }

  if (!dps_try_set_identity_chain(ctx->device)) {
    DPS_ERR("failed to set identity certificate chain");
    goto reprovision;
  }
  DPS_DBG("certificates renewed successfully");
  dps_set_ps_and_last_error(ctx, 0, PLGD_DPS_RENEW_CREDENTIALS, PLGD_DPS_OK);
  dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  dps_retry_reset(ctx, dps_provision_get_next_action(ctx));
  ctx->transient_retry_count = 0;
  dps_endpoint_close(ctx->endpoint);

  return;

retry:
  if (dps_pki_replace_credentials_retry(ctx)) {
    return;
  }
  DPS_ERR("failed to reschedule certificates renewal, force reprovisioning");

reprovision:
  dps_manager_reprovision_and_restart(ctx);
}

bool
dps_pki_try_renew_certificates(plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  DPS_DBG("trying to replace expiring DPS certificates");

  if (!dps_pki_send_csr(ctx, dps_pki_replace_credentials_handler)) {
    DPS_ERR("failed to obtain new DPS certificates: %s",
            "failed to send CSR request");
    return false;
  }

  // schedule retry in case response is not retrieved
  dps_reset_delayed_callback_ms(ctx, dps_pki_renew_certificates_retry_async,
                                dps_retry_get_delay(&ctx->retry));

  if (dps_set_ps_and_last_error(ctx, PLGD_DPS_RENEW_CREDENTIALS, 0,
                                PLGD_DPS_OK)) {
    dps_reset_delayed_callback(ctx, dps_status_callback_handler, 0);
  }
  return true;
}

oc_event_callback_retval_t
dps_pki_renew_certificates_retry_async(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  dps_retry_increment(ctx, PLGD_DPS_RENEW_CREDENTIALS);
  return dps_pki_renew_certificates_async(ctx);
}

oc_event_callback_retval_t
dps_pki_renew_certificates_async(void *user_data)
{
  plgd_dps_context_t *ctx = (plgd_dps_context_t *)user_data;
  if (!dps_pki_can_replace_certificates(ctx)) {
    DPS_DBG("renewal of certificates skipped");
    return OC_EVENT_DONE;
  }

  if (!dps_pki_try_renew_certificates(ctx)) {
    uint64_t retry = dps_retry_get_delay(&ctx->retry);
    dps_retry_increment(ctx, PLGD_DPS_RENEW_CREDENTIALS);
    if (!dps_check_credentials_and_schedule_renewal(ctx, retry)) {
      DPS_ERR(
        "failed to reschedule certificates renewal, force reprovisioning");
      dps_manager_reprovision_and_restart(ctx);
    }
  }
  return OC_EVENT_DONE;
}

void
plgd_dps_pki_set_expiring_limit(plgd_dps_context_t *ctx,
                                uint16_t expiring_limit)
{
  assert(ctx != NULL);
  DPS_DBG("certificate expiring limit set to %us", (unsigned)expiring_limit);
  ctx->pki.expiring_limit = expiring_limit;
}

uint16_t
plgd_dps_pki_get_expiring_limit(const plgd_dps_context_t *ctx)
{
  assert(ctx != NULL);
  return ctx->pki.expiring_limit;
}

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

#include "plgd_dps_context_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_pki_internal.h"
#include "plgd_dps_security_internal.h"
#include "plgd_dps_tag_internal.h"

#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_store.h"
#include "oc_uuid.h"
#include "security/oc_acl_internal.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_tls_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum {
  /* vendor specific constant 0xFF01 for DPS device */
  DPS_OXMTYPE_PLGD = 0xFF01,
};

bool
dps_is_dos_owned(size_t device)
{
  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
  return (pstat->s == OC_DOS_RFPRO || pstat->s == OC_DOS_RFNOP);
}

static bool
dps_is_owned(const plgd_dps_context_t *ctx, const oc_uuid_t *owner)
{
  char owner_str[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(owner, owner_str, sizeof(owner_str));
  if ((oc_string_len(ctx->store.owner) != OC_UUID_LEN - 1) ||
      strncmp(oc_string(ctx->store.owner), owner_str, OC_UUID_LEN - 1) != 0) {
    return false;
  }

  const oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  if (memcmp(pstat->rowneruuid.id, owner->id, OC_UUID_ID_SIZE) != 0) {
    return false;
  }
  if (!pstat->isop) {
    return false;
  }

  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(ctx->device);
  if (!doxm->owned) {
    return false;
  }
  if (doxm->oxmsel != DPS_OXMTYPE_PLGD) {
    return false;
  }
  if (memcmp(doxm->rowneruuid.id, owner->id, OC_UUID_ID_SIZE) != 0) {
    return false;
  }
  if (memcmp(doxm->devowneruuid.id, owner->id, OC_UUID_ID_SIZE) != 0) {
    return false;
  }

  const oc_sec_creds_t *creds = oc_sec_get_creds(ctx->device);
  if (memcmp(creds->rowneruuid.id, owner->id, OC_UUID_ID_SIZE) != 0) {
    return false;
  }

  const oc_sec_acl_t *acls = oc_sec_get_acl(ctx->device);
  if (memcmp(acls->rowneruuid.id, owner->id, OC_UUID_ID_SIZE) != 0) {
    return false;
  }

  return true;
}

bool
dps_is_self_owned(const plgd_dps_context_t *ctx)
{
  const oc_uuid_t *uuid = oc_core_get_device_id(ctx->device);
  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(ctx->device);
  if (memcmp(doxm->deviceuuid.id, uuid->id, OC_UUID_ID_SIZE) != 0) {
    return false;
  }

  return dps_is_owned(ctx, uuid);
}

static void
dps_clear_credentials(size_t device)
{
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *cred = (oc_sec_cred_t *)oc_list_head(creds->creds);
  while (cred != NULL) {
    oc_sec_cred_t *c_next = cred->next;
    bool skipDelete = cred->credtype == OC_CREDTYPE_CERT &&
                      (cred->credusage == OC_CREDUSAGE_MFG_CERT ||
                       cred->credusage == OC_CREDUSAGE_MFG_TRUSTCA) &&
                      !dps_is_dps_cred(cred);
    if (!skipDelete) {
      oc_sec_remove_cred(cred, device);
    }
    cred = c_next;
  }
}

bool
dps_endpoint_peer_is_server(const oc_tls_peer_t *peer, void *user_data)
{
  (void)user_data;
  bool is_server = peer->role == MBEDTLS_SSL_IS_SERVER;
#if DPS_DBG_IS_ENABLED
  // GCOVR_EXCL_START
  if (is_server) {
    oc_string_t ep_str;
    if (oc_endpoint_to_string(&peer->endpoint, &ep_str) == 0) {
      DPS_DBG("remove peer endpoint: %s", oc_string(ep_str));
      oc_free_string(&ep_str);
    }
  }
  // GCOVR_EXCL_STOP
#endif /* DPS_DBG_IS_ENABLED */
  return is_server;
}

static bool
dps_own_device(plgd_dps_context_t *ctx, const oc_uuid_t *owner)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  if (pstat->s != OC_DOS_RFOTM) {
    DPS_ERR("cannot own device: device(%zu) is not in RFOTM state",
            ctx->device);
    return false;
  }

  char owner_str[OC_UUID_LEN] = { 0 };
  int owner_str_len = oc_uuid_to_str_v1(owner, owner_str, sizeof(owner_str));
  assert(owner_str_len > 0);
  oc_set_string(&ctx->store.owner, owner_str, (size_t)owner_str_len);

#if DPS_DBG_IS_ENABLED
  DPS_DBG("own device by %s", owner_str);
#endif /*DPS_DBG_IS_ENABLED*/

  memcpy(pstat->rowneruuid.id, owner->id, OC_UUID_ID_SIZE);
  pstat->tm = pstat->cm = 4;
  pstat->isop = true;
  pstat->s = OC_DOS_RFNOP;
  oc_sec_dump_pstat(ctx->device);

  oc_sec_doxm_t *doxm = oc_sec_get_doxm(ctx->device);
  memcpy(doxm->devowneruuid.id, owner->id, OC_UUID_ID_SIZE);
  memcpy(doxm->rowneruuid.id, owner->id, OC_UUID_ID_SIZE);
  doxm->owned = true;
  doxm->oxmsel = DPS_OXMTYPE_PLGD;
  oc_sec_dump_doxm(ctx->device);

  DPS_DBG("clear credentials");
  dps_clear_credentials(ctx->device);
  oc_sec_creds_t *creds = oc_sec_get_creds(ctx->device);
  memcpy(creds->rowneruuid.id, owner->id, OC_UUID_ID_SIZE);
  oc_sec_dump_cred(ctx->device);

  DPS_DBG("clear acls");
  oc_sec_acl_clear(ctx->device, NULL, NULL);
  if (!oc_sec_acl_add_bootstrap_acl(ctx->device)) {
    DPS_ERR("failed to boostrap ACLs");
    return false;
  }
  oc_sec_acl_t *acls = oc_sec_get_acl(ctx->device);
  memcpy(acls->rowneruuid.id, owner->id, OC_UUID_ID_SIZE);
  oc_sec_dump_acl(ctx->device);
#if DPS_DBG_IS_ENABLED
  dps_print_certificates(ctx->device);
  dps_print_acls(ctx->device);
  dps_print_peers();
#endif /*DPS_DBG_IS_ENABLED*/

  // must be called after assignment pstat->s = OC_DOS_RFNOP
  oc_tls_close_peers(dps_endpoint_peer_is_server, NULL);
  return true;
}

bool
dps_set_owner(plgd_dps_context_t *ctx, const oc_uuid_t *owner)
{
  if (dps_is_dos_owned(ctx->device) && dps_is_owned(ctx, owner)) {
    DPS_DBG("set owner skipped: already set");
    return true;
  }
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  pstat->s = OC_DOS_RFOTM;
  return dps_own_device(ctx, owner);
}

bool
dps_set_self_owned(plgd_dps_context_t *ctx)
{
  if (dps_is_dos_owned(ctx->device) && dps_is_self_owned(ctx)) {
    return true;
  }
  const oc_uuid_t *uuid = oc_core_get_device_id(ctx->device);
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(ctx->device);
  pstat->s = OC_DOS_RFOTM;
  return dps_own_device(ctx, uuid);
}

bool
dps_has_owner(const plgd_dps_context_t *ctx)
{
  if (!dps_is_dos_owned(ctx->device) || dps_is_self_owned(ctx)) {
    return false;
  }

  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(ctx->device);
  oc_uuid_t owner;
  memcpy(owner.id, doxm->devowneruuid.id, OC_UUID_ID_SIZE);
  return dps_is_owned(ctx, &owner);
}

int
dps_factory_reset(size_t device, bool force)
{
  assert(dps_is_dos_owned(device));
  return oc_reset_device_v1(device, force) ? 0 : -1;
}

static bool
dps_is_dps_ace(const oc_sec_ace_t *ace)
{
  return oc_string_len(ace->tag) == DPS_TAG_LEN &&
         strcmp(oc_string(ace->tag), DPS_TAG) == 0;
}

bool
dps_has_acls(size_t device)
{
  const oc_sec_acl_t *acl = oc_sec_get_acl(device);
  const oc_sec_ace_t *ace = oc_list_head(acl->subjects);
  while (ace != NULL) {
    if (dps_is_dps_ace(ace)) {
      return true;
    }
    ace = ace->next;
  }

  return false;
}

bool
dps_is_dps_cred(const oc_sec_cred_t *cred)
{
  assert(cred != NULL);
  return oc_string_len(cred->tag) == DPS_TAG_LEN &&
         strcmp(oc_string(cred->tag), DPS_TAG) == 0;
}

static bool
is_identity_cred(const oc_sec_cred_t *cred)
{
  assert(cred != NULL);
  return cred->credtype == OC_CREDTYPE_CERT &&
         cred->credusage == OC_CREDUSAGE_IDENTITY_CERT;
}

static bool
is_dps_identity_cred(const oc_sec_cred_t *cred)
{
  return is_identity_cred(cred) && dps_is_dps_cred(cred);
}

static bool
is_trust_ca_cred(const oc_sec_cred_t *cred)
{
  assert(cred != NULL);
  return cred->credtype == OC_CREDTYPE_CERT &&
         cred->credusage == OC_CREDUSAGE_TRUSTCA;
}

typedef struct
{
  dps_pki_configuration_t cfg;
  uint64_t valid_from;
  uint64_t valid_to;
} dps_verify_certificate_data_t;

static bool
dps_verify_certificate_data(const oc_sec_certs_data_t *data, void *user_data)
{
  if (data == NULL) {
    return false;
  }

  dps_verify_certificate_data_t *udata =
    (dps_verify_certificate_data_t *)user_data;
  int ret =
    dps_pki_validate_certificate(udata->cfg, data->valid_from, data->valid_to);
  if (ret == -1) {
    return false;
  }
  dps_certificate_state_t cert_state = (dps_certificate_state_t)ret;
  if (cert_state != DPS_CERTIFICATE_VALID) {
    DPS_ERR("invalid certificate: %s",
            dps_pki_certificate_state_to_str(cert_state));
    return false;
  }

  udata->valid_to = data->valid_to;
  udata->valid_from = data->valid_from;
  return true;
}

typedef struct
{
  uint64_t valid_from;
  uint64_t valid_to;
} dps_certificate_validity_t;

static bool
dps_check_credentials(const plgd_dps_context_t *ctx,
                      dps_certificate_validity_t *min_validity)
{
  oc_remove_delayed_callback(NULL, dps_pki_renew_certificates_async);

  bool all_valid = true;
  bool has_identity = false;
  bool has_trust_anchor = false;
  uint64_t valid_to = UINT64_MAX;
  uint64_t valid_from = 0;
  const oc_sec_creds_t *creds = oc_sec_get_creds(ctx->device);
  oc_sec_cred_t *cred = oc_list_head(creds->creds);
  while (cred != NULL) {
    oc_sec_cred_t *cred_next = cred->next;
    if (!dps_is_dps_cred(cred) || cred->credtype == OC_CREDTYPE_PSK) {
      cred = cred_next;
      continue;
    }
    DPS_DBG("check certificates for cred(credid=%d):", cred->credid);
    dps_verify_certificate_data_t data = {
      .cfg = ctx->pki,
    };
    int ret = oc_cred_verify_certificate_chain(
      cred, dps_verify_certificate_data, &data);
    if (ret != 0) {
      if (ret == -1) {
        DPS_ERR("failed to get certificate data for cred(credid=%d)",
                cred->credid);
      }
      if (ret == 1) {
        DPS_DBG("removing credential with expired certificate");
        oc_sec_remove_cred(cred, ctx->device);
      }
      all_valid = false;
      cred = cred_next;
      continue; // go through all credentials, so we remove all expired
                // certificates
    }
    has_identity = is_identity_cred(cred) ? true : has_identity;
    has_trust_anchor = is_trust_ca_cred(cred) ? true : has_trust_anchor;

    if (data.valid_to < valid_to) {
      valid_from = data.valid_from;
      valid_to = data.valid_to;
    }
    cred = cred_next;
  }

  if (!all_valid || !has_identity || !has_trust_anchor) {
    return false;
  }
  DPS_DBG("earliest expiring certificate(valid-from: %lu, valid-to: %lu)",
          valid_from, valid_to);
  if (min_validity != NULL) {
    min_validity->valid_from = valid_from;
    min_validity->valid_to = valid_to;
  }
  return true;
}

bool
dps_check_credentials_and_schedule_renewal(plgd_dps_context_t *ctx,
                                           uint64_t min_interval)
{
  dps_certificate_validity_t min;
  if (!dps_check_credentials(ctx, &min)) {
    return false;
  }
  dps_pki_schedule_renew_certificates(ctx, min.valid_to, min_interval);
  return true;
}

int
dps_get_identity_credid(size_t device)
{
  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  if (creds == NULL) {
    return -1;
  }
  for (const oc_sec_cred_t *cred =
         (const oc_sec_cred_t *)oc_list_head(creds->creds);
       cred != NULL; cred = cred->next) {
    if (is_dps_identity_cred(cred)) {
      return cred->credid;
    }
  }
  return -1;
}

#if DPS_DBG_IS_ENABLED
void
dps_print_acls(size_t device)
{
  // GCOVR_EXCL_START
  DPS_DBG("acls:");
  const oc_sec_acl_t *acls = oc_sec_get_acl(device);
  char rowneruuid[OC_UUID_LEN] = { 0 };
  oc_uuid_to_str(&acls->rowneruuid, rowneruuid, sizeof(rowneruuid));
  DPS_DBG("\trowneruuid:%s", rowneruuid);
  const oc_sec_ace_t *ace = oc_list_head(acls->subjects);
  while (ace != NULL) {
    const char *tag = oc_string_len(ace->tag) > 0 ? oc_string(ace->tag) : "";
    const oc_ace_subject_t *subject = &ace->subject;
    if (ace->subject_type == OC_SUBJECT_ROLE) {
      const char *role = oc_string_len(subject->role.role) > 0
                           ? oc_string(subject->role.role)
                           : "";
      const char *authority = oc_string_len(subject->role.authority) > 0
                                ? oc_string(subject->role.authority)
                                : "";
      DPS_DBG("\taceid:%d subject_type:%d subject.role:%s subject.authority:%s "
              "subject.conn:%d permission:%d tag:%s",
              ace->aceid, ace->subject_type, role, authority, subject->conn,
              ace->permission, tag);
    } else {
      char uuid[OC_UUID_LEN] = { 0 };
      oc_uuid_to_str(&subject->uuid, uuid, sizeof(uuid));
      DPS_DBG("\taceid:%d uuid:%s subject_type:%d subject.conn:%d "
              "permission:%d tag:%s",
              ace->aceid, uuid, ace->subject_type, subject->conn,
              ace->permission, tag);
    }
    oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head(ace->resources);
    if (res != NULL) {
      DPS_DBG("\tresources:");
      for (; res != NULL; res = res->next) {
        const char *href =
          oc_string_len(res->href) > 0 ? oc_string(res->href) : "";
        DPS_DBG("\t\thref:%s wildcard:%d", href, res->wildcard);
      }
    }

    ace = ace->next;
  }
  // GCOVR_EXCL_STOP
}

void
dps_print_certificates(size_t device)
{
  // GCOVR_EXCL_START
  DPS_DBG("certificates:");
  const oc_sec_creds_t *creds = oc_sec_get_creds(device);
  const oc_sec_cred_t *cred = (const oc_sec_cred_t *)oc_list_head(creds->creds);
  while (cred != NULL) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(&cred->subjectuuid, uuid, sizeof(uuid));
    const char *tag = oc_string_len(cred->tag) > 0 ? oc_string(cred->tag) : "";
    DPS_DBG("\tcredid: %d, credtype: %d, credusage: %d, subjectuuid:%s, tag:%s",
            cred->credid, cred->credtype, cred->credusage, uuid, tag);
    cred = cred->next;
  }
  // GCOVR_EXCL_STOP
}

void
dps_print_peers(void)
{
  // GCOVR_EXCL_START
  const oc_tls_peer_t *peer = oc_tls_get_peer(NULL);
  DPS_DBG("peers:");
  if (peer == NULL) {
    DPS_DBG("\tno peers were found");
    return;
  }

  while (peer != NULL) {
    oc_string_t ep_str;
    if (oc_endpoint_to_string(&peer->endpoint, &ep_str) == 0) {
      bool is_server = peer->role == MBEDTLS_SSL_IS_SERVER;
      DPS_DBG("\tendpoint: %s, server: %d", oc_string(ep_str),
              is_server ? 1 : 0);
      oc_free_string(&ep_str);
    }
    peer = peer->next;
  }
  // GCOVR_EXCL_STOP
}

#endif /* DPS_DBG_IS_ENABLED */

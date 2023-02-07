/****************************************************************************
 *
 * Copyright (c) 2016-2020 Intel Corporation
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

#ifdef OC_SECURITY

#include "oc_api.h"
#include "oc_base64.h"
#include "oc_certs_internal.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm.h"
#include "oc_keypair.h"
#include "oc_pstat.h"
#include "oc_roles_internal.h"
#include "oc_store.h"
#include "oc_tls.h"
#include "port/oc_assert.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include <stdlib.h>

#ifdef OC_OSCORE
#include "oc_oscore_context.h"
#include <ctype.h>
#endif /* OC_OSCORE */
#ifdef OC_PKI
#include "security/oc_certs_internal.h"
#include <mbedtls/platform_util.h>
#endif /* OC_PKI */

OC_MEMB(creds, oc_sec_cred_t, OC_MAX_NUM_DEVICES *OC_MAX_NUM_SUBJECTS + 1);
#define OXM_JUST_WORKS "oic.sec.doxm.jw"
#define OXM_RANDOM_DEVICE_PIN "oic.sec.doxm.rdp"
#define OXM_MANUFACTURER_CERTIFICATE "oic.sec.doxm.mfgcert"

#ifdef OC_DYNAMIC_ALLOCATION
static oc_sec_creds_t *devices;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_creds_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_PKI
static const char *allowed_roles[] = { "oic.role.owner" };
static const int allowed_roles_num = sizeof(allowed_roles) / sizeof(char *);
#endif /* OC_PKI */

// https://openconnectivity.org/specs/OCF_Security_Specification_v2.2.5.pdf
// 13.3.3.1 Symmetric key formatting
#define SYMMETRIC_KEY_128BIT_LEN 16
#define SYMMETRIC_KEY_256BIT_LEN 32

static int
check_symmetric_key_length(int key_size)
{
  if (key_size != SYMMETRIC_KEY_128BIT_LEN &&
      key_size != SYMMETRIC_KEY_256BIT_LEN) {
    OC_ERR("oc_cred: invalid PSK length(%d)", key_size);
    return -1;
  }
  return 0;
}

oc_sec_creds_t *
oc_sec_get_creds(size_t device)
{
  return &devices[device];
}

void
oc_sec_cred_init(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  devices =
    (oc_sec_creds_t *)calloc(oc_core_get_num_devices(), sizeof(oc_sec_creds_t));
  if (!devices) {
    oc_abort("Insufficient memory");
  }
#endif /* OC_DYNAMIC_ALLOCATION */
  size_t i;
  for (i = 0; i < oc_core_get_num_devices(); i++) {
    OC_LIST_STRUCT_INIT(&devices[i], creds);
  }
}

oc_sec_cred_t *
oc_sec_get_cred_by_credid(int credid, size_t device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (cred->credid == credid) {
      return cred;
    }
    cred = cred->next;
  }
  return NULL;
}

static oc_sec_cred_t *
oc_sec_is_existing_cred(int credid, bool roles_resource, oc_tls_peer_t *client,
                        size_t device)
{
  oc_sec_cred_t *cred = NULL;
  (void)client;

  if (!roles_resource) {
    cred = (oc_sec_cred_t *)oc_list_head(devices[device].creds);
  }
#ifdef OC_PKI
  else {
    cred = oc_sec_get_roles(client);
  }
#endif /* OC_PKI */
  while (cred != NULL) {
    if (cred->credid == credid) {
      break;
    }
    cred = cred->next;
  }
  return cred;
}

#ifdef OC_PKI
static bool
oc_sec_role_cred_match_role(const oc_sec_cred_t *cred, const char *role,
                            size_t role_len, bool skipIfEmpty)
{
  const char *cred_role = oc_string(cred->role.role);
  if (role == NULL) {
    // skip check or both are NULL
    return skipIfEmpty || cred_role == NULL;
  }
  return role_len == oc_string_len(cred->role.role) && cred_role != NULL &&
         memcmp(role, cred_role, role_len) == 0;
}

#ifdef OC_CLIENT
static bool
oc_sec_role_cred_match_authority(const oc_sec_cred_t *cred,
                                 const char *authority, size_t authority_len,
                                 bool skipIfEmpty)
{
  const char *cred_authority = oc_string(cred->role.authority);
  if (authority == NULL) {
    // skip check or both are NULL
    return skipIfEmpty || oc_string(cred->role.authority) == NULL;
  }
  return authority_len == oc_string_len(cred->role.authority) &&
         cred_authority != NULL &&
         memcmp(authority, cred_authority, authority_len) == 0;
}

static bool
oc_sec_role_cred_match_tag(const oc_sec_cred_t *cred, const char *tag,
                           size_t tag_len, bool skipIfEmpty)
{
  const char *cred_tag = oc_string(cred->tag);
  if (tag == NULL) {
    // skip check or both are NULL
    return skipIfEmpty || cred_tag == NULL;
  }

  return tag_len == oc_string_len(cred->tag) && cred_tag != NULL &&
         memcmp(tag, cred_tag, tag_len) == 0;
}

oc_sec_cred_t *
oc_sec_find_role_cred(oc_sec_cred_t *start, const char *role,
                      const char *authority, const char *tag)
{
  oc_sec_cred_t *creds = start;
  if (!creds) {
    /* Checking only the 0th logical device for Clients */
    creds = (oc_sec_cred_t *)oc_list_head(devices[0].creds);
  }
  size_t role_len = strlen(role);
  size_t authority_len = authority != NULL ? strlen(authority) : 0;
  size_t tag_len = tag != NULL ? strlen(tag) : 0;
  while (creds) {
    if (creds->credtype == OC_CREDTYPE_CERT &&
        creds->credusage == OC_CREDUSAGE_ROLE_CERT) {
      if (oc_sec_role_cred_match_role(creds, role, role_len, false) &&
          oc_sec_role_cred_match_authority(creds, authority, authority_len,
                                           true) &&
          oc_sec_role_cred_match_tag(creds, tag, tag_len, true)) {
        return creds;
      }
    }
    creds = creds->next;
  }
  return NULL;
}
#endif /* OC_PKI */
#endif /* OC_CLIENT */

static int
get_new_credid(bool roles_resource, oc_tls_peer_t *client, size_t device)
{
  int credid;
  do {
    credid = oc_random_value() >> 1;
  } while (oc_sec_is_existing_cred(credid, roles_resource, client, device));
  return credid;
}

static oc_sec_cred_t *
oc_sec_remove_cred_from_device(oc_sec_cred_t *cred, size_t device)
{
  return oc_list_remove2(devices[device].creds, cred);
}

static oc_sec_cred_t *
oc_sec_remove_cred_from_device_by_credid(int credid, size_t device)
{
  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(credid, device);
  if (cred) {
    oc_sec_remove_cred_from_device(cred, device);
  }
  return cred;
}

static void
oc_sec_free_cred(oc_sec_cred_t *cred)
{
  if (oc_string_len(cred->role.role) > 0) {
#if defined(OC_PKI) && defined(OC_CLIENT)
    oc_sec_remove_role_cred(oc_string(cred->role.role),
                            oc_string(cred->role.authority));
#endif /* OC_PKI && OC_CLIENT */
  }
  oc_free_string(&cred->role.role);
  oc_free_string(&cred->role.authority);
  oc_free_string(&cred->privatedata.data);
#ifdef OC_OSCORE
  if (cred->oscore_ctx) {
    oc_oscore_free_context(cred->oscore_ctx);
  }
#endif /* OC_OSCORE */
#ifdef OC_PKI
  oc_free_string(&cred->publicdata.data);

  if (cred->credtype == OC_CREDTYPE_CERT) {
    if (cred->credusage != OC_CREDUSAGE_TRUSTCA &&
        cred->credusage != OC_CREDUSAGE_MFG_TRUSTCA) {
      if (!oc_tls_remove_identity_cert(cred)) {
        OC_ERR(
          "oc_cred: failed to remove identity certificate for credential(%d)",
          cred->credid);
      }
    } else {
      if (!oc_tls_remove_trust_anchor(cred)) {
        OC_ERR("oc_cred: failed to remove trust anchor for credential(%d)",
               cred->credid);
      }
    }
  }
#endif /* OC_PKI */
  oc_free_string(&cred->tag);
  oc_memb_free(&creds, cred);
}

void
oc_sec_remove_cred(oc_sec_cred_t *cred, size_t device)
{
  oc_sec_remove_cred_from_device(cred, device);
  oc_sec_free_cred(cred);
}

bool
oc_sec_remove_cred_by_credid(int credid, size_t device)
{
  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(credid, device);
  if (cred != NULL) {
    oc_sec_remove_cred(cred, device);
    return true;
  }
  return false;
}

void
oc_sec_cred_clear(size_t device, oc_sec_cred_filter_t filter, void *user_data)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    oc_sec_cred_t *next = cred->next;
    if (filter == NULL || filter(cred, user_data)) {
      oc_sec_remove_cred(cred, device);
    }
    cred = next;
  }
}

void
oc_sec_cred_default(size_t device)
{
  oc_sec_cred_clear(device, NULL, NULL);
  memset(devices[device].rowneruuid.id, 0, OC_UUID_ID_SIZE);
  oc_sec_dump_cred(device);
}

void
oc_sec_cred_free(void)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_cred_clear(device, NULL, NULL);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (devices) {
    free(devices);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

oc_sec_cred_t *
oc_sec_find_creds_for_subject(oc_sec_cred_t *start,
                              const oc_uuid_t *subjectuuid, size_t device)
{
  oc_sec_cred_t *cred = start;
  if (!cred) {
    cred = oc_list_head(devices[device].creds);
  }
  while (cred != NULL) {
    if (oc_uuid_is_equal(cred->subjectuuid, *subjectuuid)) {
      return cred;
    }
    cred = cred->next;
  }
  return NULL;
}

oc_sec_cred_t *
oc_sec_find_cred(oc_sec_cred_t *start, const oc_uuid_t *subjectuuid,
                 oc_sec_credtype_t credtype, oc_sec_credusage_t credusage,
                 size_t device)
{
  (void)credusage;

  oc_sec_cred_t *cred = start;
  if (!cred) {
    cred = oc_list_head(devices[device].creds);
  }
  while (cred != NULL) {
    if (cred->credtype == credtype &&
#ifdef OC_PKI
        cred->credusage == credusage &&
#endif /* OC_PKI */
        oc_uuid_is_equal(cred->subjectuuid, *subjectuuid)) {
      return cred;
    }
    cred = cred->next;
  }
  return NULL;
}

oc_sec_cred_t *
oc_sec_allocate_cred(const oc_uuid_t *subjectuuid, oc_sec_credtype_t credtype,
                     oc_sec_credusage_t credusage, size_t device)
{
  (void)credusage;

  oc_sec_cred_t *cred = oc_memb_alloc(&creds);
  if (cred == NULL) {
    OC_WRN("insufficient memory to add new credential");
    return NULL;
  }
  cred->credtype = credtype;
#ifdef OC_PKI
  cred->credusage = credusage;
#endif /* OC_PKI */
  memcpy(cred->subjectuuid.id, subjectuuid->id, OC_UUID_ID_SIZE);
  oc_list_add(devices[device].creds, cred);
  return cred;
}

#ifdef OC_PKI
static int
check_role_assertion(oc_sec_cred_t *cred)
{
  if (oc_string_len(cred->role.role) >= strlen("oic.role.") &&
      memcmp(oc_string(cred->role.role), "oic.role.", strlen("oic.role.")) ==
        0) {
    for (int i = 0; i < allowed_roles_num; i++) {
      if (oc_sec_role_cred_match_role(cred, allowed_roles[i],
                                      strlen(allowed_roles[i]), false)) {
        return 0;
      }
    }
    OC_ERR("oic.role.* roles assertion is prohibited");
    return -1;
  }
  return 0;
}

static bool
check_uuid_from_cert_raw(size_t publicdata_size, const uint8_t *publicdata,
                         const oc_uuid_t *uuid)
{
  if (!publicdata || !uuid) {
    return false;
  }

  char uuid_from_cert[OC_UUID_LEN];
  if (!oc_certs_parse_CN_for_UUID(publicdata, publicdata_size, uuid_from_cert,
                                  sizeof(uuid_from_cert))) {
    return false;
  }
  char uuid_str[OC_UUID_LEN];
  oc_uuid_to_str(uuid, uuid_str, OC_UUID_LEN);
  return memcmp(uuid_from_cert, uuid_str, OC_UUID_LEN) == 0;
}

static const oc_uuid_t *
get_device_uuid(size_t device)
{
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  return doxm ? &doxm->deviceuuid : NULL;
}
static bool
oc_sec_verify_role_cred(oc_tls_peer_t *client, oc_sec_credusage_t credusage,
                        size_t public_key_len, oc_string_t public_key,
                        size_t publicdata_size, const uint8_t *publicdata)
{
  if (credusage != OC_CREDUSAGE_ROLE_CERT) {
    return false;
  }
  if (!client) {
    return false;
  }
  if (client->public_key.size > 0 &&
      memcmp(oc_cast(public_key, uint8_t) + public_key.size - public_key_len,
             oc_cast(client->public_key, uint8_t) + client->public_key.size -
               public_key_len,
             public_key_len) != 0) {
    return false;
  }
  return check_uuid_from_cert_raw(publicdata_size + 1, publicdata,
                                  &client->uuid);
}

#endif /* OC_PKI */

static bool
oc_sec_is_equal_cred_data(oc_cred_data_t creddata, const uint8_t *data,
                          size_t data_size)
{
  return (oc_string_len(creddata.data) == data_size) &&
         (data == NULL ||
          (memcmp(oc_string(creddata.data), data, data_size) == 0));
}

static bool
oc_sec_is_equal_cred_tag(oc_string_t credtag, const char *tag)
{
  size_t credtag_size = credtag.size;
  size_t tag_size = tag != NULL ? strlen(tag) + 1 : 0;
  return (credtag_size == tag_size) &&
         ((tag == NULL) ||
          (memcmp(oc_string(credtag), tag, credtag_size) == 0));
}

static bool
oc_sec_cred_set_subject(oc_sec_credusage_t credusage, const char *subjectuuid,
                        oc_uuid_t *subject)
{
  if (!subjectuuid) {
    if (credusage != OC_CREDUSAGE_ROLE_CERT) {
      return false;
    } else {
      subject->id[0] = '*';
    }
  } else {
    if (subjectuuid[0] == '*') {
      subject->id[0] = '*';
    } else {
      oc_str_to_uuid(subjectuuid, subject);
    }
  }
  return true;
}

static bool
oc_sec_is_duplicate_cred(oc_sec_cred_t *cred, oc_sec_credtype_t credtype,
                         oc_sec_credusage_t credusage, oc_uuid_t subject,
                         size_t privatedata_size, const uint8_t *privatedata,
                         size_t publicdata_size, const uint8_t *publicdata,
                         const char *tag)
{
  if ((cred->credtype != credtype) ||
      !oc_uuid_is_equal(cred->subjectuuid, subject) ||
      !oc_sec_is_equal_cred_data(cred->privatedata, privatedata,
                                 privatedata_size) ||
      !oc_sec_is_equal_cred_tag(cred->tag, tag)) {
    return false;
  }

#ifdef OC_PKI
  if ((cred->credusage != credusage) ||
      !oc_sec_is_equal_cred_data(cred->publicdata, publicdata,
                                 publicdata_size)) {
    return false;
  }
#else  /* !OC_PKI */
  (void)credusage;
  (void)publicdata;
  (void)publicdata_size;
#endif /* OC_PKI */
  return true;
}

#ifdef OC_PKI
static oc_ecdsa_keypair_t *
oc_sec_get_valid_ecdsa_keypair(size_t device, size_t public_key_len,
                               oc_string_t public_key, size_t publicdata_size,
                               const uint8_t *publicdata)
{
  oc_ecdsa_keypair_t *kp = NULL;
  kp = oc_sec_get_ecdsa_keypair(device);
  if (!kp) {
    return NULL;
  }
  if (memcmp(kp->public_key,
             oc_cast(public_key, uint8_t) + public_key.size - public_key_len,
             public_key_len) != 0) {
    return NULL;
  }
  if (!check_uuid_from_cert_raw(publicdata_size + 1, publicdata,
                                get_device_uuid(device))) {
    return NULL;
  }
  return kp;
}
#endif /* OC_PKI */

int
oc_sec_add_new_cred(size_t device, bool roles_resource, oc_tls_peer_t *client,
                    int credid, oc_sec_credtype_t credtype,
                    oc_sec_credusage_t credusage, const char *subjectuuid,
                    oc_sec_encoding_t privatedata_encoding,
                    size_t privatedata_size, const uint8_t *privatedata,
                    oc_sec_encoding_t publicdata_encoding,
                    size_t publicdata_size, const uint8_t *publicdata,
                    const char *role, const char *authority, const char *tag,
                    oc_sec_add_new_cred_data_t *new_cred_data)
{
  (void)publicdata_encoding;
  (void)publicdata;
  (void)publicdata_size;
#ifdef OC_PKI
  oc_string_t public_key;
  memset(&public_key, 0, sizeof(oc_string_t));
  int public_key_len = 0;
  if (credtype == OC_CREDTYPE_CERT &&
      (public_key_len = oc_certs_parse_public_key_to_oc_string(
         publicdata, publicdata_size + 1, &public_key)) < 0) {
    goto add_new_cred_error;
  }

  if (roles_resource &&
      !oc_sec_verify_role_cred(client, credusage, (size_t)public_key_len,
                               public_key, publicdata_size, publicdata)) {
    goto add_new_cred_error;
  }
#endif /* OC_PKI */

  oc_uuid_t subject;
  memset(&subject, 0, sizeof(oc_uuid_t));
  oc_sec_cred_set_subject(credusage, subjectuuid, &subject);

#ifdef OC_PKI
  oc_ecdsa_keypair_t *kp = NULL;
  if (credusage == OC_CREDUSAGE_IDENTITY_CERT && privatedata_size == 0) {
    kp = oc_sec_get_valid_ecdsa_keypair(
      device, (size_t)public_key_len, public_key, publicdata_size, publicdata);
    if (!kp) {
      goto add_new_cred_error;
    }
  }
#endif /* OC_PKI */

  oc_sec_cred_t *existing =
    oc_sec_is_existing_cred(credid, roles_resource, client, device);
  if (existing) {
    if (!roles_resource) {
      /* skip duplicate cred, if one exists.  */
      if (oc_sec_is_duplicate_cred(existing, credtype, credusage, subject,
                                   privatedata_size, privatedata,
                                   publicdata_size, publicdata, tag)) {
#ifdef OC_PKI
        oc_free_string(&public_key);
#endif /* OC_PKI */
        return credid;
      } else {
        if (new_cred_data) {
          new_cred_data->replaced_cred =
            oc_sec_remove_cred_from_device_by_credid(credid, device);
        } else {
          oc_sec_remove_cred_by_credid(credid, device);
        }
      }
    }
#ifdef OC_PKI
    else {
      credid = -1;
    }
#endif /* OC_PKI */
  }

  oc_sec_cred_t *cred = NULL;
  if (!roles_resource) {
    do {
      cred = oc_sec_find_creds_for_subject(cred, &subject, device);

      if (cred) {
        if (cred->credtype == credtype) {
          /* Exit this block if we're modifying an existing cred entry */
          if (cred->credid == credid) {
            if (new_cred_data) {
              oc_assert(new_cred_data->replaced_cred == NULL);
              new_cred_data->replaced_cred =
                oc_sec_remove_cred_from_device(cred, device);
            } else {
              oc_sec_remove_cred(cred, device);
            }
            break;
          }
#ifdef OC_PKI
          if (credtype == OC_CREDTYPE_CERT && cred->credusage == credusage) {
            /* Trying to add a duplicate certificate chain, so ignore */
            if (publicdata_size > 0 &&
                oc_sec_is_equal_cred_data(cred->publicdata, publicdata,
                                          publicdata_size) &&
                oc_sec_is_equal_cred_tag(cred->tag, tag)) {
              oc_free_string(&public_key);
              return cred->credid;
            }
          }
#endif /* OC_PKI */
        }
        cred = cred->next;
      }
    } while (cred);
  }
#ifdef OC_PKI
  else {
    oc_sec_cred_t *roles = oc_sec_get_roles(client);
    while (roles) {
      /* Trying to add a duplicate role credential, so ignore */
      if (oc_sec_is_equal_cred_data(roles->publicdata, publicdata,
                                    publicdata_size) &&
          oc_sec_is_equal_cred_tag(roles->tag, tag)) {
        oc_free_string(&public_key);
        return roles->credid;
      }
      roles = roles->next;
    }
  }
#endif /* OC_PKI */

  cred = NULL;
#ifdef OC_PKI
  if (roles_resource && credusage == OC_CREDUSAGE_ROLE_CERT) {
    cred = oc_sec_allocate_role(client, device);
  } else if (!roles_resource)
#endif /* OC_PKI */
  {
    cred = oc_sec_allocate_cred(&subject, credtype, credusage, device);
  }
  if (!cred) {
    goto add_new_cred_error;
  }

#ifdef OC_PKI
  if (credusage == OC_CREDUSAGE_ROLE_CERT) {
    if (oc_certs_parse_role_certificate(publicdata, publicdata_size + 1, cred,
                                        roles_resource) < 0) {
      if (roles_resource) {
        oc_sec_free_role(cred, client);
      } else {
        oc_sec_remove_cred(cred, device);
      }
      goto add_new_cred_error;
    }

    if (roles_resource && check_role_assertion(cred) < 0) {
      oc_sec_free_role(cred, client);
      goto add_new_cred_error;
    }
  }
#endif /* OC_PKI */

  /* if a credid wasn't provided in the request, pick a suitable one */
  if (credid == -1) {
    credid = get_new_credid(roles_resource, client, device);
  }
  if (new_cred_data) {
    new_cred_data->created = true;
  }

  /* credid */
  cred->credid = credid;
  /* credtype */
  cred->credtype = credtype;

  /* privatedata */
  if (privatedata && privatedata_size > 0) {
    if (credtype == OC_CREDTYPE_PSK &&
        privatedata_encoding == OC_ENCODING_BASE64) {
      if (privatedata_size > 64) {
        oc_sec_remove_cred(cred, device);
        goto add_new_cred_error;
      }
      uint8_t key[64];
      memcpy(key, privatedata, privatedata_size);
      int key_size = oc_base64_decode(key, privatedata_size);
      if (check_symmetric_key_length(key_size)) {
        oc_sec_remove_cred(cred, device);
        goto add_new_cred_error;
      }
      oc_new_string(&cred->privatedata.data, (const char *)key, key_size);
      privatedata_encoding = OC_ENCODING_RAW;
    } else {
      if (credtype == OC_CREDTYPE_PSK &&
          check_symmetric_key_length(privatedata_size)) {
        oc_sec_remove_cred(cred, device);
        goto add_new_cred_error;
      }
      oc_new_string(&cred->privatedata.data, (const char *)privatedata,
                    privatedata_size);
    }
    cred->privatedata.encoding = privatedata_encoding;
  }
#ifdef OC_PKI
  else if (kp) {
    oc_new_string(&cred->privatedata.data, (const char *)kp->private_key,
                  kp->private_key_size);
    cred->privatedata.encoding = OC_ENCODING_RAW;
  }
#endif /* OC_PKI */

  /* roleid */
  if (!roles_resource && role) {
    oc_new_string(&cred->role.role, role, strlen(role));
    if (authority) {
      oc_new_string(&cred->role.authority, authority, strlen(authority));
    }
  }

#ifdef OC_PKI
  /* publicdata */
  if (publicdata && publicdata_size > 0) {
    cred->publicdata.encoding = publicdata_encoding;
    oc_new_string(&cred->publicdata.data, (const char *)publicdata,
                  publicdata_size);
  }

  /* credusage */
  cred->credusage = credusage;
#endif /* OC_PKI */

  /* tag */
  if (tag) {
    oc_new_string(&cred->tag, tag, strlen(tag));
  }

#ifdef OC_PKI
  if (cred->credtype == OC_CREDTYPE_CERT) {
    if (cred->credusage == OC_CREDUSAGE_MFG_CERT ||
        cred->credusage == OC_CREDUSAGE_IDENTITY_CERT) {
      oc_tls_resolve_new_identity_certs();
    }
    if (cred->credusage == OC_CREDUSAGE_MFG_TRUSTCA ||
        cred->credusage == OC_CREDUSAGE_TRUSTCA) {
      oc_tls_resolve_new_trust_anchors();
    }
#if defined(OC_PKI) && defined(OC_CLIENT)
    if (!roles_resource && credusage == OC_CREDUSAGE_ROLE_CERT &&
        oc_string_len(cred->role.role) > 0) {
      oc_sec_add_role_cred(oc_string(cred->role.role),
                           oc_string(cred->role.authority));
    }
#endif /* OC_PKI && OC_CLIENT */
  }
#endif /* OC_PKI */
#ifdef OC_PKI
  oc_free_string(&public_key);
#endif /* OC_PKI */
  return cred->credid;
add_new_cred_error:
#ifdef OC_PKI
  oc_free_string(&public_key);
#endif /* OC_PKI */
  if (new_cred_data && new_cred_data->replaced_cred) {
    oc_sec_free_cred(new_cred_data->replaced_cred);
    new_cred_data->replaced_cred = NULL;
  }
  return -1;
}

const char *
oc_cred_credtype_string(oc_sec_credtype_t credtype)
{
  if (credtype == 1) {
    return "Symmetric pair-wise key";
  } else if (credtype == 8) {
    return "Asymmetric signing key with certificate";
  }
  return "Unknown";
}

#ifdef OC_PKI
const char *
oc_cred_read_credusage(oc_sec_credusage_t credusage)
{
  switch (credusage) {
  case OC_CREDUSAGE_TRUSTCA:
    return "oic.sec.cred.trustca";
  case OC_CREDUSAGE_IDENTITY_CERT:
    return "oic.sec.cred.cert";
  case OC_CREDUSAGE_ROLE_CERT:
    return "oic.sec.cred.rolecert";
  case OC_CREDUSAGE_MFG_TRUSTCA:
    return "oic.sec.cred.mfgtrustca";
  case OC_CREDUSAGE_MFG_CERT:
    return "oic.sec.cred.mfgcert";
  default:
    break;
  }
  return "None";
}
#endif /* OC_PKI */

const char *
oc_cred_read_encoding(oc_sec_encoding_t encoding)
{
  switch (encoding) {
  case OC_ENCODING_BASE64:
    return "oic.sec.encoding.base64";
  case OC_ENCODING_RAW:
    return "oic.sec.encoding.raw";
#ifdef OC_PKI
  case OC_ENCODING_PEM:
    return "oic.sec.encoding.pem";
#endif /* OC_PKI */
  case OC_ENCODING_HANDLE:
    return "oic.sec.encoding.handle";
  default:
    break;
  }
  return "Unknown";
}

#ifdef OC_PKI
static void
oc_sec_encode_roles(oc_tls_peer_t *client, size_t device,
                    oc_interface_mask_t iface_mask)
{
  oc_sec_cred_t *cr = oc_sec_get_roles(client);
  oc_rep_start_root_object();
  if (iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_ROLES, device));
  }
  oc_rep_set_array(root, roles);
  while (cr != NULL) {
    oc_rep_object_array_start_item(roles);
    /* credid */
    oc_rep_set_int(roles, credid, cr->credid);
    /* credtype */
    oc_rep_set_int(roles, credtype, cr->credtype);
    /* credusage */
    const char *credusage_string = oc_cred_read_credusage(cr->credusage);
    if (strlen(credusage_string) > 4) {
      oc_rep_set_text_string(roles, credusage, credusage_string);
    }
    /* publicdata */
    if (oc_string_len(cr->publicdata.data) > 0) {
      oc_rep_set_object(roles, publicdata);
      if (cr->publicdata.encoding == OC_ENCODING_PEM) {
        oc_rep_set_text_string(publicdata, data,
                               oc_string(cr->publicdata.data));
      } else {
        oc_rep_set_byte_string(publicdata, data,
                               oc_cast(cr->publicdata.data, const uint8_t),
                               oc_string_len(cr->publicdata.data));
      }
      const char *encoding_string =
        oc_cred_read_encoding(cr->publicdata.encoding);
      if (strlen(encoding_string) > 7) {
        oc_rep_set_text_string(publicdata, encoding, encoding_string);
      }
      oc_rep_close_object(roles, publicdata);
    }
    oc_rep_object_array_end_item(roles);
    cr = cr->next;
  }
  oc_rep_close_array(root, roles);
  oc_rep_end_root_object();
}
#endif /* OC_PKI */

void
oc_sec_encode_cred(bool persist, size_t device, oc_interface_mask_t iface_mask,
                   bool to_storage)
{
  oc_sec_cred_t *cr = oc_list_head(devices[device].creds);
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  if (to_storage || iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_CRED, device));
  }
  oc_rep_set_array(root, creds);
  while (cr != NULL) {
    oc_rep_object_array_start_item(creds);
    /* credid */
    oc_rep_set_int(creds, credid, cr->credid);
    /* credtype */
    oc_rep_set_int(creds, credtype, cr->credtype);
    /* subjectuuid */
    if (cr->subjectuuid.id[0] == '*') {
      oc_rep_set_text_string(creds, subjectuuid, "*");
    } else {
      oc_uuid_to_str(&cr->subjectuuid, uuid, OC_UUID_LEN);
      oc_rep_set_text_string(creds, subjectuuid, uuid);
    }
    /* roleid */
    if ((persist || cr->credtype == OC_CREDTYPE_PSK) &&
        oc_string_len(cr->role.role) > 0) {
      oc_rep_set_object(creds, roleid);
      oc_rep_set_text_string(roleid, role, oc_string(cr->role.role));
      if (oc_string_len(cr->role.authority) > 0) {
        oc_rep_set_text_string(roleid, authority,
                               oc_string(cr->role.authority));
      }
      oc_rep_close_object(creds, roleid);
    }
    /* privatedata */
    oc_rep_set_object(creds, privatedata);
    if (persist) {
      if (cr->privatedata.encoding == OC_ENCODING_RAW) {
        oc_rep_set_byte_string(privatedata, data,
                               oc_cast(cr->privatedata.data, const uint8_t),
                               oc_string_len(cr->privatedata.data));
      } else {
        oc_rep_set_text_string(privatedata, data,
                               oc_string(cr->privatedata.data));
      }
    } else {
      if (cr->privatedata.encoding == OC_ENCODING_RAW) {
        oc_rep_set_byte_string(privatedata, data,
                               oc_cast(cr->privatedata.data, const uint8_t), 0);
      } else {
        oc_rep_set_text_string(privatedata, data, "");
      }
    }
    const char *encoding_string =
      oc_cred_read_encoding(cr->privatedata.encoding);
    if (strlen(encoding_string) > 7) {
      oc_rep_set_text_string(privatedata, encoding, encoding_string);
    } else {
      oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
    }
    oc_rep_close_object(creds, privatedata);
#ifdef OC_OSCORE
    /* oscore */
    if (cr->oscore_ctx) {
      oc_oscore_context_t *oscore_ctx = (oc_oscore_context_t *)cr->oscore_ctx;
      char hex_str[OSCORE_CTXID_LEN * 2 + 1];
      size_t hex_str_len;
      oc_rep_set_object(creds, oscore);
      if (cr->credtype != OC_CREDTYPE_OSCORE_MCAST_SERVER) {
        hex_str_len = OSCORE_CTXID_LEN * 2 + 1;
        oc_conv_byte_array_to_hex_string(
          oscore_ctx->sendid, oscore_ctx->sendid_len, hex_str, &hex_str_len);
        oc_rep_set_text_string(oscore, senderid, hex_str);
      }
      if (cr->credtype != OC_CREDTYPE_OSCORE_MCAST_CLIENT) {
        hex_str_len = OSCORE_CTXID_LEN * 2 + 1;
        oc_conv_byte_array_to_hex_string(
          oscore_ctx->recvid, oscore_ctx->recvid_len, hex_str, &hex_str_len);
        oc_rep_set_text_string(oscore, recipientid, hex_str);
      }
      if (cr->credtype != OC_CREDTYPE_OSCORE) {
        oc_rep_set_text_string(oscore, desc, oc_string(oscore_ctx->desc));
      }
      if (cr->credtype != OC_CREDTYPE_OSCORE_MCAST_SERVER) {
        oc_rep_set_int(oscore, ssn, oscore_ctx->ssn);
      }
      oc_rep_close_object(creds, oscore);
    }
#endif /* OC_OSCORE */
#ifdef OC_PKI
    /* credusage */
    const char *credusage_string = oc_cred_read_credusage(cr->credusage);
    if (strlen(credusage_string) > 4) {
      oc_rep_set_text_string(creds, credusage, credusage_string);
    }
    /* publicdata */
    if (oc_string_len(cr->publicdata.data) > 0) {
      oc_rep_set_object(creds, publicdata);
      if (cr->publicdata.encoding == OC_ENCODING_PEM) {
        oc_rep_set_text_string(publicdata, data,
                               oc_string(cr->publicdata.data));
      } else {
        oc_rep_set_byte_string(publicdata, data,
                               oc_cast(cr->publicdata.data, const uint8_t),
                               oc_string_len(cr->publicdata.data));
      }
      const char *encoding_string =
        oc_cred_read_encoding(cr->publicdata.encoding);
      if (strlen(encoding_string) > 7) {
        oc_rep_set_text_string(publicdata, encoding, encoding_string);
      }
      oc_rep_close_object(creds, publicdata);
    }
    if (persist) {
      oc_rep_set_boolean(creds, owner_cred, cr->owner_cred);
      if ((oc_string(cr->tag) != NULL) && (oc_string_len(cr->tag) > 0)) {
        oc_rep_set_text_string(creds, tag, oc_string(cr->tag));
      }
    }
#endif /* OC_PKI */
    oc_rep_object_array_end_item(creds);
    cr = cr->next;
  }
  oc_rep_close_array(root, creds);
  /* rowneruuid */
  oc_uuid_to_str(&devices[device].rowneruuid, uuid, OC_UUID_LEN);
  oc_rep_set_text_string(root, rowneruuid, uuid);
  oc_rep_end_root_object();
}

#ifdef OC_PKI

oc_sec_credusage_t
oc_cred_parse_credusage(oc_string_t *credusage_string)
{
  oc_sec_credusage_t credusage = 0;
  if (oc_string_len(*credusage_string) == 20 &&
      memcmp("oic.sec.cred.trustca", oc_string(*credusage_string), 20) == 0) {
    credusage = OC_CREDUSAGE_TRUSTCA;
  } else if (oc_string_len(*credusage_string) == 17 &&
             memcmp("oic.sec.cred.cert", oc_string(*credusage_string), 17) ==
               0) {
    credusage = OC_CREDUSAGE_IDENTITY_CERT;
  } else if (oc_string_len(*credusage_string) == 21 &&
             memcmp("oic.sec.cred.rolecert", oc_string(*credusage_string),
                    21) == 0) {
    credusage = OC_CREDUSAGE_ROLE_CERT;
  } else if (oc_string_len(*credusage_string) == 23 &&
             memcmp("oic.sec.cred.mfgtrustca", oc_string(*credusage_string),
                    23) == 0) {
    credusage = OC_CREDUSAGE_MFG_TRUSTCA;
  } else if (oc_string_len(*credusage_string) == 20 &&
             memcmp("oic.sec.cred.mfgcert", oc_string(*credusage_string), 20) ==
               0) {
    credusage = OC_CREDUSAGE_MFG_CERT;
  }
  return credusage;
}

static bool
oc_cred_parse_certificate(const oc_sec_cred_t *cred, mbedtls_x509_crt *crt)
{
  OC_DBG("parsing credential certificate");
  const unsigned char *cert =
    (const unsigned char *)oc_string(cred->publicdata.data);
  if (cert == NULL) {
    OC_ERR("failed to get validity times from cert: %s", "empty public data");
    return false;
  }
  size_t cert_size = oc_string_len(cred->publicdata.data);
  if (cred->publicdata.encoding == OC_ENCODING_PEM) {
    ++cert_size;
  }

  mbedtls_x509_crt_init(crt);
  int ret = mbedtls_x509_crt_parse(crt, cert, cert_size);
  if (ret < 0) {
    OC_ERR("failed to parse certificate: %d", ret);
    return false;
  }
  return true;
}

typedef struct oc_cred_get_certificate_chain_result_t
{
  bool valid;
  bool must_deallocate;
  mbedtls_x509_crt *crt;
} oc_cred_get_certificate_chain_result_t;

static oc_cred_get_certificate_chain_result_t
oc_cred_get_certificate_chain(const oc_sec_cred_t *cred,
                              mbedtls_x509_crt *buffer)
{
  oc_cred_get_certificate_chain_result_t res = {
    .valid = false,
    .must_deallocate = false,
    .crt = NULL,
  };
  // check global lists to avoid parsing the certificates again
  if ((cred->credusage &
       (OC_CREDUSAGE_MFG_CERT | OC_CREDUSAGE_IDENTITY_CERT)) != 0) {
    OC_DBG(
      "identity certificate for credential(credid=%d) found in global list",
      cred->credid);
    res.crt = oc_tls_get_identity_cert_for_cred(cred);
  } else if ((cred->credusage &
              (OC_CREDUSAGE_TRUSTCA | OC_CREDUSAGE_MFG_TRUSTCA)) != 0) {
    OC_DBG("trust anchor for credential(credid=%d) found in global list",
           cred->credid);
    res.crt = oc_tls_get_trust_anchor_for_cred(cred);
  }

  if (res.crt == NULL) {
    oc_assert(buffer != NULL);
    if (!oc_cred_parse_certificate(cred, buffer)) {
      return res;
    }
    res.crt = buffer;
    res.must_deallocate = true;
  }
  res.valid = true;
  return res;
}

int
oc_cred_verify_certificate_chain(const oc_sec_cred_t *cred,
                                 oc_verify_sec_certs_data_fn_t verify_cert,
                                 void *user_data)
{
  oc_assert(cred != NULL);
  oc_assert(verify_cert != NULL);

  mbedtls_x509_crt crt;
  oc_cred_get_certificate_chain_result_t res =
    oc_cred_get_certificate_chain(cred, &crt);
  if (!res.valid) {
    return -1;
  }

  int result = 0;
  bool is_ca =
    (cred->credusage & (OC_CREDUSAGE_TRUSTCA | OC_CREDUSAGE_MFG_TRUSTCA)) != 0;
  // - Identity certificates: each certificate chain is stored in a different
  // container, so to get all data the whole container must be iterated
  // - CAs: all CAs are linked in a single container, so we just
  // take the single element and don't iterate further
  for (const mbedtls_x509_crt *crt_ptr = res.crt; crt_ptr != NULL;
       crt_ptr = crt_ptr->next) {

    oc_sec_certs_data_t data = {
      .valid_from = oc_certs_time_to_unix_timestamp(crt_ptr->valid_from),
      .valid_to = oc_certs_time_to_unix_timestamp(crt_ptr->valid_to),
    };

    if (!verify_cert(&data, user_data)) {
      result = 1;
      goto finish;
    }

    if (is_ca) {
      break;
    }
  }

finish:
  if (res.must_deallocate) {
    mbedtls_x509_crt_free(res.crt);
  }
  return result;
}

#endif /* OC_PKI */

oc_sec_encoding_t
oc_cred_parse_encoding(oc_string_t *encoding_string)
{
  oc_sec_encoding_t encoding = 0;
  if (oc_string_len(*encoding_string) == 23 &&
      memcmp("oic.sec.encoding.base64", oc_string(*encoding_string), 23) == 0) {
    encoding = OC_ENCODING_BASE64;
  } else if (oc_string_len(*encoding_string) == 20 &&
             memcmp("oic.sec.encoding.raw", oc_string(*encoding_string), 20) ==
               0) {
    encoding = OC_ENCODING_RAW;
  } else if (oc_string_len(*encoding_string) == 23 &&
             memcmp("oic.sec.encoding.handle", oc_string(*encoding_string),
                    23) == 0) {
    encoding = OC_ENCODING_HANDLE;
  }
#ifdef OC_PKI
  else if (oc_string_len(*encoding_string) == 20 &&
           memcmp("oic.sec.encoding.pem", oc_string(*encoding_string), 20) ==
             0) {
    encoding = OC_ENCODING_PEM;
  }
#endif /* OC_PKI */
  return encoding;
}

#ifdef OC_OSCORE
static bool
is_valid_oscore_id(const char *id, size_t id_len)
{
  if (id_len != 14) {
    return false;
  }
  size_t i;
  for (i = 0; i < id_len; i++) {
    if (!isxdigit(id[i])) {
      return false;
    }
  }
  return true;
}
#endif /* OC_OSCORE */

static oc_event_callback_retval_t
dump_cred(void *data)
{
  size_t device = (size_t)data;
  oc_sec_dump_cred(device);
  return OC_EVENT_DONE;
}

bool
oc_sec_decode_cred(oc_rep_t *rep, oc_sec_cred_t **owner, bool from_storage,
                   bool roles_resource, oc_tls_peer_t *client, size_t device,
                   oc_sec_on_apply_cred_cb_t on_apply_cred_cb,
                   void *on_apply_cred_data)
{
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_rep_t *t = rep;
  size_t len = 0;
  bool got_oscore_ctx = false;

  if (!roles_resource) {
    while (t != NULL) {
      len = oc_string_len(t->name);
      switch (t->type) {
      case OC_REP_STRING:
        if (len == 10 && memcmp(oc_string(t->name), "rowneruuid", 10) == 0) {
          if (!from_storage && ps->s != OC_DOS_RFOTM &&
              ps->s != OC_DOS_SRESET) {
            OC_ERR("oc_cred: Can set rowneruuid only in RFOTM/SRESET");
            return false;
          }
        }
        break;
      case OC_REP_OBJECT_ARRAY: {
        if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_SRESET &&
            ps->s != OC_DOS_RFPRO) {
          OC_ERR("oc_cred: Can set cred only in RFOTM/SRESET/RFPRO");
          return false;
        }
      } break;
      default:
        break;
      }
      t = t->next;
    }
  }

  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    /* rowneruuid */
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string),
                       &devices[device].rowneruuid);
      }
      break;
    /* creds */
    case OC_REP_OBJECT_ARRAY: {
      if (len == 5 && (memcmp(oc_string(rep->name), "creds", 5) == 0 ||
                       memcmp(oc_string(rep->name), "roles", 5) == 0)) {
        oc_rep_t *creds_array = rep->value.object_array;
        /* array of oic.sec.cred */
        while (creds_array != NULL) {
          oc_rep_t *cred = creds_array->value.object;
          int credid = -1;
          oc_sec_credtype_t credtype = 0;
          char *role = NULL, *authority = NULL, *subjectuuid = NULL,
               *privatedata = NULL;
          oc_sec_encoding_t privatedatatype = 0;
          size_t privatedata_size = 0;
#ifdef OC_PKI
          oc_sec_credusage_t credusage = 0;
          char *publicdata = NULL;
          oc_sec_encoding_t publicdatatype = 0;
          size_t publicdata_size = 0;
#endif /* OC_PKI */
#ifdef OC_OSCORE
          const char *sid = NULL, *rid = NULL, *desc = NULL;
          uint64_t ssn = 0;
#endif /* OC_OSCORE */
          bool owner_cred = false;
          char *tag = NULL;
          bool non_empty = false;
          while (cred != NULL) {
            non_empty = true;
            len = oc_string_len(cred->name);
            switch (cred->type) {
            /* credid and credtype  */
            case OC_REP_INT:
              if (len == 6 && memcmp(oc_string(cred->name), "credid", 6) == 0) {
                credid = (int)cred->value.integer;
              } else if (len == 8 &&
                         memcmp(oc_string(cred->name), "credtype", 8) == 0) {
                credtype = cred->value.integer;
              }
              break;
            /* subjectuuid, credusage and tag */
            case OC_REP_STRING:
              if (len == 11 &&
                  memcmp(oc_string(cred->name), "subjectuuid", 11) == 0) {
                subjectuuid = oc_string(cred->value.string);
              }
#ifdef OC_PKI
              else if (len == 9 &&
                       memcmp(oc_string(cred->name), "credusage", 9) == 0) {
                credusage = oc_cred_parse_credusage(&cred->value.string);
              }
#endif /* OC_PKI */
              else if (len == 3 &&
                       memcmp(oc_string(cred->name), "tag", 3) == 0) {
                tag = oc_string(cred->value.string);
              }
              break;
            /* publicdata, privatedata, roleid, oscore */
            case OC_REP_OBJECT: {
              oc_rep_t *data = cred->value.object;
              if ((len == 11 &&
                   memcmp(oc_string(cred->name), "privatedata", 11) == 0)
#ifdef OC_PKI
                  || (len == 10 &&
                      memcmp(oc_string(cred->name), "publicdata", 10) == 0)
#endif /* OC_PKI */
              ) {
                size_t *size = 0;
                char **pubpriv = 0;
                oc_sec_encoding_t *encoding = 0;
                if (len == 11) {
                  size = &privatedata_size;
                  pubpriv = &privatedata;
                  encoding = &privatedatatype;
                }
#ifdef OC_PKI
                else {
                  size = &publicdata_size;
                  pubpriv = &publicdata;
                  encoding = &publicdatatype;
                }
#endif /* OC_PKI */
                while (data != NULL) {
                  switch (data->type) {
                  case OC_REP_STRING: {
                    if (oc_string_len(data->name) == 8 &&
                        memcmp("encoding", oc_string(data->name), 8) == 0) {
                      *encoding = oc_cred_parse_encoding(&data->value.string);
                      if (*encoding == 0) {
                        /* Unsupported encoding */
                        return false;
                      }
                    } else if (oc_string_len(data->name) == 4 &&
                               memcmp(oc_string(data->name), "data", 4) == 0) {
                      *pubpriv = oc_string(data->value.string);
                      *size = oc_string_len(data->value.string);
                      if (*size == 0) {
                        goto next_item;
                      }
                    }
                  } break;
                  case OC_REP_BYTE_STRING: {
                    if (oc_string_len(data->name) == 4 &&
                        memcmp(oc_string(data->name), "data", 4) == 0) {
                      *pubpriv = oc_string(data->value.string);
                      *size = oc_string_len(data->value.string);
                      if (*size == 0) {
                        goto next_item;
                      }
                    }
                  } break;
                  default:
                    break;
                  }
                next_item:
                  data = data->next;
                }
              } else if (len == 6 &&
                         memcmp(oc_string(cred->name), "roleid", 6) == 0) {
                while (data != NULL) {
                  len = oc_string_len(data->name);
                  if (len == 4 &&
                      memcmp(oc_string(data->name), "role", 4) == 0) {
                    role = oc_string(data->value.string);
                  } else if (len == 9 && memcmp(oc_string(data->name),
                                                "authority", 9) == 0) {
                    authority = oc_string(data->value.string);
                  }
                  data = data->next;
                }
              }
#ifdef OC_OSCORE
              /* oscore configuration */
              else if (len == 6 &&
                       memcmp(oc_string(cred->name), "oscore", 6) == 0) {
                got_oscore_ctx = true;
                /* senderid, recipientid, ssn, desc */
                while (data != NULL) {
                  len = oc_string_len(data->name);
                  if (data->type == OC_REP_STRING && len == 8 &&
                      memcmp(oc_string(data->name), "senderid", 8) == 0) {
                    if (!is_valid_oscore_id(
                          oc_string(data->value.string),
                          oc_string_len(data->value.string))) {
                      OC_ERR("oc_cred: invalid oscore/senderid");
                      return false;
                    }
                    sid = oc_string(data->value.string);
                  } else if (data->type == OC_REP_STRING && len == 11 &&
                             memcmp(oc_string(data->name), "recipientid", 11) ==
                               0) {
                    if (!is_valid_oscore_id(
                          oc_string(data->value.string),
                          oc_string_len(data->value.string))) {
                      OC_ERR("oc_cred: invalid oscore/senderid");
                      return false;
                    }
                    rid = oc_string(data->value.string);
                  } else if (data->type == OC_REP_STRING && len == 4 &&
                             memcmp(oc_string(data->name), "desc", 4) == 0) {
                    desc = oc_string(data->value.string);
                  } else if (data->type == OC_REP_INT && len == 3 &&
                             memcmp(oc_string(data->name), "ssn", 3) == 0) {
                    if (!from_storage) {
                      OC_ERR("oc_cred: oscore/ssn is R-only");
                      return false;
                    }
                    ssn = data->value.integer;
                  } else {
                    OC_ERR("oc_cred: unexpected property/value type in oscore "
                           "config");
                    return false;
                  }
                  data = data->next;
                }
              }
#endif /* OC_OSCORE */
            } break;
            case OC_REP_BOOL:
              if (len == 10 &&
                  memcmp(oc_string(cred->name), "owner_cred", 10) == 0) {
                owner_cred = cred->value.boolean;
              }
              break;
            default:
              break;
            }
            cred = cred->next;
          }

#ifdef OC_OSCORE
          if (credtype == OC_CREDTYPE_OSCORE &&
              (!sid || !rid || privatedata_size != OSCORE_MASTER_SECRET_LEN ||
               desc)) {
            OC_ERR("oc_cred: invalid oscore credential..rejecting");
            return false;
          }
          if (credtype == OC_CREDTYPE_OSCORE_MCAST_CLIENT &&
              (!sid || rid || privatedata_size != OSCORE_MASTER_SECRET_LEN)) {
            OC_ERR("oc_cred: invalid oscore credential..rejecting");
            return false;
          }
          if (credtype == OC_CREDTYPE_OSCORE_MCAST_SERVER &&
              (!rid || sid || privatedata_size != OSCORE_MASTER_SECRET_LEN)) {
            OC_ERR("oc_cred: invalid oscore credential..rejecting");
            return false;
          }
#endif /* OC_OSCORE */
          if (non_empty) {
            oc_sec_add_new_cred_data_t add_cred_data = { false, NULL };
            credid = oc_sec_add_new_cred(
              device, roles_resource, client, credid, credtype,
#ifdef OC_PKI
              credusage,
#else  /* OC_PKI */
              0,
#endif /* !OC_PKI */
              subjectuuid, privatedatatype, privatedata_size,
              (const uint8_t *)privatedata,
#ifdef OC_PKI
              publicdatatype, publicdata_size, (const uint8_t *)publicdata,
#else  /* OC_PKI */
              0, 0, NULL,
#endif /* !OC_PKI */
              role, authority, tag, &add_cred_data);

            if (credid == -1) {
              return false;
            }

            oc_sec_cred_t *cr = oc_sec_get_cred_by_credid(credid, device);
            if (cr) {
#ifdef OC_OSCORE
              if (sid || rid) {
                oc_oscore_context_t *oscore_ctx = oc_oscore_add_context(
                  device, sid, rid, ssn, desc, cr, from_storage);
                if (!oscore_ctx) {
                  if (add_cred_data.replaced_cred) {
                    oc_sec_free_cred(add_cred_data.replaced_cred);
                  }
                  return false;
                }

                cr->oscore_ctx = oscore_ctx;
              }
#endif /* OC_OSCORE */
              cr->owner_cred = owner_cred;
              /* Obtain a handle to the owner credential entry where that
               * applies
               */
              if (credtype == OC_CREDTYPE_PSK && privatedata_size == 0 &&
                  owner) {
                *owner = cr;
                (*owner)->owner_cred = true;
              }
              if (on_apply_cred_cb) {
                oc_sec_on_apply_cred_data_t cred_data = {
                  cr,
                  add_cred_data.replaced_cred,
                  add_cred_data.created,
                };
                on_apply_cred_cb(cred_data, on_apply_cred_data);
              }
            }
            if (add_cred_data.replaced_cred) {
              oc_sec_free_cred(add_cred_data.replaced_cred);
            }
          }
          creds_array = creds_array->next;
        }
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (from_storage && got_oscore_ctx) {
    oc_set_delayed_callback((void *)device, dump_cred, 0);
  }

  return true;
}

void
get_cred(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  bool roles_resource = false;
#ifdef OC_PKI
  oc_tls_peer_t *client = NULL;
  if (oc_string_len(request->resource->uri) == 14 &&
      memcmp(oc_string(request->resource->uri), "/oic/sec/roles", 14) == 0) {
    roles_resource = true;
  }
#endif /* OC_PKI */
  if (!roles_resource) {
    oc_sec_encode_cred(false, request->resource->device, iface_mask, false);
  }
#ifdef OC_PKI
  else {
    client = oc_tls_get_peer(request->origin);
    oc_sec_encode_roles(client, request->resource->device, iface_mask);
  }
#endif /* OC_PKI */
  oc_send_response(request, OC_STATUS_OK);
}

bool
oc_cred_remove_subject(const char *subjectuuid, size_t device)
{
  oc_uuid_t _subjectuuid;
  if (subjectuuid[0] == '*') {
    memset(&_subjectuuid, 0, sizeof(oc_uuid_t));
    _subjectuuid.id[0] = '*';
  } else {
    oc_str_to_uuid(subjectuuid, &_subjectuuid);
  }
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds), *next = 0;
  while (cred != NULL) {
    next = cred->next;
    if (memcmp(cred->subjectuuid.id, _subjectuuid.id, 16) == 0) {
      oc_sec_remove_cred(cred, device);
      return true;
    }
    cred = next;
  }
  return false;
}

void
delete_cred(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  bool success = false;
  bool roles_resource = false;

#ifdef OC_PKI
  oc_tls_peer_t *client = NULL;
  if (oc_string_len(request->resource->uri) == 14 &&
      memcmp(oc_string(request->resource->uri), "/oic/sec/roles", 14) == 0) {
    client = oc_tls_get_peer(request->origin);
    roles_resource = true;
  }
#endif /* OC_PKI */

  if (!roles_resource) {
    oc_sec_pstat_t *ps = oc_sec_get_pstat(request->resource->device);
    if (ps->s == OC_DOS_RFNOP) {
      OC_ERR("oc_cred: Cannot DELETE ACE in RFNOP");
      oc_send_response(request, OC_STATUS_FORBIDDEN);
      return;
    }
  }

  const char *query_param = 0;
  int ret = oc_get_query_value(request, "credid", &query_param);
  int credid = 0;
  if (ret != -1) {
    credid = (int)strtoul(query_param, NULL, 10);
    if (credid >= 0) {
      if (!roles_resource) {
        if (oc_sec_remove_cred_by_credid(credid, request->resource->device)) {
          success = true;
        }
      }
#ifdef OC_PKI
      else {
        if (oc_sec_free_role_by_credid(credid, client) >= 0) {
          success = true;
        }
      }
#endif /* OC_PKI */
    }
  } else {
    if (!roles_resource) {
      oc_sec_cred_clear(request->resource->device, NULL, NULL);
    }
#ifdef OC_PKI
    else {
      oc_sec_free_roles(client);
    }
#endif /* OC_PKI */
    success = true;
  }

  if (success) {
    oc_send_response(request, OC_STATUS_DELETED);
    oc_sec_dump_cred(request->resource->device);
  } else {
    oc_send_response(request, OC_STATUS_NOT_FOUND);
  }
}

int
oc_sec_apply_cred(oc_rep_t *rep, oc_resource_t *resource,
                  oc_endpoint_t *endpoint,
                  oc_sec_on_apply_cred_cb_t on_apply_cred_cb,
                  void *on_apply_cred_data)
{
  bool roles_resource = false;
  oc_tls_peer_t *client = NULL;

#ifdef OC_PKI
#define OIC_SEC_ROLES "/oic/sec/roles"
  if (oc_string_len(resource->uri) == strlen(OIC_SEC_ROLES) &&
      memcmp(oc_string(resource->uri), OIC_SEC_ROLES, strlen(OIC_SEC_ROLES)) ==
        0) {
    roles_resource = true;
    client = oc_tls_get_peer(endpoint);
  }
#endif /* OC_PKI */

  oc_sec_doxm_t *doxm = oc_sec_get_doxm(resource->device);
  oc_sec_cred_t *owner = NULL;
  bool success =
    oc_sec_decode_cred(rep, &owner, false, roles_resource, client,
                       resource->device, on_apply_cred_cb, on_apply_cred_data);
#define FIELD_ARRAY_SIZE(type, field)                                          \
  (sizeof(((type *)NULL)->field) / sizeof(((type *)NULL)->field[0]))

  const size_t uuid_size = FIELD_ARRAY_SIZE(oc_uuid_t, id);

#undef FIELD_ARRAY_SIZE
  if (!roles_resource && success && owner &&
      memcmp(owner->subjectuuid.id, devices[resource->device].rowneruuid.id,
             uuid_size) == 0) {
    char owneruuid[OC_UUID_LEN], deviceuuid[OC_UUID_LEN];
    oc_uuid_to_str(&doxm->deviceuuid, deviceuuid, sizeof(deviceuuid));
    oc_uuid_to_str(&owner->subjectuuid, owneruuid, sizeof(owneruuid));
    oc_alloc_string(&owner->privatedata.data, uuid_size + 1);
    if (doxm->oxmsel == OC_OXMTYPE_JW) {
      success = oc_sec_derive_owner_psk(
        endpoint, (const uint8_t *)OXM_JUST_WORKS, strlen(OXM_JUST_WORKS),
        doxm->deviceuuid.id, uuid_size, owner->subjectuuid.id, uuid_size,
        oc_cast(owner->privatedata.data, uint8_t), uuid_size);
    } else if (doxm->oxmsel == OC_OXMTYPE_RDP) {
      success = oc_sec_derive_owner_psk(
        endpoint, (const uint8_t *)OXM_RANDOM_DEVICE_PIN,
        strlen(OXM_RANDOM_DEVICE_PIN), doxm->deviceuuid.id, uuid_size,
        owner->subjectuuid.id, uuid_size,
        oc_cast(owner->privatedata.data, uint8_t), uuid_size);
    }
#ifdef OC_PKI
    else if (doxm->oxmsel == OC_OXMTYPE_MFG_CERT) {
      success = oc_sec_derive_owner_psk(
        endpoint, (const uint8_t *)OXM_MANUFACTURER_CERTIFICATE,
        strlen(OXM_MANUFACTURER_CERTIFICATE), doxm->deviceuuid.id, uuid_size,
        owner->subjectuuid.id, uuid_size,
        oc_cast(owner->privatedata.data, uint8_t), uuid_size);
    }
#endif /* OC_PKI */
    owner->privatedata.encoding = OC_ENCODING_RAW;
  }

  if (!success) {
    if (owner) {
      oc_sec_remove_cred_by_credid(owner->credid, resource->device);
    }
    return -1;
  }
  return 0;
}

void
post_cred(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  bool success = oc_sec_apply_cred(request->request_payload, request->resource,
                                   request->origin,
                                   /*on_apply_cred_cb*/ NULL,
                                   /*on_apply_cred_data*/ NULL) == 0;

  if (!success) {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  } else {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_cred(request->resource->device);
  }
}

#endif /* OC_SECURITY */

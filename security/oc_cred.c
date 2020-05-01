/*
// Copyright (c) 2016-2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifdef OC_SECURITY

#include "oc_api.h"
#include "oc_base64.h"
#include "oc_certs.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm.h"
#include "oc_keypair.h"
#include "oc_pstat.h"
#include "oc_roles.h"
#include "oc_store.h"
#include "oc_tls.h"
#include "port/oc_log.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#include <stdlib.h>

OC_MEMB(creds, oc_sec_cred_t, OC_MAX_NUM_DEVICES *OC_MAX_NUM_SUBJECTS + 1);
#define OXM_JUST_WORKS "oic.sec.doxm.jw"
#define OXM_RANDOM_DEVICE_PIN "oic.sec.doxm.rdp"
#define OXM_MANUFACTURER_CERTIFICATE "oic.sec.doxm.mfgcert"

#ifdef OC_DYNAMIC_ALLOCATION
#include "port/oc_assert.h"
static oc_sec_creds_t *devices;
#else  /* OC_DYNAMIC_ALLOCATION */
static oc_sec_creds_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_PKI
static const char *allowed_roles[] = { "oic.role.owner" };
static const int allowed_roles_num = sizeof(allowed_roles) / sizeof(char *);
#endif

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
    if (cred->credid == credid)
      return cred;
    cred = cred->next;
  }
  return NULL;
}

static oc_sec_cred_t *
is_existing_cred(int credid, bool roles_resource, oc_tls_peer_t *client,
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

#if defined(OC_CLIENT) && defined(OC_PKI)
oc_sec_cred_t *
oc_sec_find_role_cred(const char *role, const char *authority)
{
  /* Checking only the 0th logical device for Clients */
  oc_sec_cred_t *creds = (oc_sec_cred_t *)oc_list_head(devices[0].creds);
  size_t role_len = strlen(role);
  size_t authority_len = 0;
  if (authority) {
    authority_len = strlen(authority);
  }
  while (creds) {
    if (creds->credtype == OC_CREDTYPE_CERT &&
        creds->credusage == OC_CREDUSAGE_ROLE_CERT) {
      if ((role_len == oc_string_len(creds->role.role)) &&
          (memcmp(role, oc_string(creds->role.role), role_len) == 0)) {
        if (authority_len == 0) {
          return creds;
        } else if ((authority_len == oc_string_len(creds->role.authority)) &&
                   (memcmp(authority, oc_string(creds->role.authority),
                           authority_len) == 0)) {
          return creds;
        }
      }
    }
    creds = creds->next;
  }
  return NULL;
}
#endif /* OC_CLIENT && OC_PKI */

static int
get_new_credid(bool roles_resource, oc_tls_peer_t *client, size_t device)
{
  int credid;
  do {
    credid = oc_random_value() >> 1;
  } while (is_existing_cred(credid, roles_resource, client, device));
  return credid;
}

void
oc_sec_remove_cred(oc_sec_cred_t *cred, size_t device)
{
  oc_list_remove(devices[device].creds, cred);
  if (oc_string_len(cred->role.role) > 0) {
#if defined(OC_PKI) && defined(OC_CLIENT)
    oc_sec_remove_role_cred(oc_string(cred->role.role),
                            oc_string(cred->role.authority));
#endif /* OC_PKI && OC_CLIENT */
    oc_free_string(&cred->role.role);
    if (oc_string_len(cred->role.authority) > 0) {
      oc_free_string(&cred->role.authority);
    }
  }
  if (oc_string_len(cred->privatedata.data) > 0) {
    oc_free_string(&cred->privatedata.data);
  }
#ifdef OC_PKI
  if (oc_string_len(cred->publicdata.data) > 0) {
    oc_free_string(&cred->publicdata.data);
  }

  if (cred->credtype == OC_CREDTYPE_CERT) {
    if (cred->credusage != OC_CREDUSAGE_TRUSTCA &&
        cred->credusage != OC_CREDUSAGE_MFG_TRUSTCA) {
      oc_tls_remove_identity_cert(cred);
    } else {
      oc_tls_remove_trust_anchor(cred);
    }
  }
#endif /* OC_PKI */
  oc_memb_free(&creds, cred);
}

static bool
oc_sec_remove_cred_by_credid(int credid, size_t device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (cred->credid == credid) {
      oc_sec_remove_cred(cred, device);
      return true;
    }
    cred = cred->next;
  }
  return false;
}

static void
oc_sec_clear_creds(size_t device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds), *next;
  while (cred != NULL) {
    next = cred->next;
    oc_sec_remove_cred(cred, device);
    cred = next;
  }
}

void
oc_sec_cred_default(size_t device)
{
  oc_sec_clear_creds(device);
  memset(devices[device].rowneruuid.id, 0, 16);
  oc_sec_dump_cred(device);
}

void
oc_sec_cred_free(void)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_clear_creds(device);
  }
#ifdef OC_DYNAMIC_ALLOCATION
  if (devices) {
    free(devices);
  }
#endif /* OC_DYNAMIC_ALLOCATION */
}

oc_sec_cred_t *
oc_sec_find_creds_for_subject(oc_uuid_t *subjectuuid, oc_sec_cred_t *start,
                              size_t device)
{
  oc_sec_cred_t *cred = start;
  if (!cred) {
    cred = oc_list_head(devices[device].creds);
  }
  while (cred != NULL) {
    if (memcmp(cred->subjectuuid.id, subjectuuid->id, 16) == 0) {
      return cred;
    }
    cred = cred->next;
  }
  return NULL;
}

oc_sec_cred_t *
oc_sec_find_cred(oc_uuid_t *subjectuuid, oc_sec_credtype_t credtype,
                 oc_sec_credusage_t credusage, size_t device)
{
  (void)credusage;

  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (cred->credtype == credtype &&
#ifdef OC_PKI
        cred->credusage == credusage &&
#endif /* OC_PKI */
        memcmp(cred->subjectuuid.id, subjectuuid->id, 16) == 0) {
      return cred;
    }
    cred = cred->next;
  }
  return NULL;
}

oc_sec_cred_t *
oc_sec_allocate_cred(oc_uuid_t *subjectuuid, oc_sec_credtype_t credtype,
                     oc_sec_credusage_t credusage, size_t device)
{
  (void)credusage;

  oc_sec_cred_t *cred = oc_memb_alloc(&creds);
  if (cred != NULL) {
    cred->credtype = credtype;
#ifdef OC_PKI
    cred->credusage = credusage;
#endif /* OC_PKI */
    memcpy(cred->subjectuuid.id, subjectuuid->id, 16);
    oc_list_add(devices[device].creds, cred);
  } else {
    OC_WRN("insufficient memory to add new credential");
  }
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
      if (oc_string_len(cred->role.role) == strlen(allowed_roles[i]) &&
          memcmp(oc_string(cred->role.role), allowed_roles[i],
                 strlen(allowed_roles[i])) == 0) {
        return 0;
      }
    }
    OC_ERR("oic.role.* roles assertion is prohibited");
    return -1;
  }
  return 0;
}
#endif

#ifdef OC_PKI
static bool
check_uuid_from_cert_raw(size_t publicdata_size, const uint8_t *publicdata,
                         const oc_uuid_t *uuid)
{
  bool res = false;

  if (!publicdata || !uuid) {
    return false;
  }

  oc_string_t uuid_from_cert;
  if (oc_certs_parse_CN_for_UUID_raw(publicdata, publicdata_size,
                                     &uuid_from_cert) == 0) {
    char uuid_str[OC_UUID_LEN];
    oc_uuid_to_str(uuid, uuid_str, OC_UUID_LEN);
    res = (memcmp(oc_string(uuid_from_cert), uuid_str, OC_UUID_LEN) == 0);
    oc_free_string(&uuid_from_cert);
  }

  return res;
}
#endif

static const oc_uuid_t *
get_device_uuid(size_t device)
{
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  return doxm ? &doxm->deviceuuid : NULL;
}

int
oc_sec_add_new_cred(size_t device, bool roles_resource, oc_tls_peer_t *client,
                    int credid, oc_sec_credtype_t credtype,
                    oc_sec_credusage_t credusage, const char *subjectuuid,
                    oc_sec_encoding_t privatedata_encoding,
                    size_t privatedata_size, const uint8_t *privatedata,
                    oc_sec_encoding_t publicdata_encoding,
                    size_t publicdata_size, const uint8_t *publicdata,
                    const char *role, const char *authority)
{
  (void)publicdata_encoding;
  (void)publicdata;
  (void)publicdata_size;
  (void)get_device_uuid;
#ifdef OC_PKI
  oc_string_t public_key;
  memset(&public_key, 0, sizeof(oc_string_t));
  int public_key_len = 0;
  if (credtype == OC_CREDTYPE_CERT &&
      (public_key_len = oc_certs_parse_public_key(
         publicdata, publicdata_size + 1, &public_key)) < 0) {
    goto add_new_cred_error;
  }

  if (roles_resource) {
    if (credusage != OC_CREDUSAGE_ROLE_CERT) {
      goto add_new_cred_error;
    }
    if (!client) {
      goto add_new_cred_error;
    }
    if (client->public_key.size > 0 &&
        memcmp(oc_cast(public_key, uint8_t) + public_key.size -
                 (size_t)public_key_len,
               oc_cast(client->public_key, uint8_t) + client->public_key.size -
                 (size_t)public_key_len,
               (size_t)public_key_len) != 0) {
      goto add_new_cred_error;
    }
    if (!check_uuid_from_cert_raw(publicdata_size + 1, publicdata,
                                  &client->uuid)) {
      goto add_new_cred_error;
    }
  }
#endif /* OC_PKI */

  oc_uuid_t subject;
  memset(&subject, 0, sizeof(oc_uuid_t));

  if (!subjectuuid) {
    if (credusage != OC_CREDUSAGE_ROLE_CERT) {
      goto add_new_cred_error;
    } else {
      subject.id[0] = '*';
    }
  } else {
    if (subjectuuid[0] == '*') {
      subject.id[0] = '*';
    } else {
      oc_str_to_uuid(subjectuuid, &subject);
    }
  }

#ifdef OC_PKI
  oc_ecdsa_keypair_t *kp = NULL;

  if (credusage == OC_CREDUSAGE_IDENTITY_CERT && privatedata_size == 0) {
    kp = oc_sec_get_ecdsa_keypair(device);
    if (!kp) {
      goto add_new_cred_error;
    }
    if (memcmp(kp->public_key,
               oc_cast(public_key, uint8_t) + public_key.size -
                 (size_t)public_key_len,
               (size_t)public_key_len) != 0) {
      goto add_new_cred_error;
    }
    if (!check_uuid_from_cert_raw(publicdata_size + 1, publicdata,
                                  get_device_uuid(device))) {
      goto add_new_cred_error;
    }
  }
#endif /* OC_PKI */

  oc_sec_cred_t *existing =
    is_existing_cred(credid, roles_resource, client, device);
  if (existing) {
    if (!roles_resource) {
      /* remove duplicate cred, if one exists.  */
      if ((existing->credtype == credtype) &&
          memcmp(&existing->subjectuuid, &subject, sizeof(oc_uuid_t)) == 0 &&
          ((oc_string_len(existing->privatedata.data) == privatedata_size) &&
           (memcmp(oc_string(existing->privatedata.data), privatedata,
                   privatedata_size) == 0))
#ifdef OC_PKI
          && (existing->credusage == credusage) &&
          ((oc_string_len(existing->publicdata.data) == publicdata_size) &&
           (memcmp(oc_string(existing->publicdata.data), publicdata,
                   publicdata_size) == 0))
#endif /* OC_PKI */
      ) {
#ifdef OC_PKI
        if (oc_string_len(public_key) > 0) {
          oc_free_string(&public_key);
        }
#endif /* OC_PKI */
        return credid;
      } else {
        oc_sec_remove_cred_by_credid(credid, device);
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
      cred = oc_sec_find_creds_for_subject(&subject, cred, device);

      if (cred) {
        if (cred->credtype == credtype) {
          /* Exit this block if we're modifying an existing cred entry */
          if (cred->credid == credid) {
            oc_sec_remove_cred(cred, device);
            break;
          }
#ifdef OC_PKI
          if (credtype == OC_CREDTYPE_CERT && cred->credusage == credusage) {
            /* Trying to add a duplicate certificate chain, so ignore */
            if (publicdata_size > 0 &&
                publicdata_size == oc_string_len(cred->publicdata.data) &&
                memcmp(publicdata, oc_string(cred->publicdata.data),
                       publicdata_size) == 0) {
              if (oc_string_len(public_key) > 0) {
                oc_free_string(&public_key);
              }
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
      if ((oc_string_len(roles->publicdata.data) == publicdata_size) &&
          memcmp(oc_string(roles->publicdata.data), publicdata,
                 publicdata_size) == 0) {
        if (oc_string_len(public_key) > 0) {
          oc_free_string(&public_key);
        }
        return roles->credid;
      }
      roles = roles->next;
    }
  }
#endif /* OC_PKI */

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
      if (key_size < 0) {
        oc_sec_remove_cred(cred, device);
        goto add_new_cred_error;
      }
      oc_new_string(&cred->privatedata.data, (const char *)key, key_size);
      privatedata_encoding = OC_ENCODING_RAW;
    } else {
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

#ifdef OC_PKI
  if (cred->credtype == OC_CREDTYPE_CERT) {
    if (cred->credusage == OC_CREDUSAGE_MFG_CERT ||
        cred->credusage == OC_CREDUSAGE_IDENTITY_CERT) {
      oc_tls_refresh_identity_certs();
    }
    if (cred->credusage == OC_CREDUSAGE_MFG_TRUSTCA ||
        cred->credusage == OC_CREDUSAGE_TRUSTCA) {
      oc_tls_refresh_trust_anchors();
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
  if (oc_string_len(public_key) > 0) {
    oc_free_string(&public_key);
  }
#endif /* OC_PKI */
  return cred->credid;
add_new_cred_error:
#ifdef OC_PKI
  if (oc_string_len(public_key) > 0) {
    oc_free_string(&public_key);
  }
#endif /* OC_PKI */
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

bool
oc_sec_decode_cred(oc_rep_t *rep, oc_sec_cred_t **owner, bool from_storage,
                   bool roles_resource, oc_tls_peer_t *client, size_t device)
{
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_rep_t *t = rep;
  size_t len = 0;

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
          bool owner_cred = false;
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
            /* subjectuuid and credusage */
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
              break;
            /* publicdata, privatedata and roleid */
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

          if (non_empty) {
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
              role, authority);

            if (credid == -1) {
              return false;
            }

            oc_sec_cred_t *cr = oc_sec_get_cred_by_credid(credid, device);
            if (cr) {
              cr->owner_cred = owner_cred;
              /* Obtain a handle to the owner credential entry where that
               * applies
               */
              if (credtype == OC_CREDTYPE_PSK && privatedata_size == 0 &&
                  owner) {
                *owner = cr;
                (*owner)->owner_cred = true;
              }
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

  char *query_param = 0;
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
      oc_sec_clear_creds(request->resource->device);
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

void
post_cred(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  bool roles_resource = false;
  oc_tls_peer_t *client = NULL;

#ifdef OC_PKI
  if (oc_string_len(request->resource->uri) == 14 &&
      memcmp(oc_string(request->resource->uri), "/oic/sec/roles", 14) == 0) {
    roles_resource = true;
    client = oc_tls_get_peer(request->origin);
  }
#endif /* OC_PKI */

  oc_sec_doxm_t *doxm = oc_sec_get_doxm(request->resource->device);
  oc_sec_cred_t *owner = NULL;
  bool success =
    oc_sec_decode_cred(request->request_payload, &owner, false, roles_resource,
                       client, request->resource->device);
  if (!roles_resource && success && owner &&
      memcmp(owner->subjectuuid.id,
             devices[request->resource->device].rowneruuid.id, 16) == 0) {
    char owneruuid[37], deviceuuid[37];
    oc_uuid_to_str(&doxm->deviceuuid, deviceuuid, 37);
    oc_uuid_to_str(&owner->subjectuuid, owneruuid, 37);
    oc_alloc_string(&owner->privatedata.data, 17);
    if (doxm->oxmsel == OC_OXMTYPE_JW) {
      success = oc_sec_derive_owner_psk(
        request->origin, (const uint8_t *)OXM_JUST_WORKS,
        strlen(OXM_JUST_WORKS), doxm->deviceuuid.id, 16, owner->subjectuuid.id,
        16, oc_cast(owner->privatedata.data, uint8_t), 16);
    } else if (doxm->oxmsel == OC_OXMTYPE_RDP) {
      success = oc_sec_derive_owner_psk(
        request->origin, (const uint8_t *)OXM_RANDOM_DEVICE_PIN,
        strlen(OXM_RANDOM_DEVICE_PIN), doxm->deviceuuid.id, 16,
        owner->subjectuuid.id, 16, oc_cast(owner->privatedata.data, uint8_t),
        16);
    }
#ifdef OC_PKI
    else if (doxm->oxmsel == OC_OXMTYPE_MFG_CERT) {
      success = oc_sec_derive_owner_psk(
        request->origin, (const uint8_t *)OXM_MANUFACTURER_CERTIFICATE,
        strlen(OXM_MANUFACTURER_CERTIFICATE), doxm->deviceuuid.id, 16,
        owner->subjectuuid.id, 16, oc_cast(owner->privatedata.data, uint8_t),
        16);
    }
#endif /* OC_PKI */
    owner->privatedata.encoding = OC_ENCODING_RAW;
  }
  if (!success) {
    if (owner) {
      oc_sec_remove_cred_by_credid(owner->credid, request->resource->device);
    }
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  } else {
    oc_send_response(request, OC_STATUS_CHANGED);
    oc_sec_dump_cred(request->resource->device);
  }
}

#endif /* OC_SECURITY */

/*
// Copyright (c) 2017 Intel Corporation
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

#include "oc_cred.h"
#include "oc_api.h"
#include "oc_base64.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_doxm.h"
#include "oc_pstat.h"
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
#else /* OC_DYNAMIC_ALLOCATION */
static oc_sec_creds_t devices[OC_MAX_NUM_DEVICES];
#endif /* !OC_DYNAMIC_ALLOCATION */

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

static bool
unique_credid(int credid, size_t device)
{
  oc_sec_cred_t *cred = oc_list_head(devices[device].creds);
  while (cred != NULL) {
    if (cred->credid == credid)
      return false;
    cred = cred->next;
  }
  return true;
}

static int
get_new_credid(size_t device)
{
  int credid;
  do {
    credid = oc_random_value() >> 1;
  } while (!unique_credid(credid, device));
  return credid;
}

void
oc_sec_remove_cred(oc_sec_cred_t *cred, size_t device)
{
  oc_list_remove(devices[device].creds, cred);
  if (oc_string_len(cred->role.role) > 0) {
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
      oc_tls_remove_identity_cert(cred, device);
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
#ifdef OC_PKI
    if (cred->credusage != OC_CREDUSAGE_MFG_TRUSTCA &&
        cred->credusage != OC_CREDUSAGE_MFG_CERT)
#endif /* OC_PKI */
    {
      oc_sec_remove_cred(cred, device);
    }
    cred = next;
  }
}

static void
oc_sec_free_creds(size_t device)
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
}

void
oc_sec_cred_free(void)
{
  size_t device;
  for (device = 0; device < oc_core_get_num_devices(); device++) {
    oc_sec_free_creds(device);
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

int
oc_sec_add_new_cred(size_t device, int credid, oc_sec_credtype_t credtype,
                    oc_sec_credusage_t credusage, const char *subjectuuid,
                    oc_sec_encoding_t privatedata_encoding,
                    size_t privatedata_size, const uint8_t *privatedata,
                    oc_sec_encoding_t publicdata_encoding,
                    size_t publicdata_size, const uint8_t *publicdata,
                    const char *role, const char *authority)
{
  (void)publicdata_encoding;
  (void)publicdata_size;
  (void)publicdata;

  if (!subjectuuid) {
    return -1;
  }

  /* remove duplicate cred, if one exists.  */
  if (!unique_credid(credid, device)) {
    oc_sec_remove_cred_by_credid(credid, device);
  }

  oc_uuid_t subject;
  if (subjectuuid[0] == '*') {
    memset(&subject, 0, sizeof(oc_uuid_t));
    subject.id[0] = '*';
  } else {
    oc_str_to_uuid(subjectuuid, &subject);
  }

#ifdef OC_PKI
  oc_sec_cred_t *chain = NULL;
#endif /* OC_PKI */
  oc_sec_cred_t *cred = NULL;
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
            return cred->credid;
          } else if (cred->credusage != OC_CREDUSAGE_TRUSTCA &&
                     cred->credusage != OC_CREDUSAGE_MFG_TRUSTCA) {
            /* Trying to record a new cert in a cert chain via a
                     separate cred entry. Store a pointer to the existing
                     cred entry for linking to two below. */
            chain = cred;
            break;
          }
        }
#endif /* OC_PKI */
      }
      cred = cred->next;
    }
  } while (cred);

  cred = oc_sec_allocate_cred(&subject, credtype, credusage, device);
  if (!cred) {
    return -1;
  }

#ifdef OC_PKI
  if (chain) {
    if (oc_string_len(chain->privatedata.data) > 0) {
      chain->chain = cred;
      cred->child = chain;
    } else if (privatedata_size > 0) {
      cred->chain = chain;
      chain->child = cred;
    } else {
      /* Cannot find the leaf certificate among two certificates carrying
       * the same subjectuuid. This contradicts the three tiered certificate
       * hierarchy and is hence an error.
       */
      oc_sec_remove_cred(cred, device);
      return -1;
    }
  }
#endif /* OC_PKI */

  /* if a credid wasn't provided in the request, pick a suitable one */
  if (credid == -1) {
    credid = get_new_credid(device);
  }

  /* credid */
  cred->credid = credid;
  /* credtype */
  cred->credtype = credtype;

  /* privatedata */
  if (privatedata && privatedata_size > 0) {
    uint8_t key[24];
    if (credtype == OC_CREDTYPE_PSK &&
        privatedata_encoding == OC_ENCODING_BASE64) {
      memcpy(key, privatedata, 24);
      oc_base64_decode(key, 24);
      oc_new_string(&cred->privatedata.data, (const char *)privatedata,
                    privatedata_size);
      privatedata_encoding = OC_ENCODING_RAW;
    } else {
      oc_new_string(&cred->privatedata.data, (const char *)privatedata,
                    privatedata_size);
    }
    cred->privatedata.encoding = privatedata_encoding;
  }

  /* roleid */
  if (role) {
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
  }
#endif /* OC_PKI */

  return cred->credid;
}

#ifdef OC_PKI

static const char *
return_credusage_string(oc_sec_credusage_t credusage)
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
  return NULL;
}
#endif /* OC_PKI */

static const char *
return_encoding_string(oc_sec_encoding_t encoding)
{
  switch (encoding) {
  case OC_ENCODING_BASE64:
    return "oic.sec.encoding.base64";
  case OC_ENCODING_RAW:
    return "oic.sec.encoding.raw";
#ifdef OC_PKI
  case OC_ENCODING_PEM:
    return "oic.sec.encoding.pem";
  case OC_ENCODING_DER:
    return "oic.sec.encoding.der";
#endif /* OC_PKI */
  default:
    break;
  }
  return NULL;
}

void
oc_sec_encode_cred(bool persist, size_t device)
{
  oc_sec_cred_t *cr = oc_list_head(devices[device].creds);
  char uuid[OC_UUID_LEN];
  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_CRED, device));
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
    if (oc_string_len(cr->role.role) > 0) {
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
      oc_rep_set_byte_string(privatedata, data,
                             oc_cast(cr->privatedata.data, const uint8_t),
                             oc_string_len(cr->privatedata.data));
    } else {
      oc_rep_set_byte_string(privatedata, data,
                             oc_cast(cr->privatedata.data, const uint8_t), 0);
    }
    const char *encoding_string =
      return_encoding_string(cr->privatedata.encoding);
    if (encoding_string) {
      oc_rep_set_text_string(privatedata, encoding, encoding_string);
    }
    oc_rep_close_object(creds, privatedata);
#ifdef OC_PKI
    /* credusage */
    const char *credusage_string = return_credusage_string(cr->credusage);
    if (credusage_string) {
      oc_rep_set_text_string(creds, credusage, credusage_string);
    }
    /* publicdata */
    oc_rep_set_object(creds, publicdata);
    if (cr->publicdata.encoding == OC_ENCODING_PEM) {
      oc_rep_set_text_string(publicdata, data, oc_string(cr->publicdata.data));
    } else {
      oc_rep_set_byte_string(publicdata, data,
                             oc_cast(cr->publicdata.data, const uint8_t),
                             oc_string_len(cr->publicdata.data));
    }
    const char *encoding_string =
      return_encoding_string(cr->publicdata.encoding);
    if (encoding_string) {
      oc_rep_set_text_string(publicdata, encoding, encoding_string);
    }
    oc_rep_close_object(creds, publicdata);
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
static oc_sec_credusage_t
parse_credusage_property(oc_string_t *credusage_string)
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

static oc_sec_encoding_t
parse_encoding_property(oc_string_t *encoding_string)
{
  oc_sec_encoding_t encoding = 0;
  if (oc_string_len(*encoding_string) == 23 &&
      memcmp("oic.sec.encoding.base64", oc_string(*encoding_string), 23) == 0) {
    encoding = OC_ENCODING_BASE64;
  } else if (oc_string_len(*encoding_string) == 20 &&
             memcmp("oic.sec.encoding.raw", oc_string(*encoding_string), 20) ==
               0) {
    encoding = OC_ENCODING_RAW;
  }
#ifdef OC_PKI
  else if (oc_string_len(*encoding_string) == 20 &&
           memcmp("oic.sec.encoding.pem", oc_string(*encoding_string), 20) ==
             0) {
    encoding = OC_ENCODING_PEM;
  } else if (oc_string_len(*encoding_string) == 20 &&
             memcmp("oic.sec.encoding.der", oc_string(*encoding_string), 20) ==
               0) {
    encoding = OC_ENCODING_DER;
  }
#endif /* OC_PKI */
  return encoding;
}

bool
oc_sec_decode_cred(oc_rep_t *rep, oc_sec_cred_t **owner, bool from_storage,
                   size_t device)
{
  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_rep_t *t = rep;
  size_t len = 0;

  while (t != NULL) {
    len = oc_string_len(t->name);
    switch (t->type) {
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(t->name), "rowneruuid", 10) == 0) {
        if (!from_storage && ps->s != OC_DOS_RFOTM && ps->s != OC_DOS_SRESET) {
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
      if (len == 5 && memcmp(oc_string(rep->name), "creds", 5) == 0) {
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
          bool non_empty = false;
          while (cred != NULL) {
            non_empty = true;
            len = oc_string_len(cred->name);
            switch (cred->type) {
            /* credid and credtype  */
            case OC_REP_INT:
              if (len == 6 && memcmp(oc_string(cred->name), "credid", 6) == 0) {
                credid = cred->value.integer;
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
                credusage = parse_credusage_property(&cred->value.string);
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
                      *encoding = parse_encoding_property(&data->value.string);
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
                  } else if (len == 9 &&
                             memcmp(oc_string(data->name), "authority", 9) ==
                               0) {
                    authority = oc_string(data->value.string);
                  }
                  data = data->next;
                }
              }
            } break;
            default:
              break;
            }
            cred = cred->next;
          }

          if (non_empty) {
            credid = oc_sec_add_new_cred(
              device, credid, credtype,
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

            /* privatedata */
            if (credtype == OC_CREDTYPE_PSK && privatedata_size == 0 && owner) {
              *owner = oc_sec_get_cred_by_credid(credid, device);
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
get_cred(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  oc_sec_encode_cred(false, request->resource->device);
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
delete_cred(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  bool success = false;
  char *query_param = 0;
  int ret = oc_get_query_value(request, "credid", &query_param);
  int credid = 0;
  if (ret != -1) {
    credid = (int)strtoul(query_param, NULL, 10);
    if (credid != 0) {
      if (oc_sec_remove_cred_by_credid(credid, request->resource->device)) {
        success = true;
      }
    }
  } else {
    oc_sec_clear_creds(request->resource->device);
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
post_cred(oc_request_t *request, oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(request->resource->device);
  oc_sec_cred_t *owner = NULL;
  bool success = oc_sec_decode_cred(request->request_payload, &owner, false,
                                    request->resource->device);
  if (success && owner &&
      memcmp(owner->subjectuuid.id,
             devices[request->resource->device].rowneruuid.id, 16) == 0) {
    char owneruuid[37], deviceuuid[37];
    oc_uuid_to_str(&doxm->deviceuuid, deviceuuid, 37);
    oc_uuid_to_str(&owner->subjectuuid, owneruuid, 37);
    oc_alloc_string(&owner->privatedata.data, 16);
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

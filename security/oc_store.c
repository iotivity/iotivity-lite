/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
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
#include "oc_acl_internal.h"
#include "oc_ael.h"
#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm.h"
#include "oc_keypair_internal.h"
#include "oc_pstat.h"
#include "oc_sdi.h"
#include "oc_sp_internal.h"
#include "oc_store.h"
#include "oc_tls.h"
#include "port/oc_storage.h"
#include <oc_config.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#else /* OC_DYNAMIC_ALLOCATION */
#define OC_APP_DATA_STORAGE_BUFFER
#ifndef OC_APP_DATA_BUFFER_SIZE
#define OC_APP_DATA_BUFFER_SIZE OC_MAX_APP_DATA_SIZE
#endif /* OC_APP_DATA_BUFFER_SIZE */
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_APP_DATA_STORAGE_BUFFER
static uint8_t oc_store_buf[OC_APP_DATA_BUFFER_SIZE];
#endif /* OC_APP_DATA_STORAGE_BUFFER */

#define SVR_TAG_MAX (32)
static void
gen_svr_tag(const char *name, size_t device_index, char *svr_tag)
{
  int svr_tag_len =
    snprintf(svr_tag, SVR_TAG_MAX, "%s_%zd", name, device_index);
  svr_tag_len =
    (svr_tag_len < SVR_TAG_MAX - 1) ? svr_tag_len + 1 : SVR_TAG_MAX - 1;
  svr_tag[svr_tag_len] = '\0';
}

void
oc_sec_load_doxm(size_t device)
{
  long ret = 0;
  oc_rep_t *rep;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_doxm_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("doxm", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    oc_sec_decode_doxm(rep, true, false, device);
    oc_free_rep(rep);
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  memcpy(deviceuuid, &doxm->deviceuuid, sizeof(oc_uuid_t));
}

void
oc_sec_load_pstat(size_t device)
{
  long ret = 0;
  oc_rep_t *rep = 0;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_pstat_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("pstat", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    oc_sec_decode_pstat(rep, true, device);
    oc_free_rep(rep);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  if (ret <= 0) {
    oc_sec_pstat_default(device);
  }
}

void
oc_sec_load_sp(size_t device)
{
  long ret = 0;
  oc_rep_t *rep = 0;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_sp_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("sp", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    oc_sec_decode_sp(rep, device);
    oc_free_rep(rep);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  if (ret <= 0) {
    oc_sec_sp_default(device);
  }
}

void
oc_sec_dump_sp(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_sp(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded sp size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("sp", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

#ifdef OC_PKI
void
oc_sec_load_ecdsa_keypair(size_t device)
{
  long ret = 0;
  oc_rep_t *rep = 0;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_sp_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("keypair", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    if (oc_sec_ecdsa_decode_keypair_for_device(rep, device)) {
      OC_DBG("successfully read ECDSA keypair for device %zd", device);
    }
    oc_free_rep(rep);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  if (ret <= 0) {
    if (!oc_sec_ecdsa_generate_keypair_for_device(oc_sec_certs_ecp_group_id(),
                                                  device)) {
      OC_ERR("error generating ECDSA keypair for device %zd", device);
    }
    oc_sec_dump_ecdsa_keypair(device);
  }
}

void
oc_sec_dump_ecdsa_keypair(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_ecdsa_encode_keypair_for_device(device);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded sp size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("keypair", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}
#endif /* OC_PKI */

void
oc_sec_load_cred(size_t device)
{
  long ret = 0;
  oc_rep_t *rep;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("cred", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);

  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    oc_sec_decode_cred(rep, NULL, true, false, NULL, device, NULL, NULL);
    oc_free_rep(rep);
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_load_acl(size_t device)
{
  long ret = 0;
  oc_rep_t *rep;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_acl_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("acl", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    if (oc_parse_rep(oc_store_buf, (int)ret, &rep) != 0) {
      OC_ERR("failed to parse acl buffer");
    }
    oc_sec_decode_acl(rep, true, device, NULL, NULL);
    oc_free_rep(rep);
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_pstat(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_pstat(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded pstat size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("pstat", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_cred(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_cred(true, device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded cred size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("cred", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_doxm(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_doxm(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded doxm size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("doxm", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_acl(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_acl(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded ACL size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("acl", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_load_unique_ids(size_t device)
{
  long ret = 0;
  oc_rep_t *rep;
  oc_platform_info_t *platform_info = oc_core_get_platform_info();
  oc_device_info_t *device_info = oc_core_get_device_info(device);

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("u_ids", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    int err = oc_parse_rep(oc_store_buf, ret, &rep);
    oc_rep_t *p = rep;
    if (err == 0) {
      while (rep != NULL) {
        switch (rep->type) {
        case OC_REP_STRING:
          if (oc_string_len(rep->name) == 2 &&
              memcmp(oc_string(rep->name), "pi", 2) == 0) {
            oc_str_to_uuid(oc_string(rep->value.string), &platform_info->pi);
          } else if (oc_string_len(rep->name) == 4 &&
                     memcmp(oc_string(rep->name), "piid", 4) == 0) {
            oc_str_to_uuid(oc_string(rep->value.string), &device_info->piid);
          }
          break;
        default:
          break;
        }
        rep = rep->next;
      }
    }
    oc_free_rep(p);
  } else {
    oc_sec_dump_unique_ids(device);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_unique_ids(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  const oc_device_info_t *device_info = oc_core_get_device_info(device);
  char piid[OC_UUID_LEN];
  oc_uuid_to_str(&device_info->piid, piid, OC_UUID_LEN);
  const oc_platform_info_t *platform_info = oc_core_get_platform_info();
  char pi[OC_UUID_LEN];
  oc_uuid_to_str(&platform_info->pi, pi, OC_UUID_LEN);

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, pi, pi);
  oc_rep_set_text_string(root, piid, piid);
  oc_rep_end_root_object();

#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded unique identifiers: size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("u_ids", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_ael(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  /* ael */
  oc_sec_ael_encode(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded ael size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("ael", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }

#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_load_sdi(size_t device)
{
  long ret = 0;
  oc_rep_t *rep;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_sdi_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("sdi", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    oc_sec_decode_sdi(rep, true, device);
    oc_free_rep(rep);
  } else {
    oc_sec_sdi_default(device);
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_load_ael(size_t device)
{
  long ret = 0;
  oc_rep_t *rep;

#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!oc_store_buf) {
    oc_sec_ael_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("ael", device, svr_tag);
  ret = oc_storage_read(svr_tag, oc_store_buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(oc_store_buf, (int)ret, &rep);
    oc_sec_ael_decode(device, rep, true);
    oc_free_rep(rep);
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

void
oc_sec_dump_sdi(size_t device)
{
#ifndef OC_APP_DATA_STORAGE_BUFFER
  uint8_t *oc_store_buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!oc_store_buf)
    return;
  oc_rep_new_realloc(&oc_store_buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new(oc_store_buf, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  /* sdi */
  oc_sec_encode_sdi(device, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  oc_store_buf = oc_rep_shrink_encoder_buf(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded sdi size %d", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("sdi", device, svr_tag);
    oc_storage_write(svr_tag, oc_store_buf, size);
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  free(oc_store_buf);
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
}

#endif /* OC_SECURITY */

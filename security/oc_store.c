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

#include "oc_store.h"
#include "api/oc_rep_internal.h"
#include "api/oc_storage_internal.h"
#include "oc_acl_internal.h"
#include "oc_ael_internal.h"
#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_doxm_internal.h"
#include "oc_keypair_internal.h"
#include "oc_pstat_internal.h"
#include "oc_rep.h"
#include "oc_sdi_internal.h"
#include "oc_sp_internal.h"
#include "oc_tls_internal.h"
#include "port/oc_storage.h"

static int
store_decode_doxm(const oc_rep_t *rep, size_t device, void *data)
{
  (void)data;
  if (!oc_sec_decode_doxm(rep, /*from_storage*/ true, /*doc*/ false, device)) {
    OC_ERR("cannot load doxm: cannot decode representation");
    return -1;
  }
  return 0;
}

void
oc_sec_load_doxm(size_t device)
{
  if (oc_storage_data_load("doxm", device, store_decode_doxm, NULL) <= 0) {
    OC_DBG("failed to load doxm from storage for device(%zu)", device);
    oc_sec_doxm_default(device);
    return;
  }
  OC_DBG("%s resource loaded from storage for device(%zu)", "doxm", device);

  oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
  const oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  memcpy(deviceuuid, &doxm->deviceuuid, sizeof(oc_uuid_t));
}

static int
store_encode_doxm(size_t device, void *data)
{
  (void)data;
  oc_sec_encode_doxm(device, /*iface_mask*/ 0, true);
  return 0;
}

void
oc_sec_dump_doxm(size_t device)
{
  long ret = oc_storage_data_save("doxm", device, store_encode_doxm, NULL);
  if (ret <= 0) {
    OC_ERR("cannot dump doxm to storage: error(%ld)", ret);
  }
}

static int
store_decode_pstat(const oc_rep_t *rep, size_t device, void *data)
{
  (void)data;
  if (!oc_sec_decode_pstat(rep, true, device)) {
    OC_ERR("cannot decode pstat");
    return -1;
  }
  return 0;
}

void
oc_sec_load_pstat(size_t device)
{
  if (oc_storage_data_load("pstat", device, store_decode_pstat, NULL) <= 0) {
    OC_DBG("failed to load pstat from storage for device(%zu)", device);
    oc_sec_pstat_default(device);
    return;
  }
  OC_DBG("%s resource loaded from storage for device(%zu)", "pstat", device);
}

static int
store_encode_pstat(size_t device, void *data)
{
  (void)data;
  oc_sec_encode_pstat(device, /*iface_mask*/ 0, /*to_storage*/ true);
  return 0;
}

void
oc_sec_dump_pstat(size_t device)
{
  long ret = oc_storage_data_save("pstat", device, store_encode_pstat, NULL);
  if (ret <= 0) {
    OC_ERR("cannot dump pstat to storage: error(%ld)", ret);
  }
}

static int
store_decode_sp(const oc_rep_t *rep, size_t device, void *data)
{
  (void)data;
  if (!oc_sec_sp_decode_for_device(rep, device)) {
    OC_ERR("cannot decode sp for device(%zu)", device);
    return -1;
  }
  return 0;
}

void
oc_sec_load_sp(size_t device)
{
  if (oc_storage_data_load(OCF_SEC_SP_STORE_NAME, device, store_decode_sp,
                           NULL) <= 0) {
    OC_DBG("failed to load sp from storage for device(%zu)", device);
    oc_sec_sp_default(device);
    return;
  }
  OC_DBG("sp resource loaded from storage for device(%zu)", device);
}

static int
store_encode_sp(size_t device, void *data)
{
  (void)data;
  return oc_sec_sp_encode_for_device(device, /*flags*/ 0) ? 0 : -1;
}

void
oc_sec_dump_sp(size_t device)
{
  long ret =
    oc_storage_data_save(OCF_SEC_SP_STORE_NAME, device, store_encode_sp, NULL);
  if (ret <= 0) {
    OC_ERR("cannot dump sp for device(%zu) to store: error(%ld)", device, ret);
  }
}

#ifdef OC_PKI
void
oc_sec_load_ecdsa_keypair(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MAX_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot load %s from store: cannot allocate buffer", "keypair");
    oc_sec_sp_default(device);
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  oc_storage_gen_svr_tag("keypair", device, svr_tag, sizeof(svr_tag));
  long ret = oc_storage_read(svr_tag, sb.buffer, sb.size);
  if (ret > 0) {
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
    struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
    oc_rep_t *rep = NULL;
    oc_parse_rep(sb.buffer, (int)ret, &rep);
    if (oc_sec_ecdsa_decode_keypair_for_device(rep, device)) {
      OC_DBG("successfully read ECDSA keypair for device %zd", device);
    }
    oc_free_rep(rep);
    oc_rep_set_pool(prev_rep_objects);
  }

  oc_storage_free_buffer(sb);

  if (ret <= 0) {
    if (!oc_sec_ecdsa_update_or_generate_keypair_for_device(
          oc_sec_certs_ecp_group_id(), device)) {
      OC_ERR("error generating ECDSA keypair for device %zd", device);
    }
    oc_sec_dump_ecdsa_keypair(device);
  }
}

void
oc_sec_dump_ecdsa_keypair(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MIN_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot dump %s to store: cannot allocate buffer", "keypair");
    return;
  }
  oc_rep_new_realloc_v1(&sb.buffer, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new_v1(sb.buffer, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_ecdsa_encode_keypair_for_device(device);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  sb.buffer = oc_rep_shrink_encoder_buf(sb.buffer);
  sb.size = (size_t)oc_rep_get_encoder_buffer_size();
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded sp size %d", size);
    char svr_tag[OC_STORAGE_SVR_TAG_MAX];
    oc_storage_gen_svr_tag("keypair", device, svr_tag, sizeof(svr_tag));
    oc_storage_write(svr_tag, sb.buffer, size);
  }
  oc_storage_free_buffer(sb);
}
#endif /* OC_PKI */

void
oc_sec_load_cred(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MAX_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot load %s from store: cannot allocate buffer", "cred");
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  oc_storage_gen_svr_tag("cred", device, svr_tag, sizeof(svr_tag));
  long ret = oc_storage_read(svr_tag, sb.buffer, sb.size);
  if (ret > 0) {
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
    struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
    oc_rep_t *rep = NULL;
    oc_parse_rep(sb.buffer, (int)ret, &rep);
    oc_sec_decode_cred(rep, NULL, true, false, NULL, device, NULL, NULL);
    oc_free_rep(rep);
    oc_rep_set_pool(prev_rep_objects);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_dump_cred(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MIN_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot dump %s to store: cannot allocate buffer", "cred");
    return;
  }
  oc_rep_new_realloc_v1(&sb.buffer, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new_v1(sb.buffer, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_cred(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  sb.buffer = oc_rep_shrink_encoder_buf(sb.buffer);
  sb.size = (size_t)oc_rep_get_encoder_buffer_size();
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded cred size %d", size);
    char svr_tag[OC_STORAGE_SVR_TAG_MAX];
    oc_storage_gen_svr_tag("cred", device, svr_tag, sizeof(svr_tag));
    oc_storage_write(svr_tag, sb.buffer, size);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_load_acl(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MAX_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot load %s from store: cannot allocate buffer", "acl");
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  oc_storage_gen_svr_tag("acl", device, svr_tag, sizeof(svr_tag));
  long ret = oc_storage_read(svr_tag, sb.buffer, sb.size);
  if (ret > 0) {
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
    struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
    oc_rep_t *rep = NULL;
    if (oc_parse_rep(sb.buffer, (int)ret, &rep) != 0) {
      OC_ERR("failed to parse acl buffer");
    }
    oc_sec_decode_acl(rep, true, device, NULL, NULL);
    oc_free_rep(rep);
    oc_rep_set_pool(prev_rep_objects);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_dump_acl(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MIN_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot dump %s to store: cannot allocate buffer", "acl");
    return;
  }
  oc_rep_new_realloc_v1(&sb.buffer, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new_v1(sb.buffer, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  oc_sec_encode_acl(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  sb.buffer = oc_rep_shrink_encoder_buf(sb.buffer);
  sb.size = (size_t)oc_rep_get_encoder_buffer_size();
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded ACL size %d", size);
    char svr_tag[OC_STORAGE_SVR_TAG_MAX];
    oc_storage_gen_svr_tag("acl", device, svr_tag, sizeof(svr_tag));
    oc_storage_write(svr_tag, sb.buffer, size);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_load_unique_ids(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MAX_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot load %s from store: cannot allocate buffer", "unique_ids");
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  oc_storage_gen_svr_tag("u_ids", device, svr_tag, sizeof(svr_tag));
  long ret = oc_storage_read(svr_tag, sb.buffer, sb.size);
  if (ret > 0) {
    oc_platform_info_t *platform_info = oc_core_get_platform_info();
    oc_device_info_t *device_info = oc_core_get_device_info(device);
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
    struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
    oc_rep_t *rep = NULL;
    int err = oc_parse_rep(sb.buffer, ret, &rep);
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
    oc_rep_set_pool(prev_rep_objects);
  } else {
    oc_sec_dump_unique_ids(device);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_dump_unique_ids(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MIN_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot dump %s to store: cannot allocate buffer", "unique_ids");
    return;
  }
  oc_rep_new_realloc_v1(&sb.buffer, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new_v1(sb.buffer, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  const oc_device_info_t *device_info = oc_core_get_device_info(device);
  char piid[OC_UUID_LEN];
  oc_uuid_to_str(&device_info->piid, piid, sizeof(piid));
  const oc_platform_info_t *platform_info = oc_core_get_platform_info();
  char pi[OC_UUID_LEN];
  oc_uuid_to_str(&platform_info->pi, pi, sizeof(pi));

  oc_rep_start_root_object();
  oc_rep_set_text_string(root, pi, pi);
  oc_rep_set_text_string(root, piid, piid);
  oc_rep_end_root_object();

#ifndef OC_APP_DATA_STORAGE_BUFFER
  sb.buffer = oc_rep_shrink_encoder_buf(sb.buffer);
  sb.size = (size_t)oc_rep_get_encoder_buffer_size();
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded unique identifiers: size %d", size);
    char svr_tag[OC_STORAGE_SVR_TAG_MAX];
    oc_storage_gen_svr_tag("u_ids", device, svr_tag, sizeof(svr_tag));
    oc_storage_write(svr_tag, sb.buffer, size);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_load_ael(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MAX_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot load %s from store: cannot allocate buffer", "ael");
    return;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  oc_storage_gen_svr_tag("ael", device, svr_tag, sizeof(svr_tag));
  long ret = oc_storage_read(svr_tag, sb.buffer, sb.size);
  if (ret > 0) {
    OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
    struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
    oc_rep_t *rep = NULL;
    oc_parse_rep(sb.buffer, (int)ret, &rep);
    oc_sec_ael_decode(device, rep, true);
    oc_free_rep(rep);
    oc_rep_set_pool(prev_rep_objects);
  }
  oc_storage_free_buffer(sb);
}

void
oc_sec_dump_ael(size_t device)
{
  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MIN_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot dump %s to store: cannot allocate buffer", "ael");
    return;
  }
  oc_rep_new_realloc_v1(&sb.buffer, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new_v1(sb.buffer, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  /* ael */
  oc_sec_ael_encode(device, 0, true);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  sb.buffer = oc_rep_shrink_encoder_buf(sb.buffer);
  sb.size = (size_t)oc_rep_get_encoder_buffer_size();
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_store: encoded ael size %d", size);
    char svr_tag[OC_STORAGE_SVR_TAG_MAX];
    oc_storage_gen_svr_tag("ael", device, svr_tag, sizeof(svr_tag));
    oc_storage_write(svr_tag, sb.buffer, size);
  }
  oc_storage_free_buffer(sb);
}

static int
store_decode_sdi(const oc_rep_t *rep, size_t device, void *data)
{
  (void)data;
  if (!oc_sec_sdi_decode(device, rep, /*from_storage*/ true)) {
    OC_ERR("cannot decode sdi");
    return -1;
  }
  return 0;
}

void
oc_sec_load_sdi(size_t device)
{
  if (oc_storage_data_load(OCF_SEC_SDI_STORE_NAME, device, store_decode_sdi,
                           NULL) <= 0) {
    OC_DBG("failed to load sdi from storage for device(%zu)", device);
    oc_sec_sdi_default(device);
    return;
  }
  OC_DBG("%s resource loaded from storage for device(%zu)", "sdi", device);
}

static int
store_encode_sdi(size_t device, void *data)
{
  (void)data;
  return oc_sec_sdi_encode(device, /*iface_mask*/ 0);
}

void
oc_sec_dump_sdi(size_t device)
{
  long ret = oc_storage_data_save(OCF_SEC_SDI_STORE_NAME, device,
                                  store_encode_sdi, NULL);
  if (ret <= 0) {
    OC_ERR("cannot dump sdi to store: error(%ld)", ret);
  }
}

#endif /* OC_SECURITY */

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
#include "oc_store.h"
#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_doxm.h"
#include "oc_dtls.h"
#include "oc_pstat.h"
#include "port/oc_storage.h"
#include <config.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#define SVR_TAG_MAX (32)
static void
gen_svr_tag(const char *name, int device_index, char *svr_tag)
{
  int svr_tag_len = snprintf(svr_tag, SVR_TAG_MAX, "%s_%d", name, device_index);
  svr_tag_len = (svr_tag_len < SVR_TAG_MAX) ? svr_tag_len + 1 : SVR_TAG_MAX;
  svr_tag[svr_tag_len] = '\0';
}

void
oc_sec_load_doxm(int device)
{
  long ret = 0;
  oc_rep_t *rep;

  if (oc_sec_is_operational(device)) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf) {
      oc_sec_doxm_default(device);
      return;
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("doxm", device, svr_tag);
    ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
    if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
      char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
      oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
      memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
      memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
      struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                     rep_objects_alloc,
                                     (void *)rep_objects_pool };
#else  /* !OC_DYNAMIC_ALLOCATION */
      struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_rep_set_pool(&rep_objects);
      oc_parse_rep(buf, (uint16_t)ret, &rep);
      oc_sec_decode_doxm(rep, true, device);
      oc_free_rep(rep);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  oc_uuid_t *deviceuuid = oc_core_get_device_id(device);
  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  memcpy(deviceuuid, &doxm->deviceuuid, sizeof(oc_uuid_t));
  oc_sec_dtls_update_psk_identity(device);
}

void
oc_sec_load_pstat(int device)
{
  long ret = 0;
  oc_rep_t *rep = 0;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    oc_sec_pstat_default(device);
    return;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  char svr_tag[SVR_TAG_MAX];
  gen_svr_tag("pstat", device, svr_tag);
  ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
    char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
    oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
    memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
    struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                   rep_objects_alloc,
                                   (void *)rep_objects_pool };
#else  /* !OC_DYNAMIC_ALLOCATION */
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_rep_set_pool(&rep_objects);
    oc_parse_rep(buf, (uint16_t)ret, &rep);
    oc_sec_decode_pstat(rep, true, device);
    oc_free_rep(rep);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  if (ret <= 0) {
    oc_sec_pstat_default(device);
  }
}

void
oc_sec_load_cred(int device)
{
  long ret = 0;
  oc_rep_t *rep;

  if (oc_sec_is_operational(device)) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf)
      return;
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("cred", device, svr_tag);
    ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);

    if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
      char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
      oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
      memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
      memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
      struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                     rep_objects_alloc,
                                     (void *)rep_objects_pool };
#else  /* !OC_DYNAMIC_ALLOCATION */
      struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_rep_set_pool(&rep_objects);
      oc_parse_rep(buf, (uint16_t)ret, &rep);
      oc_sec_decode_cred(rep, NULL, true, device);
      oc_free_rep(rep);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
}

void
oc_sec_load_acl(int device)
{
  long ret = 0;
  oc_rep_t *rep;

  if (oc_sec_is_operational(device)) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf) {
      oc_sec_acl_default(device);
      return;
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("acl", device, svr_tag);
    ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
    if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
      char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
      oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
      memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
      memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
      struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                     rep_objects_alloc,
                                     (void *)rep_objects_pool };
#else  /* !OC_DYNAMIC_ALLOCATION */
      struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_rep_set_pool(&rep_objects);
      oc_parse_rep(buf, (uint16_t)ret, &rep);
      oc_sec_decode_acl(rep, true, device);
      oc_free_rep(rep);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
}

void
oc_sec_dump_pstat(int device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_pstat(device);
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded pstat size %d\n", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("pstat", device, svr_tag);
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_dump_cred(int device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_cred(true, device);
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded cred size %d\n", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("cred", device, svr_tag);
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_dump_doxm(int device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  /* doxm */
  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_doxm(device);
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded doxm size %d\n", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("doxm", device, svr_tag);
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_dump_acl(int device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_acl(device);
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded ACL size %d\n", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("acl", device, svr_tag);
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_load_unique_ids(int device)
{
  long ret = 0;
  oc_rep_t *rep;
  oc_platform_info_t *platform_info = oc_core_get_platform_info();
  oc_device_info_t *device_info = oc_core_get_device_info(device);

  if (oc_sec_is_operational(device)) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf) {
      return;
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("u_ids", device, svr_tag);
    ret = oc_storage_read(svr_tag, buf, OC_MAX_APP_DATA_SIZE);
    if (ret > 0) {
#ifndef OC_DYNAMIC_ALLOCATION
      char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
      oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
      memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
      memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
      struct oc_memb rep_objects = { sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                                     rep_objects_alloc,
                                     (void *)rep_objects_pool };
#else  /* !OC_DYNAMIC_ALLOCATION */
      struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
#endif /* OC_DYNAMIC_ALLOCATION */
      oc_rep_set_pool(&rep_objects);
      int err = oc_parse_rep(buf, ret, &rep);
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
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
}

void
oc_sec_dump_unique_ids(int device)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_device_info_t *device_info = oc_core_get_device_info(device);
  oc_platform_info_t *platform_info = oc_core_get_platform_info();

  char pi[37], piid[37];
  oc_uuid_to_str(&device_info->piid, piid, 37);
  oc_uuid_to_str(&platform_info->pi, pi, 37);

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, pi, pi);
  oc_rep_set_text_string(root, piid, piid);
  oc_rep_end_root_object();

  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded unique identifiers: size %d\n", size);
    char svr_tag[SVR_TAG_MAX];
    gen_svr_tag("u_ids", device, svr_tag);
    oc_storage_write(svr_tag, buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

#endif /* OC_SECURITY */

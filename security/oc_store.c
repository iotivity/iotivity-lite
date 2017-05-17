/*
// Copyright (c) 2016 Intel Corporation
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
#include "oc_pstat.h"
#include "port/oc_storage.h"
#include <config.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

void
oc_sec_load_doxm(void)
{
  long ret = 0;
  oc_rep_t *rep;

  if (oc_sec_provisioned()) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf) {
      oc_sec_doxm_default();
      return;
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
    ret = oc_storage_read("/doxm", buf, OC_MAX_APP_DATA_SIZE);
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
      oc_parse_rep(buf, ret, &rep);
      oc_sec_decode_doxm(rep, true);
      oc_free_rep(rep);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  if (ret <= 0) {
    oc_sec_doxm_default();
  }

  oc_uuid_t *deviceuuid = oc_core_get_device_id(0);
  oc_sec_doxm_t *doxm = oc_sec_get_doxm();
  memcpy(deviceuuid, &doxm->deviceuuid, sizeof(oc_uuid_t));
}

void
oc_sec_load_pstat(void)
{
  long ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    oc_sec_pstat_default();
    return;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_sec_acl_init();

  ret = oc_storage_read("/pstat", buf, OC_MAX_APP_DATA_SIZE);
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
    oc_parse_rep(buf, ret, &rep);
    oc_sec_decode_pstat(rep, true);
    oc_free_rep(rep);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  if (ret <= 0) {
    oc_sec_pstat_default();
  }
}

void
oc_sec_load_cred(void)
{
  long ret = 0;
  oc_rep_t *rep;

  if (oc_sec_provisioned()) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf)
      return;
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
    ret = oc_storage_read("/cred", buf, OC_MAX_APP_DATA_SIZE);

    if (ret <= 0)
      return;

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
    oc_parse_rep(buf, ret, &rep);
    oc_sec_decode_cred(rep, NULL);
    oc_free_rep(rep);
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }
}

void
oc_sec_load_acl(void)
{
  long ret = 0;
  oc_rep_t *rep;

  if (oc_sec_provisioned()) {
#ifdef OC_DYNAMIC_ALLOCATION
    uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
    if (!buf) {
      oc_sec_acl_default();
      return;
    }
#else  /* OC_DYNAMIC_ALLOCATION */
    uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
    ret = oc_storage_read("/acl", buf, OC_MAX_APP_DATA_SIZE);
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
      oc_parse_rep(buf, ret, &rep);
      oc_sec_decode_acl(rep);
      oc_free_rep(rep);
    }
#ifdef OC_DYNAMIC_ALLOCATION
    free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  if (ret <= 0) {
    oc_sec_acl_default();
  }
}

void
oc_sec_dump_pstat(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_pstat();
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded pstat size %d\n", size);
    oc_storage_write("/pstat", buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_dump_cred(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_cred(true);
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded cred size %d\n", size);
    oc_storage_write("/cred", buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_dump_doxm(void)
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
  oc_sec_encode_doxm();
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded doxm size %d\n", size);
    oc_storage_write("/doxm", buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}

void
oc_sec_dump_acl(void)
{
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[OC_MAX_APP_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_sec_encode_acl();
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_store: encoded ACL size %d\n", size);
    oc_storage_write("/acl", buf, size);
  }

#ifdef OC_DYNAMIC_ALLOCATION
  free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
}
#endif /* OC_SECURITY */

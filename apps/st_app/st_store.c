/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "st_store.h"
#include "oc_rep.h"
#include "port/oc_storage.h"
#include "st_easy_setup.h"
#include "st_port.h"
#include "util/oc_mem.h"

#define SVR_TAG_MAX (32)
#define ST_MAX_DATA_SIZE (1024)
#define ST_STORE_NAME "st_info"

// static void
// gen_svr_tag(const char *name, char *svr_tag)
// {
//   int svr_tag_len = snprintf(svr_tag, SVR_TAG_MAX, "%s", name);
//   svr_tag_len = (svr_tag_len < SVR_TAG_MAX) ? svr_tag_len + 1 : SVR_TAG_MAX;
//   svr_tag[svr_tag_len] = '\0';
// }

int
st_load(void)
{
  int ret = 0;
  oc_rep_t *rep;

#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf) {
    st_print_log("[ST_Store] alloc failed!");
    return -1;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */
  long size = 0;
#ifdef OC_SECURITY
  size = oc_storage_read(ST_STORE_NAME, buf, ST_MAX_DATA_SIZE);
#endif
  if (size > 0) {
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
    oc_parse_rep(buf, (uint16_t)size, &rep);
    ret = st_decode_store_info(rep);
    oc_free_rep(rep);
  } else {
    st_set_default_store_info();
  }
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */

  return ret;
}

void
st_dump(void)
{
#ifdef OC_SECURITY
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buf = oc_mem_malloc(ST_MAX_DATA_SIZE);
  if (!buf)
    return;
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buf[ST_MAX_DATA_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  oc_rep_new(buf, ST_MAX_DATA_SIZE);
  // TODO : encode
  st_encode_store_info();
  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("[ST_Store] encoded info size %d", size);
    oc_storage_write(ST_STORE_NAME, buf, size);
  }
  OC_LOGbytes(buf, size);
#ifdef OC_DYNAMIC_ALLOCATION
  oc_mem_free(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
#endif /* OC_SECURITY */
}
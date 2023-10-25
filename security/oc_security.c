/******************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifdef OC_SECURITY

#include "oc_acl.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_helpers.h"
#include "oc_store.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "security/oc_acl_internal.h"
#include "security/oc_ael_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_doxm_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_sdi_internal.h"
#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <mbedtls/build_info.h>
#include <mbedtls/debug.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>

#ifndef OC_DYNAMIC_ALLOCATION
#define MBEDTLS_ALLOC_BUF_SIZE (20000)
static unsigned char g_alloc_buf[MBEDTLS_ALLOC_BUF_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

#if defined(_WIN32) || defined(_WIN64)
#include <mbedtls/platform.h>
#endif /* WIN32 || _WIN64  */

#include <time.h>

void
oc_mbedtls_init(void)
{
#ifndef OC_DYNAMIC_ALLOCATION
  mbedtls_memory_buffer_alloc_init(g_alloc_buf, sizeof(g_alloc_buf));
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef OC_DEBUG
#if defined(_WIN32) || defined(_WIN64)
  // mbedtls debug logs fail if snprintf is not specified
  mbedtls_platform_set_snprintf(snprintf);
#endif /* _WIN32 or _WIN64 */
  mbedtls_debug_set_threshold(4);
#endif /* OC_DEBUG */
}

int
oc_sec_self_own(size_t device)
{
  OC_DBG("performing self-onboarding of device(%zu)", device);
  const oc_uuid_t *uuid = oc_core_get_device_id(device);
  if (uuid == NULL) {
    return -1;
  }

  oc_sec_acl_t *acl = oc_sec_get_acl(device);
  memcpy(acl->rowneruuid.id, uuid->id, sizeof(uuid->id));

  oc_sec_doxm_t *doxm = oc_sec_get_doxm(device);
  memcpy(doxm->devowneruuid.id, uuid->id, sizeof(uuid->id));
  memcpy(doxm->deviceuuid.id, uuid->id, sizeof(uuid->id));
  memcpy(doxm->rowneruuid.id, uuid->id, sizeof(uuid->id));
  doxm->owned = true;
  doxm->oxmsel = 0;

  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  memcpy(creds->rowneruuid.id, uuid->id, sizeof(uuid->id));

  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  memcpy(ps->rowneruuid.id, uuid->id, sizeof(uuid->id));
  ps->tm = 0;
  ps->cm = 0;
  ps->isop = true;
  ps->s = OC_DOS_RFNOP;

  oc_sec_acl_add_bootstrap_acl(device);

  oc_sec_sdi_t *sdi = oc_sec_sdi_get(device);
  const oc_device_info_t *self = oc_core_get_device_info(device);
  oc_gen_uuid(&sdi->uuid);
  oc_set_string(&sdi->name, oc_string(self->name), oc_string_len(self->name));
  sdi->priv = false;

  oc_sec_dump_pstat(device);
  oc_sec_dump_doxm(device);
  oc_sec_dump_cred(device);
  oc_sec_dump_acl(device);
  oc_sec_dump_ael(device);
  oc_sec_dump_sdi(device);

  return 0;
}

void
oc_sec_self_disown(size_t device)
{
  oc_sec_sdi_default(device);

  oc_sec_pstat_t *ps = oc_sec_get_pstat(device);
  oc_sec_pstat_clear(ps, true);
  oc_sec_dump_pstat(device);

  oc_sec_cred_default(device);
  oc_sec_doxm_default(device);
  oc_sec_ael_default(device);
  oc_sec_acl_default(device);
}

#ifdef OC_HAS_FEATURE_PLGD_TIME

void
oc_mbedtls_platform_time_init(void)
{
  mbedtls_platform_set_time(oc_mbedtls_platform_time);
}

void
oc_mbedtls_platform_time_deinit(void)
{
  mbedtls_platform_set_time(MBEDTLS_PLATFORM_STD_TIME);
}

mbedtls_time_t
oc_mbedtls_platform_time(mbedtls_time_t *timer)
{
  if (!plgd_time_is_active()) {
    return MBEDTLS_PLATFORM_STD_TIME(timer);
  }

  unsigned long ct = plgd_time_seconds();
  if (ct == (unsigned long)-1) {
    return -1;
  }
  mbedtls_time_t t = (mbedtls_time_t)ct;
  if (timer != NULL) {
    *timer = t;
  }
  return t;
}

#endif /* OC_HAS_FEATURE_PLGD_TIME */

#endif /* OC_SECURITY */

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

#include "plgd_dps_apis_internal.h"
#include "plgd_dps_log_internal.h"
#include "plgd_dps_tag_internal.h"

#include "oc_acl.h"
#include "oc_cred.h"

static bool
dps_has_tag(oc_string_t value, const char *tag, size_t taglen)
{
  return oc_string_len(value) == taglen && (strcmp(oc_string(value), tag) == 0);
}

void
dps_acls_set_stale_tag(size_t device)
{
  DPS_DBG("adding tags to acls:");
  oc_sec_ace_t *ace = oc_list_head(oc_sec_get_acl(device)->subjects);
  for (; ace != NULL; ace = ace->next) {
    if (dps_has_tag(ace->tag, DPS_TAG, DPS_TAG_LEN)) {
      DPS_DBG("\ttag(%s) added to aceid=%d", DPS_STALE_TAG, ace->aceid);
      oc_set_string(&ace->tag, DPS_STALE_TAG, DPS_STALE_TAG_LEN);
      continue;
    }
  }
}

void
dps_acls_remove_stale_tag(size_t device)
{
  DPS_DBG("removing tags from acls");
  oc_sec_ace_t *ace = oc_list_head(oc_sec_get_acl(device)->subjects);
  for (; ace != NULL; ace = ace->next) {
    if (dps_has_tag(ace->tag, DPS_STALE_TAG, DPS_STALE_TAG_LEN)) {
      DPS_DBG("\ttag(%s) removed from aceid=%d", DPS_STALE_TAG, ace->aceid);
      oc_set_string(&ace->tag, DPS_TAG, DPS_TAG_LEN);
      continue;
    }
  }
}

void
dps_credentials_set_stale_tag(size_t device)
{
  DPS_DBG("adding stale tag to credentials:");
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *cred = (oc_sec_cred_t *)oc_list_head(creds->creds);
  for (; cred != NULL; cred = cred->next) {
    if (dps_has_tag(cred->tag, DPS_TAG, DPS_TAG_LEN)) {
      DPS_DBG("\ttag(%s) added to credid=%d", DPS_STALE_TAG, cred->credid);
      oc_set_string(&cred->tag, DPS_STALE_TAG, DPS_STALE_TAG_LEN);
      continue;
    }
  }
}

void
dps_credentials_remove_stale_tag(size_t device)
{
  DPS_DBG("removing stale tag from credentials");
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *cred = (oc_sec_cred_t *)oc_list_head(creds->creds);
  for (; cred != NULL; cred = cred->next) {
    if (dps_has_tag(cred->tag, DPS_STALE_TAG, DPS_STALE_TAG_LEN)) {
      DPS_DBG("\ttag(%s) removed from credid=%d", DPS_STALE_TAG, cred->credid);
      oc_set_string(&cred->tag, DPS_TAG, DPS_TAG_LEN);
      continue;
    }
  }
}

void
dps_remove_stale_acls(size_t device)
{
  DPS_DBG("removing tagged acls:");
  oc_sec_ace_t *ace = oc_list_head(oc_sec_get_acl(device)->subjects);
  while (ace != NULL) {
    oc_sec_ace_t *next = ace->next;
    if (dps_has_tag(ace->tag, DPS_STALE_TAG, DPS_STALE_TAG_LEN)) {
      DPS_DBG("\tstale aceid=%d removed", ace->aceid);
      oc_sec_remove_ace(ace, device);
    }
    ace = next;
  }
}

int
dps_remove_stale_credentials(size_t device)
{
  DPS_DBG("removing stale credentials:");
  int count = 0;
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *cred = (oc_sec_cred_t *)oc_list_head(creds->creds);
  while (cred != NULL) {
    oc_sec_cred_t *next = cred->next;
    if (dps_has_tag(cred->tag, DPS_STALE_TAG, DPS_STALE_TAG_LEN)) {
      DPS_DBG("\tstale credid=%d removed", cred->credid);
      oc_sec_remove_cred(cred, device);
      ++count;
    }
    cred = next;
  }
  return count;
}

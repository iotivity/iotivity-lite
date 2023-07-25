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

#include "api/oc_core_res_internal.h"
#include "oc_acl_internal.h"
#include "oc_ael_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_csr_internal.h"
#include "oc_csr.h"
#include "oc_doxm_internal.h"
#include "oc_pstat_internal.h"
#include "oc_ri.h"
#include "oc_roles_internal.h"
#include "oc_sdi_internal.h"
#include "oc_sp_internal.h"
#include "oc_svr_internal.h"
#include "port/oc_log_internal.h"

void
oc_sec_svr_create(void)
{
  oc_sec_doxm_init();
  oc_sec_pstat_init();
  oc_sec_acl_init();
  oc_sec_cred_init();
  oc_sec_ael_init();
  oc_sec_sp_init();
  oc_sec_sdi_init();

  for (size_t i = 0; i < oc_core_get_num_devices(); i++) {
    oc_sec_doxm_create_resource(i);
    oc_core_populate_resource(OCF_SEC_PSTAT, i, "/oic/sec/pstat",
                              OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                              OC_DISCOVERABLE | OC_OBSERVABLE, get_pstat, 0,
                              post_pstat, 0, 1, "oic.r.pstat");
    oc_core_populate_resource(OCF_SEC_ACL, i, "/oic/sec/acl2",
                              OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                              OC_DISCOVERABLE | OC_SECURE, get_acl, 0, post_acl,
                              delete_acl, 1, "oic.r.acl2");
    oc_sec_cred_create_resource(i);
    oc_core_populate_resource(
      OCF_SEC_AEL, i, "/oic/sec/ael", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_SECURE, get_ael, 0, post_ael, 0, 1, "oic.r.ael");

    oc_sec_sp_create_resource(i);
    oc_sec_sdi_create_resource(i);
#ifdef OC_PKI
    oc_sec_csr_create_resource(i);
    oc_sec_roles_create_resource(i);
#endif /* OC_PKI */
  }
}

void
oc_sec_svr_free(void)
{
  oc_sec_sdi_free();
  oc_sec_sp_free();
  oc_sec_ael_free();
  oc_sec_cred_free();
  oc_sec_acl_free();
  oc_sec_pstat_free();
  oc_sec_doxm_free();
}

#endif /* OC_SECURITY */

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

#include "oc_svr_internal.h"
#include "api/oc_core_res_internal.h"
#include "oc_acl_internal.h"
#include "oc_ael.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred_internal.h"
#include "oc_csr_internal.h"
#include "oc_csr.h"
#include "oc_doxm_internal.h"
#include "oc_pstat.h"
#include "oc_ri.h"
#include "oc_sdi_internal.h"
#include "oc_sp_internal.h"
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
    oc_core_populate_resource(
      OCF_SEC_DOXM, i, "/oic/sec/doxm", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE, get_doxm, 0, post_doxm, 0, 1, "oic.r.doxm");
    oc_core_populate_resource(OCF_SEC_PSTAT, i, "/oic/sec/pstat",
                              OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                              OC_DISCOVERABLE | OC_OBSERVABLE, get_pstat, 0,
                              post_pstat, 0, 1, "oic.r.pstat");
    oc_core_populate_resource(OCF_SEC_ACL, i, "/oic/sec/acl2",
                              OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                              OC_DISCOVERABLE | OC_SECURE, get_acl, 0, post_acl,
                              delete_acl, 1, "oic.r.acl2");
    oc_core_populate_resource(OCF_SEC_CRED, i, "/oic/sec/cred",
                              OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                              OC_DISCOVERABLE | OC_SECURE, get_cred, 0,
                              post_cred, delete_cred, 1, "oic.r.cred");
    oc_core_populate_resource(
      OCF_SEC_AEL, i, "/oic/sec/ael", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_SECURE, get_ael, 0, post_ael, 0, 1, "oic.r.ael");

    oc_sec_sp_create_resource(i);
    oc_sec_sdi_create_resource(i);
#ifdef OC_PKI
    oc_sec_csr_create_resource(i);

    oc_core_populate_resource(OCF_SEC_ROLES, i, "/oic/sec/roles",
                              OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
                              OC_DISCOVERABLE | OC_SECURE, get_cred, 0,
                              post_cred, delete_cred, 1, "oic.r.roles");
#endif /* OC_PKI */
  }
}


/*
 * modifiedbyme <2023/7/28> add func : oc_sec_svr_create_new_devicee(){}
 */
#ifdef OC_HAS_FEATURE_BRIDGE
void
oc_sec_svr_create_new_device(void)
{
  oc_sec_doxm_new_device();
  oc_sec_pstat_new_device();
  oc_sec_acl_new_device();
  oc_sec_cred_new_device();
  oc_sec_ael_new_device();
  oc_sec_sp_new_device();
  oc_sec_sdi_new_device();

  oc_core_populate_resource(
      OCF_SEC_DOXM, oc_core_get_num_devices()-1, "/oic/sec/doxm", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE, get_doxm, 0, post_doxm, 0, 1, "oic.r.doxm");
  oc_core_populate_resource(OCF_SEC_PSTAT, oc_core_get_num_devices()-1, "/oic/sec/pstat",
      OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_OBSERVABLE, get_pstat, 0,
      post_pstat, 0, 1, "oic.r.pstat");
  oc_core_populate_resource(OCF_SEC_ACL, oc_core_get_num_devices()-1, "/oic/sec/acl2",
      OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_SECURE, get_acl, 0, post_acl,
      delete_acl, 1, "oic.r.acl2");
  oc_core_populate_resource(OCF_SEC_CRED, oc_core_get_num_devices()-1, "/oic/sec/cred",
      OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_SECURE, get_cred, 0,
      post_cred, delete_cred, 1, "oic.r.cred");
  oc_core_populate_resource(
      OCF_SEC_AEL, oc_core_get_num_devices()-1, "/oic/sec/ael", OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_SECURE, get_ael, 0, post_ael, 0, 1, "oic.r.ael");

  oc_sec_sp_create_resource(oc_core_get_num_devices()-1);
  oc_sec_sdi_create_resource(oc_core_get_num_devices()-1);
#ifdef OC_PKI
  oc_sec_csr_create_resource(oc_core_get_num_devices()-1);

  oc_core_populate_resource(OCF_SEC_ROLES, oc_core_get_num_devices()-1, "/oic/sec/roles",
      OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
      OC_DISCOVERABLE | OC_SECURE, get_cred, 0,
      post_cred, delete_cred, 1, "oic.r.roles");
#endif /* OC_PKI */

}


/*
 * modifiedbyme <2023/8/8> add func : oc_sec_svr_init_new_devicee(){}
 */
void
oc_sec_svr_init_new_device(size_t device_index)
{
//  oc_sec_svr_create_new_device();
  oc_sec_load_unique_ids(device_index);
  OC_DBG("oc_main_init(): loading pstat(%zu)", device_index);
  oc_sec_load_pstat(device_index);
  OC_DBG("oc_main_init(): loading doxm(%zu)", device_index);
  oc_sec_load_doxm(device_index);
  OC_DBG("oc_main_init(): loading cred(%zu)", device_index);
  oc_sec_load_cred(device_index);
  OC_DBG("oc_main_init(): loading acl(%zu)", device_index);
  oc_sec_load_acl(device_index);
  OC_DBG("oc_main_init(): loading sp(%zu)", device_index);
  oc_sec_load_sp(device_index);
  OC_DBG("oc_main_init(): loading ael(%zu)", device_index);
  oc_sec_load_ael(device_index);
#ifdef OC_PKI
  OC_DBG("oc_main_init(): loading ECDSA keypair(%zu)", device_index);
  oc_sec_load_ecdsa_keypair(device_index);
#endif /* OC_PKI */
  OC_DBG("oc_main_init(): loading sdi(%zu)", device_index);
  oc_sec_load_sdi(device_index);
}

#endif /* OC_HAS_FEATURE_BRIDGE */



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

/*
// Copyright (c) 2019 Intel Corporation
//
// Li!censed under the Apache License, Version 2.0 (the "License");
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
#ifdef OC_PKI
#ifndef OC_DYNAMIC_ALLOCATION
#error "ERROR: Please rebuild with OC_DYNAMIC_ALLOCATION"
#endif /* !OC_DYNAMIC_ALLOCATION */

#include "oc_core_res.h"
#include "security/oc_cred.h"
#include "security/oc_obt_otm_internal.h"

/* Manufacturer certificate-based ownership transfer */
/*
  OTM sequence:
  1) get /oic/d
  2) post doxm oxmsel=2
  3) <Open-TLS_ECDSA_with_Mfg_Cert>+post pstat om=4
  4) post doxm devowneruuid
  5) generate random deviceuuid; <store new peer uuid>; post doxm deviceuuid
  6) post doxm rowneruuid
  7) post acl rowneruuid
  8) post pstat rowneruuid
  9) post cred rowneruuid, cred
  10) post doxm owned = true
  11) <close DTLS>+<Open-TLS-PSK>+post pstat s=rfpro
  12) delete acl2
  13) post acl2 with ACEs for res, p, d, csr, sp
  14) post pstat s=rfnop
  15) <close DTLS>
*/
int
oc_obt_perform_cert_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                        void *data)
{
  OC_DBG("In oc_obt_perform_just_works_otm");

  oc_device_t *device = oc_obt_get_cached_device_handle(uuid);
  if (!device) {
    return -1;
  }

  if (oc_obt_is_owned_device(uuid)) {
    char subjectuuid[OC_UUID_LEN];
    oc_uuid_to_str(uuid, subjectuuid, OC_UUID_LEN);
    oc_cred_remove_subject(subjectuuid, 0);
  }

  oc_otm_ctx_t *o = oc_obt_alloc_otm_ctx();
  if (!o) {
    return -1;
  }

  o->cb.cb = cb;
  o->cb.data = data;
  o->device = device;
  o->otm = OC_OBT_OTM_CERT;

  /**  1) get /oic/d
   */
  oc_endpoint_t *ep = oc_obt_get_unsecure_endpoint(device->endpoint);
  if (oc_do_get("/oic/d", ep, NULL,
                &oc_obt_otm_set_doxm_oxmsel, HIGH_QOS, o)) {
    oc_set_delayed_callback(o, oc_obt_otm_request_timeout_cb, OBT_CB_TIMEOUT);
    return 0;
  }

  oc_obt_free_otm_ctx(o, -1);

  return -1;
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

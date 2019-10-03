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
#ifndef OC_DYNAMIC_ALLOCATION
#error "ERROR: Please rebuild with OC_DYNAMIC_ALLOCATION"
#endif /* !OC_DYNAMIC_ALLOCATION */

#include "oc_core_res.h"
#include "security/oc_cred.h"
#include "security/oc_doxm.h"
#include "security/oc_tls.h"
#include "security/oc_obt_otm_internal.h"

/* Random PIN OTM */
/*
  OTM sequence:
  1) provision PSK cred locally+<Open-TLS-PSK>+get /oic/d
  2) post pstat om=4
  3) post doxm devowneruuid
  4) generate random deviceuuid; <store new peer uuid>; post doxm deviceuuid
  5) post doxm rowneruuid
  6) post acl rowneruuid
  7) post pstat rowneruuid
  8) post cred rowneruuid, cred
  9) post doxm owned = true
  10) <close DTLS>+<Open-TLS-PSK>+post pstat s=rfpro
  11) delete acl2
  12) post acl2 with ACEs for res, p, d, csr, sp
  13) post pstat s=rfnop
  14) <close DTLS>
*/
int
oc_obt_perform_random_pin_otm(oc_uuid_t *uuid, const unsigned char *pin,
                              size_t pin_len, oc_obt_device_status_cb_t cb,
                              void *data)
{
  OC_DBG("In oc_obt_perform_random_pin_otm");

  oc_device_t *device = oc_obt_get_cached_device_handle(uuid);
  if (!device) {
    return -1;
  }

  if (oc_obt_is_owned_device(uuid)) {
    char subjectuuid[OC_UUID_LEN];
    oc_uuid_to_str(uuid, subjectuuid, OC_UUID_LEN);
    oc_cred_remove_subject(subjectuuid, 0);
  }

  uint8_t key[16];
  if (oc_tls_pbkdf2(pin, pin_len, uuid, 1000, key, 16) != 0) {
    return -1;
  }

  oc_otm_ctx_t *o = oc_obt_alloc_otm_ctx();
  if (!o) {
    return -1;
  }

  o->otm = OC_OBT_OTM_RDP;

  char subjectuuid[37];
  oc_uuid_to_str(uuid, subjectuuid, 37);

  /* 1) provision PSK cred locally */

  int credid = oc_sec_add_new_cred(
    0, false, NULL, -1, OC_CREDTYPE_PSK, OC_CREDUSAGE_NULL, subjectuuid,
    OC_ENCODING_RAW, 16, key, 0, 0, NULL, NULL, NULL);

  if (credid == -1) {
    oc_obt_free_otm_ctx(o, -1);
    return -1;
  }

  o->cb.cb = cb;
  o->cb.data = data;
  o->device = device;

  /**  1) <Open-TLS-PSK>+get /oic/d
   */
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_tls_close_connection(ep);
  oc_tls_select_psk_ciphersuite();
  if (oc_do_get("/oic/d", ep, NULL,
                &oc_obt_otm_set_pstat_om, HIGH_QOS, o)) {
    oc_set_delayed_callback(o, oc_obt_otm_request_timeout_cb, OBT_CB_TIMEOUT);
    return 0;
  }

  oc_sec_cred_t *c = oc_sec_get_cred_by_credid(credid, 0);
  if (c) {
    oc_sec_remove_cred(c, 0);
  }

  oc_obt_free_otm_ctx(o, -1);

  return -1;
}

/* Request a peer device to generate and display a Random PIN */

static void
obt_rrdp_2(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_rrdp_2");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_rrdp_2;
  }

  oc_obt_free_otm_ctx(o, 0);
  return;

err_obt_rrdp_2:
  oc_obt_free_otm_ctx(o, -1);
}

/*
  Sequence:
  1) post doxm oxmsel=1
  2) success/fail
*/
int
oc_obt_request_random_pin(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                          void *data)
{
  OC_DBG("In oc_obt_request_random_pin");

  if (oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  oc_device_t *device = oc_obt_get_cached_device_handle(uuid);
  if (!device) {
    return -1;
  }

  oc_otm_ctx_t *o = oc_obt_alloc_otm_ctx();
  if (!o) {
    return -1;
  }

  o->cb.cb = cb;
  o->cb.data = data;
  o->device = device;
  o->otm = OC_OBT_RDP;

  /**  1) post doxm oxmsel=1
   */
  oc_endpoint_t *ep = oc_obt_get_unsecure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_rrdp_2, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_int(root, oxmsel, OC_OXMTYPE_RDP);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      oc_set_delayed_callback(o, oc_obt_otm_request_timeout_cb, OBT_CB_TIMEOUT);
      return 0;
    }
  }

  oc_obt_free_otm_ctx(o, -1);

  return -1;
}

#endif /* OC_SECURITY */

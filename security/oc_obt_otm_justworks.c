/*
// Copyright (c) 2017-2019 Intel Corporation
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
#include "oc_obt.h"
#include "security/oc_acl.h"
#include "security/oc_cred.h"
#include "security/oc_doxm.h"
#include "security/oc_obt_internal.h"
#include "security/oc_pstat.h"
#include "security/oc_store.h"
#include "security/oc_tls.h"

/* Just-works ownership transfer */
static void
obt_jw_12(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_12");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
    return;
  }

  /**  12) <close DTLS>
   */
  oc_dostype_t s = oc_obt_parse_dos(data->payload);
  if (s == OC_DOS_RFNOP) {
    oc_obt_free_otm_ctx(o, 0, OC_OBT_OTM_JW);
  } else {
    oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
  }
}

static void
obt_jw_11(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_11");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_11;
  }

  /**  11) <close DTLS> ; <tls psk> ; get pstat s=rfnop?
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);

  oc_tls_close_connection(ep);

  if (oc_do_get("/oic/sec/pstat", ep, NULL, &obt_jw_12, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_11:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_10(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_10");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_10;
  }

  oc_dostype_t s = oc_obt_parse_dos(data->payload);
  if (s == OC_DOS_RFPRO) {
    /**  10) post pstat s=rfnop, isop=true
     */
    oc_device_t *device = o->device;
    oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_11, HIGH_QOS, o)) {
      oc_rep_start_root_object();
      oc_rep_set_object(root, dos);
      oc_rep_set_int(dos, s, OC_DOS_RFNOP);
      oc_rep_close_object(root, dos);
      oc_rep_end_root_object();
      if (oc_do_post()) {
        return;
      }
    }
  }

err_obt_jw_10:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_9(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_9");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_9;
  }

  /**  9) get pstat s=rfpro?
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/pstat", ep, NULL, &obt_jw_10, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_9:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_8(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_8");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_8;
  }

  /**  8) post pstat s=rfpro
    */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_9, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RFPRO);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_8:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_7(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_7");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_7;
  }

  /**  7) post doxm owned = true
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_jw_8, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, owned, true);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_7:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_6(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_6");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_6;
  }

  oc_sec_dump_cred(0);

  /**  6) post pstat rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_7, HIGH_QOS, o)) {
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_6:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_5(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_5");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_5;
  }

  oc_device_t *device = o->device;

  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);
  char suuid[OC_UUID_LEN];
  oc_uuid_to_str(&device->uuid, suuid, OC_UUID_LEN);

#define OXM_JUST_WORKS "oic.sec.doxm.jw"
  uint8_t key[16];
  bool derived = oc_sec_derive_owner_psk(
    ep, (const uint8_t *)OXM_JUST_WORKS, strlen(OXM_JUST_WORKS),
    device->uuid.id, 16, my_uuid->id, 16, key, 16);
#undef OXM_JUST_WORKS
  if (!derived) {
    goto err_obt_jw_5;
  }

  int credid = oc_sec_add_new_cred(0, false, NULL, -1, OC_CREDTYPE_PSK,
                                   OC_CREDUSAGE_NULL, suuid, OC_ENCODING_RAW,
                                   16, key, 0, 0, NULL, NULL, NULL);

  if (credid == -1) {
    goto err_obt_jw_5;
  }

  /**  5) post cred rowneruuid, cred
   */
  if (oc_init_post("/oic/sec/cred", ep, NULL, &obt_jw_6, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_array(root, creds);
    oc_rep_object_array_start_item(creds);

    oc_rep_set_int(creds, credtype, 1);
    oc_rep_set_text_string(creds, subjectuuid, uuid);

    oc_rep_set_object(creds, privatedata);
    oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
    oc_rep_close_object(creds, privatedata);

    oc_rep_object_array_end_item(creds);
    oc_rep_close_array(root, creds);
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_5:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_4(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_4");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_4;
  }

  oc_uuid_t peer;
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_string_len(rep->name) == 10 &&
          memcmp(oc_string(rep->name), "deviceuuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &peer);
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  /**  4) <store peer uuid> ; post acl rowneruuid
   */
  oc_device_t *device = o->device;

  /* Store peer device's now fixed uuid in local device object */
  memcpy(device->uuid.id, peer.id, 16);
  oc_endpoint_t *ep = device->endpoint;
  while (ep) {
    memcpy(ep->di.id, peer.id, 16);
    ep = ep->next;
  }

  ep = oc_obt_get_secure_endpoint(device->endpoint);

  if (oc_init_post("/oic/sec/acl2", ep, NULL, &obt_jw_5, HIGH_QOS, o)) {
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_4:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_3(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_3");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_3;
  }

  /**  3) get doxm
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/doxm", ep, NULL, &obt_jw_4, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_3:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

static void
obt_jw_2(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_2");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_2;
  }

  oc_dostype_t s = oc_obt_parse_dos(data->payload);
  if (s == OC_DOS_RFOTM) {
    /**  2) post doxm oxmsel=0, rowneruuid, devowneruuid
     */
    oc_device_t *device = o->device;
    oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_jw_3, HIGH_QOS, o)) {
      oc_uuid_t *my_uuid = oc_core_get_device_id(0);
      char uuid[OC_UUID_LEN];
      oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);

      oc_rep_start_root_object();
      oc_rep_set_int(root, oxmsel, 0);
      /* Set OBT's uuid as rowneruuid */
      oc_rep_set_text_string(root, rowneruuid, uuid);
      /* Set OBT's uuid as devowneruuid */
      oc_rep_set_text_string(root, devowneruuid, uuid);
      oc_rep_end_root_object();
      if (oc_do_post()) {
        return;
      }
    }
  }

err_obt_jw_2:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);
}

/*
  OTM sequence:
  1) <anon ecdh>+get pstat s=rfotm?
  2) post doxm oxmsel=0, rowneruuid, devowneruuid
  3) get doxm
  4) <store peer uuid> ; post acl rowneruuid
  5) post cred rowneruuid, cred
  6) post pstat rowneruuid
  7) post doxm owned = true
  8) post pstat s=rfpro
  9) get pstat s=rfpro?
  10) post pstat s=rfnop, isop=true
  11) <close DTLS> ; <tls psk> ; get pstat s=rfnop?
  12) <close DTLS>
*/
int
oc_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                              void *data)
{
  OC_DBG("In oc_obt_perform_just_works_otm");

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

  /**  1) <anon ecdh>+get pstat s=rfotm?
   */

  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/pstat", ep, NULL, &obt_jw_2, HIGH_QOS, o)) {
    oc_set_delayed_callback(o, oc_obt_otm_request_timeout_cb, OBT_CB_TIMEOUT);
    return 0;
  }

  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_JW);

  return -1;
}

#endif /* OC_SECURITY */

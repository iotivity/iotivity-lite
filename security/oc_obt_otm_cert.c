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
#include "oc_obt.h"
#include "security/oc_acl_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_doxm.h"
#include "security/oc_obt_internal.h"
#include "security/oc_pstat.h"
#include "security/oc_sdi.h"
#include "security/oc_store.h"
#include "security/oc_tls.h"

/* Manufacturer certificate-based ownership transfer */
static void
obt_cert_16(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_16");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
    return;
  }

  /**  16) <close DTLS>
   */
  oc_obt_free_otm_ctx(o, 0, OC_OBT_OTM_CERT);
}

static void
obt_cert_15(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_15");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_15;
  }

  /**  15) post pstat s=rfnop
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_cert_16, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RFNOP);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_15:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_14(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_14");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_14;
  }

  /**  14) post acl2 with ACEs for res, p, d, csr, sp
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/acl2", ep, NULL, &obt_cert_15, HIGH_QOS, o)) {
    char uuid[OC_UUID_LEN];
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);

    oc_rep_start_root_object();

    oc_rep_set_array(root, aclist2);

    /* Owner-subejct ACEs for (R-only) /oic/sec/csr and (RW) /oic/sec/sp */
    oc_rep_object_array_start_item(aclist2);

    oc_rep_set_object(aclist2, subject);
    oc_rep_set_text_string(subject, uuid, uuid);
    oc_rep_close_object(aclist2, subject);

    oc_rep_set_array(aclist2, resources);

    oc_rep_object_array_start_item(resources);
    oc_rep_set_text_string(resources, href, "/oic/sec/sp");
    oc_rep_object_array_end_item(resources);

    oc_rep_close_array(aclist2, resources);

    oc_rep_set_uint(aclist2, permission, 14);

    oc_rep_object_array_end_item(aclist2);
    /**/
    oc_rep_object_array_start_item(aclist2);

    oc_rep_set_object(aclist2, subject);
    oc_rep_set_text_string(subject, uuid, uuid);
    oc_rep_close_object(aclist2, subject);

    oc_rep_set_array(aclist2, resources);

    oc_rep_object_array_start_item(resources);
    oc_rep_set_text_string(resources, href, "/oic/sec/csr");
    oc_rep_object_array_end_item(resources);

    oc_rep_close_array(aclist2, resources);

    oc_rep_set_uint(aclist2, permission, 2);

    oc_rep_object_array_end_item(aclist2);

    /* anon-clear R-only ACE for res, d and p */
    oc_rep_object_array_start_item(aclist2);

    oc_rep_set_object(aclist2, subject);
    oc_rep_set_text_string(subject, conntype, "anon-clear");
    oc_rep_close_object(aclist2, subject);

    oc_rep_set_array(aclist2, resources);

    oc_rep_object_array_start_item(resources);
    oc_rep_set_text_string(resources, href, "/oic/d");
    oc_rep_object_array_end_item(resources);

    oc_rep_object_array_start_item(resources);
    oc_rep_set_text_string(resources, href, "/oic/p");
    oc_rep_object_array_end_item(resources);

    oc_rep_object_array_start_item(resources);
    oc_rep_set_text_string(resources, href, "/oic/res");
    oc_rep_object_array_end_item(resources);

    if (o->sdi) {
      oc_rep_object_array_start_item(resources);
      oc_rep_set_text_string(resources, href, "/oic/sec/sdi");
      oc_rep_object_array_end_item(resources);
    }

    oc_rep_close_array(aclist2, resources);

    oc_rep_set_uint(aclist2, permission, 0x02);

    oc_rep_object_array_end_item(aclist2);

    oc_rep_close_array(root, aclist2);

    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_14:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_13(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_13");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_13;
  }

  /**  13) delete acl2
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_do_delete("/oic/sec/acl2", ep, NULL, &obt_cert_14, HIGH_QOS, o)) {
    return;
  }

err_obt_cert_13:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_12(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_12");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_12;
  }

  /**  12) <close DTLS>+<Open-TLS-PSK>+ post pstat s=rfpro
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_tls_close_connection(ep);
  oc_tls_select_psk_ciphersuite();
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_cert_13, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RFPRO);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_12:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_11(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_11");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  o->sdi = true;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    if (data->code != OC_STATUS_NOT_FOUND) {
      goto err_obt_cert_11;
    } else {
      o->sdi = false;
    }
  }

  oc_sec_dump_cred(0);

  /**  11) post doxm owned = true
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_cert_12, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, owned, true);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_11:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_10(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_10");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_10;
  }

  oc_sec_sdi_t *sdi = oc_sec_get_sdi(0);
  char sdi_uuid[OC_UUID_LEN];
  oc_uuid_to_str(&sdi->uuid, sdi_uuid, OC_UUID_LEN);

  /**  10) post sdi
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/sdi", ep, NULL, &obt_cert_11, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, uuid, sdi_uuid);
    oc_rep_set_text_string(root, name, oc_string(sdi->name));
    oc_rep_set_boolean(root, priv, sdi->priv);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_10:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_9(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_9");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_9;
  }

  oc_device_t *device = o->device;

  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);
  char suuid[OC_UUID_LEN];
  oc_uuid_to_str(&device->uuid, suuid, OC_UUID_LEN);

#define OXM_MFG_CERT "oic.sec.doxm.mfgcert"
  uint8_t key[16];
  bool derived = oc_sec_derive_owner_psk(ep, (const uint8_t *)OXM_MFG_CERT,
                                         strlen(OXM_MFG_CERT), device->uuid.id,
                                         16, my_uuid->id, 16, key, 16);
#undef OXM_MFG_CERT
  if (!derived) {
    goto err_obt_cert_9;
  }

  int credid = oc_sec_add_new_cred(0, false, NULL, -1, OC_CREDTYPE_PSK,
                                   OC_CREDUSAGE_NULL, suuid, OC_ENCODING_RAW,
                                   16, key, 0, 0, NULL, NULL, NULL);

  if (credid == -1) {
    goto err_obt_cert_9;
  }

  oc_sec_cred_t *oc = oc_sec_get_cred_by_credid(credid, 0);
  if (oc) {
    oc->owner_cred = true;
  }

  /**  9) post cred rowneruuid, cred
   */
  if (oc_init_post("/oic/sec/cred", ep, NULL, &obt_cert_10, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_array(root, creds);
    oc_rep_object_array_start_item(creds);

    oc_rep_set_int(creds, credtype, 1);
    oc_rep_set_text_string(creds, subjectuuid, uuid);

    oc_rep_set_object(creds, privatedata);
    oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
    oc_rep_set_byte_string(privatedata, data, (const uint8_t *)"", 0);
    oc_rep_close_object(creds, privatedata);

    oc_rep_object_array_end_item(creds);
    oc_rep_close_array(root, creds);
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_9:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_8(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_8");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_8;
  }

  /**  8) post pstat rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_cert_9, HIGH_QOS, o)) {
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

err_obt_cert_8:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_7(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_7");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_7;
  }

  /**  7) post acl rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);

  if (oc_init_post("/oic/sec/acl2", ep, NULL, &obt_cert_8, HIGH_QOS, o)) {
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

err_obt_cert_7:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_6(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_6");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_6;
  }

  /**  6) post doxm rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);

  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_cert_7, HIGH_QOS, o)) {
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    /* Set OBT's uuid as rowneruuid */
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_6:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_5(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_5");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_5;
  }

  /** 5) generate random deviceuuid; <store new peer uuid>; post doxm deviceuuid
   */
  oc_uuid_t dev_uuid = { { 0 } };
  oc_gen_uuid(&dev_uuid);
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(&dev_uuid, uuid, OC_UUID_LEN);
  OC_DBG("generated deviceuuid: %s", uuid);

  oc_device_t *device = o->device;
  /* Store peer device's random uuid in local device object */
  memcpy(device->uuid.id, dev_uuid.id, 16);
  oc_endpoint_t *ep = device->endpoint;
  while (ep) {
    memcpy(ep->di.id, dev_uuid.id, 16);
    ep = ep->next;
  }

  ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_cert_6, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    /* Set random uuid as deviceuuid */
    oc_rep_set_text_string(root, deviceuuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_5:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_4(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_4");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_4;
  }

  /** 4) post doxm devowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_cert_5, HIGH_QOS, o)) {
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);

    oc_rep_start_root_object();
    /* Set OBT's uuid as devowneruuid */
    oc_rep_set_text_string(root, devowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_4:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_3(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_3");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_3;
  }

  /**  3) <Open-TLS_ECDSA_with_Mfg_Cert>+post pstat om=4
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_tls_close_connection(ep);
  oc_tls_select_cert_ciphersuite();
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_cert_4, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_int(root, om, 4);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_cert_3:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

static void
obt_cert_2(oc_client_response_t *data)
{
  if (!oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In obt_cert_2");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_cert_2;
  }

  int64_t *oxms = NULL;
  size_t oxms_len = 0;

  if (oc_rep_get_int_array(data->payload, "oxms", &oxms, &oxms_len)) {
    size_t i;
    for (i = 0; i < oxms_len; i++) {
      if (oxms[i] == OC_OXMTYPE_MFG_CERT) {
        break;
      }
    }

    if (i == oxms_len) {
      goto err_obt_cert_2;
    }

    /**  2) post doxm oxmsel=2
     */
    oc_device_t *device = o->device;
    oc_endpoint_t *ep = oc_obt_get_unsecure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_cert_3, HIGH_QOS, o)) {
      oc_rep_start_root_object();
      oc_rep_set_int(root, oxmsel, OC_OXMTYPE_MFG_CERT);
      oc_rep_end_root_object();
      if (oc_do_post()) {
        return;
      }
    }
  }

err_obt_cert_2:
  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);
}

/*
  OTM sequence:
  1) get doxm
  2) post doxm oxmsel=2
  3) <Open-TLS_ECDSA_with_Mfg_Cert>+post pstat om=4
  4) post doxm devowneruuid
  5) generate random deviceuuid; <store new peer uuid>; post doxm deviceuuid
  6) post doxm rowneruuid
  7) post acl rowneruuid
  8) post pstat rowneruuid
  9) post cred rowneruuid, cred
  10) post sdi
  11) post doxm owned = true
  12) <close DTLS>+<Open-TLS-PSK>+post pstat s=rfpro
  13) delete acl2
  14) post acl2 with ACEs for res, p, d, csr, sp
  15) post pstat s=rfnop
  16) <close DTLS>
*/
int
oc_obt_perform_cert_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                        void *data)
{
  OC_DBG("In oc_obt_perform_cert_otm");

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

  /**  1) get doxm
   */
  oc_endpoint_t *ep = oc_obt_get_unsecure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/doxm", ep, NULL, &obt_cert_2, HIGH_QOS, o)) {
    return 0;
  }

  oc_obt_free_otm_ctx(o, -1, OC_OBT_OTM_CERT);

  return -1;
}
#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

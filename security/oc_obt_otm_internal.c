/*
// Copyright (c) 2017-2019 Intel Corporation
// Copyright 2019 Samsung Electronics All Rights Reserved
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

#include "oc_core_res.h"
#include "security/oc_doxm.h"
#include "security/oc_store.h"
#include "security/oc_tls.h"
#include "security/oc_obt_internal.h"
#include "security/oc_obt_otm_internal.h"

static const char*
get_oxm_string(oc_obt_otm_t otm)
{
  static const char* s_oxm_strings[] = {
    "oic.sec.doxm.jw",
    "oic.sec.doxm.rdp",
    "oic.sec.doxm.mfgcert",
  };

  switch (otm)
  {
  case OC_OBT_OTM_JW:
    return s_oxm_strings[0];
  case OC_OBT_OTM_RDP:
    return s_oxm_strings[1];
  case OC_OBT_OTM_CERT:
    return s_oxm_strings[2];
  default:
    break;
  }
  return NULL;
}

static void
close_dtls(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In close_dtls");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  /**  <close DTLS>
   */
  oc_obt_free_otm_ctx(o, data->code >= OC_STATUS_BAD_REQUEST ? -1 : 0);
}

static void
post_pstat_dos_s_rfnop(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_pstat_dos_s_rfnop");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_pstat_dos_s_rfnop;
  }

  /**  post pstat s=rfnop
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &close_dtls, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RFNOP);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_post_pstat_dos_s_rfnop:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_acl2(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_acl2");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_acl2;
  }

  /**  post acl2 with ACEs for res, p, d, csr, sp
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/acl2", ep, NULL, &post_pstat_dos_s_rfnop, HIGH_QOS, o)) {
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

    oc_rep_close_array(aclist2, resources);

    oc_rep_set_uint(aclist2, permission, 0x02);

    oc_rep_object_array_end_item(aclist2);

    oc_rep_close_array(root, aclist2);

    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_post_acl2:
  oc_obt_free_otm_ctx(o, -1);
}

static void
delete_acl2(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In delete_acl2");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_delete_acl2;
  }

  /**  delete acl2
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_do_delete("/oic/sec/acl2", ep, NULL, &post_acl2, HIGH_QOS, o)) {
    return;
  }

err_delete_acl2:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_pstat_dos_s_rfpro(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_pstat_dos_s_rfpro");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_pstat_dos_s_rfpro;
  }

  /**  <close DTLS>+<Open-TLS-PSK>+post pstat s=rfpro
    */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_tls_close_connection(ep);
  oc_tls_select_psk_ciphersuite();
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &delete_acl2, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RFPRO);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_post_pstat_dos_s_rfpro:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_doxm_owned(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_doxm_owned");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_doxm_owned;
  }

  oc_sec_dump_cred(0);

  /**  post doxm owned = true
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &post_pstat_dos_s_rfpro, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, owned, true);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_post_doxm_owned:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_cred_creds_rowneruuid(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_cred_creds_rowneruuid");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_cred_creds_rowneruuid;
  }

  oc_device_t *device = o->device;

  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(my_uuid, uuid, OC_UUID_LEN);
  char suuid[OC_UUID_LEN];
  oc_uuid_to_str(&device->uuid, suuid, OC_UUID_LEN);

  const char* oxm_str = get_oxm_string(o->otm);
  uint8_t key[16];
  if (!oc_sec_derive_owner_psk(ep, (const uint8_t *)oxm_str, strlen(oxm_str),
                               device->uuid.id, 16, my_uuid->id, 16, key, 16)) {
    goto err_post_cred_creds_rowneruuid;
  }

  int credid = oc_sec_add_new_cred(0, false, NULL, -1, OC_CREDTYPE_PSK,
                                   OC_CREDUSAGE_NULL, suuid, OC_ENCODING_RAW,
                                   16, key, 0, 0, NULL, NULL, NULL);
  if (credid == -1) {
    goto err_post_cred_creds_rowneruuid;
  }

  oc_sec_cred_t *oc = oc_sec_get_cred_by_credid(credid, 0);
  if (oc) {
    oc->owner_cred = true;
  }

  /**  post cred rowneruuid, cred
   */
  if (oc_init_post("/oic/sec/cred", ep, NULL, &post_doxm_owned, HIGH_QOS, o)) {
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

err_post_cred_creds_rowneruuid:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_pstat_rowneruuid(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_pstat_rowneruuid");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_pstat_rowneruuid;
  }

  /**  post pstat rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &post_cred_creds_rowneruuid, HIGH_QOS, o)) {
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

err_post_pstat_rowneruuid:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_acl2_rowneruuid(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_acl2_rowneruuid");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_acl2_rowneruuid;
  }

  /**  post acl rowneruuid
  */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/acl2", ep, NULL, &post_pstat_rowneruuid, HIGH_QOS, o)) {
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

err_post_acl2_rowneruuid:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_doxm_rowneruuid(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_doxm_rowneruuid");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_doxm_rowneruuid;
  }

  /**  post doxm rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &post_acl2_rowneruuid, HIGH_QOS, o)) {
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

err_post_doxm_rowneruuid:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_doxm_deviceuuid(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_doxm_deviceuuid");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_doxm_deviceuuid;
  }

  /** generate random deviceuuid; <store new peer uuid>; post doxm deviceuuid
   */
  oc_uuid_t dev_uuid = { { 0 } };
  oc_gen_uuid(&dev_uuid);
  char uuid[OC_UUID_LEN];
  oc_uuid_to_str(&dev_uuid, uuid, OC_UUID_LEN);
  OC_DBG("generated deviceuuid: %s", uuid);

  oc_device_t *device = o->device;
  if (o->otm == OC_OBT_OTM_RDP) {
    /* Free temporary PSK credential that was created for this handshake
     * and has served its purpose.
     */
    char suuid[37];
    oc_uuid_to_str(&device->uuid, suuid, 37);
    oc_cred_remove_subject(suuid, 0);
  }
  /* Store peer device's random uuid in local device object */
  memcpy(device->uuid.id, dev_uuid.id, 16);
  oc_endpoint_t *ep = device->endpoint;
  while (ep) {
    memcpy(ep->di.id, dev_uuid.id, 16);
    ep = ep->next;
  }

  ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &post_doxm_rowneruuid, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    /* Set random uuid as deviceuuid */
    oc_rep_set_text_string(root, deviceuuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_post_doxm_deviceuuid:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_doxm_devowneruuid(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_doxm_devowneruuid");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_doxm_devowneruuid;
  }

  /** post doxm devowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &post_doxm_deviceuuid, HIGH_QOS, o)) {
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

err_post_doxm_devowneruuid:
  oc_obt_free_otm_ctx(o, -1);
}

static void
post_pstat_om(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In post_pstat_om");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_post_pstat_om;
  }

  oc_device_t *device = o->device;
  oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  oc_tls_close_connection(ep);
  switch (o->otm)
  {
  case OC_OBT_OTM_JW:
    /**  <Open-anon-ecdh>
     */
    oc_tls_select_anon_ciphersuite();
    break;
#ifdef OC_PKI
  case OC_OBT_OTM_CERT:
    /**  <Open-TLS_ECDSA_with_Mfg_Cert>
     */
    oc_tls_select_cert_ciphersuite();
    break;
#endif
  default:
    goto err_post_pstat_om;
  }

  /**  post pstat om=4
   */
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &post_doxm_devowneruuid, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_int(root, om, 4);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_post_pstat_om:
  oc_obt_free_otm_ctx(o, -1);
}

void
oc_obt_otm_get_doxm_handler(oc_client_response_t *data)
{
  if (!data || !oc_obt_is_otm_ctx_valid(data->user_data)) {
    return;
  }

  OC_DBG("In oc_obt_otm_get_doxm_handler");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_oc_obt_otm_get_doxm_handler;
  }

  int64_t *oxms = NULL;
  size_t oxms_len = 0;
  if (oc_rep_get_int_array(data->payload, "oxms", &oxms, &oxms_len)) {
    int64_t oxmt;
    switch (o->otm)
    {
    case OC_OBT_OTM_JW:
      oxmt = OC_OXMTYPE_JW;
      break;
#ifdef OC_PKI
    case OC_OBT_OTM_CERT:
      oxmt = OC_OXMTYPE_MFG_CERT;
      break;
#endif
    default:
      goto err_oc_obt_otm_get_doxm_handler;
    }

    size_t i;
    for (i = 0; i < oxms_len; i++) {
      if (oxms[i] == oxmt) {
        break;
      }
    }
    if (i == oxms_len) {
      goto err_oc_obt_otm_get_doxm_handler;
    }

    /**  post doxm oxmsel
     */
    oc_device_t *device = o->device;
    oc_endpoint_t *ep = oc_obt_get_unsecure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/doxm", ep, NULL, &post_pstat_om, HIGH_QOS, o)) {
      oc_rep_start_root_object();
      oc_rep_set_int(root, oxmsel, oxmt);
      oc_rep_end_root_object();
      if (oc_do_post()) {
        return;
      }
    }
  }

err_oc_obt_otm_get_doxm_handler:
  oc_obt_free_otm_ctx(o, -1);
}

void
oc_obt_otm_post_pstat_om_handler(oc_client_response_t *data)
{
    post_doxm_devowneruuid(data);
}

#endif /* OC_SECURITY */

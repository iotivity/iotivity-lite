/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
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

#include "oc_obt.h"
#include "oc_core_res.h"
#include "security/oc_acl.h"
#include "security/oc_cred.h"
#include "security/oc_doxm.h"
#include "security/oc_dtls.h"
#include "security/oc_pstat.h"
#include "security/oc_store.h"
#include <stdlib.h>

#define DISCOVERY_CB_DELAY (5)
/* Worst case timeout for all onboarding/provisioning sequences */
#define OBT_CB_TIMEOUT (100)

typedef struct
{
  oc_obt_devicelist_cb_t cb;
  void *data;
} oc_devicelist_cb_t;

OC_MEMB(oc_devicelist_s, oc_devicelist_cb_t, 1);

typedef struct
{
  oc_obt_status_cb_t cb;
  void *data;
} oc_status_cb_t;

typedef struct oc_otm_ctx_t
{
  struct oc_otm_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device;
} oc_otm_ctx_t;

OC_MEMB(oc_otm_ctx_m, oc_otm_ctx_t, 1);
OC_LIST(oc_otm_ctx_l);

typedef struct oc_switch_dos_ctx_t
{
  struct oc_switch_dos_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device;
  oc_dostype_t dos;
} oc_switch_dos_ctx_t;

OC_MEMB(oc_switch_dos_ctx_m, oc_switch_dos_ctx_t, 1);
OC_LIST(oc_switch_dos_ctx_l);

typedef struct
{
  oc_status_cb_t cb;
  oc_device_t *device;
  oc_switch_dos_ctx_t *switch_dos;
} oc_hard_reset_ctx_t;

OC_MEMB(oc_hard_reset_ctx_m, oc_hard_reset_ctx_t, 1);

typedef struct oc_credprov_ctx_t
{
  struct oc_credprov_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device1;
  oc_device_t *device2;
  oc_switch_dos_ctx_t *switch_dos;
  uint8_t key[16];
} oc_credprov_ctx_t;

OC_MEMB(oc_credprov_ctx_m, oc_credprov_ctx_t, 1);
OC_LIST(oc_credprov_ctx_l);

typedef struct oc_acl2prov_ctx_t
{
  struct oc_acl2prov_ctx_t *next;
  oc_status_cb_t cb;
  oc_device_t *device;
  oc_sec_ace_t *ace;
  oc_switch_dos_ctx_t *switch_dos;
} oc_acl2prov_ctx_t;

OC_MEMB(oc_acl2prov_m, oc_acl2prov_ctx_t, 1);
OC_LIST(oc_acl2prov_l);

OC_MEMB(oc_aces_m, oc_sec_ace_t, 1);
OC_MEMB(oc_res_m, oc_ace_res_t, 1);

OC_MEMB(oc_devices_s, oc_device_t, 1);
OC_LIST(oc_devices);
OC_LIST(oc_cache);

/* Persisted state */
static int id = 1000;

enum
{
  OC_OBT_UNOWNED_DISCOVERY = 1,
  OC_OBT_OWNED_DISCOVERY
};

/* Helper functions */

static oc_endpoint_t *
get_secure_endpoint(oc_endpoint_t *endpoint)
{
  while (endpoint->next != NULL && !(endpoint->flags & SECURED)) {
    endpoint = endpoint->next;
  }
  return endpoint;
}

static oc_endpoint_t *
get_unsecure_endpoint(oc_endpoint_t *endpoint)
{
  while (endpoint->next != NULL && (endpoint->flags & SECURED)) {
    endpoint = endpoint->next;
  }
  return endpoint;
}

static bool
owned_device(oc_uuid_t *uuid)
{
  /* Check if we already own this device by querying our creds */
  oc_sec_creds_t *creds = oc_sec_get_creds(0);
  oc_sec_cred_t *c = (oc_sec_cred_t *)oc_list_head(creds->creds);
  while (c != NULL) {
    if (memcmp(c->subjectuuid.id, uuid->id, 16) == 0) {
      return true;
    }
    c = c->next;
  }
  return false;
}

static oc_dostype_t
parse_dos(oc_rep_t *rep)
{
  oc_dostype_t s = 0;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_OBJECT: {
      if (oc_string_len(rep->name) == 3 &&
          memcmp(oc_string(rep->name), "dos", 3) == 0) {
        oc_rep_t *dos = rep->value.object;
        while (dos != NULL) {
          switch (dos->type) {
          case OC_REP_INT: {
            if (oc_string_len(dos->name) == 1 &&
                oc_string(dos->name)[0] == 's') {
              s = dos->value.integer;
            }
          } break;
          default:
            break;
          }
          dos = dos->next;
        }
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return s;
}

static void
purge_cache(oc_device_t *device)
{
  oc_list_remove(oc_cache, device);
  oc_list_remove(oc_devices, device);
}

static oc_event_callback_retval_t
free_device(void *data)
{
  oc_device_t *device = (oc_device_t *)data;
  oc_free_server_endpoints(device->endpoint);
  purge_cache(device);
  oc_memb_free(&oc_devices_s, device);
  return OC_EVENT_DONE;
}

static void
oc_obt_dump_state(void)
{
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf)
    return;

  oc_rep_new(buf, OC_MAX_APP_DATA_SIZE);
  oc_rep_start_root_object();
  oc_rep_set_int(root, id, id);
  oc_rep_end_root_object();

  int size = oc_rep_finalize();
  if (size > 0) {
    OC_DBG("oc_obt: dumped current state: size %d\n", size);
    oc_storage_write("obt_state", buf, size);
  }

  free(buf);
}

static void
oc_obt_load_state(void)
{
  long ret = 0;
  oc_rep_t *rep, *head;

  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    return;
  }

  ret = oc_storage_read("obt_state", buf, OC_MAX_APP_DATA_SIZE);
  if (ret > 0) {
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0 };
    oc_rep_set_pool(&rep_objects);
    uint16_t err = oc_parse_rep(buf, ret, &rep);
    head = rep;
    if (err == 0) {
      while (rep != NULL) {
        switch (rep->type) {
        case OC_REP_INT:
          if (oc_string_len(rep->name) == 2 &&
              memcmp(oc_string(rep->name), "id", 2) == 0) {
            id = rep->value.integer;
          }
          break;
        default:
          break;
        }
        rep = rep->next;
      }
    }
    oc_free_rep(head);
  } else {
    id = 1000;
  }
  free(buf);
}

static int
oc_obt_get_next_id(void)
{
  ++id;
  oc_obt_dump_state();
  return id;
}

struct list
{
  struct list *next;
};

static bool
is_item_in_list(oc_list_t list, void *item)
{
  struct list *h = oc_list_head(list);
  while (h != NULL) {
    if (h == item) {
      return true;
    }
    h = h->next;
  }
  return false;
}

/* End of helper functions */

/* Just-works ownership transfer */

static void
free_otm_state(oc_otm_ctx_t *o, int status)
{
  oc_endpoint_t *ep = get_secure_endpoint(o->device->endpoint);
  oc_sec_dtls_close_connection(ep);
  oc_sec_dtls_demote_anon_ciphersuite();
  if (status == -1) {
    char suuid[37];
    oc_uuid_to_str(&o->device->uuid, suuid, 37);
    oc_cred_remove_subject(suuid, 0);
  }
  free_device(o->device);
  o->cb.cb(status, o->cb.data);
  oc_list_remove(oc_otm_ctx_l, o);
  oc_memb_free(&oc_otm_ctx_m, o);
}

static oc_event_callback_retval_t
otm_request_timeout_cb(void *data)
{
  free_otm_state(data, -1);
  return OC_EVENT_DONE;
}

static void
free_otm_ctx(oc_otm_ctx_t *ctx, int status)
{
  oc_remove_delayed_callback(ctx, otm_request_timeout_cb);
  free_otm_state(ctx, status);
}

static void
obt_jw_13(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_13\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_otm_ctx(o, -1);
    return;
  }

  /**  13) <close DTLS>
   */
  oc_dostype_t s = parse_dos(data->payload);
  if (s == OC_DOS_RFNOP) {
    free_otm_ctx(o, 0);
  } else {
    free_otm_ctx(o, -1);
  }
}

static void
obt_jw_12(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_12\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_12;
  }

  /**  12) <close DTLS> ; <tls psk> ; get pstat s=rfnop?
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);

  oc_sec_dtls_close_connection(ep);

  oc_sec_dtls_demote_anon_ciphersuite();

  if (oc_do_get("/oic/sec/pstat", ep, NULL, &obt_jw_13, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_12:
  free_otm_ctx(o, -1);
}

static void
obt_jw_11(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_11\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_11;
  }

  oc_dostype_t s = parse_dos(data->payload);
  if (s == OC_DOS_RFPRO) {
    /**  11) post pstat s=rfnop, isop=true
     */
    oc_device_t *device = o->device;
    oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_12, HIGH_QOS, o)) {
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

err_obt_jw_11:
  free_otm_ctx(o, -1);
}

static void
obt_jw_10(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_10\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_10;
  }

  /**  10) get pstat s=rfpro?
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/pstat", ep, NULL, &obt_jw_11, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_10:
  free_otm_ctx(o, -1);
}

static void
obt_jw_9(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_9\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_9;
  }

  /**  9) post pstat s=rfpro
    */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_10, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RFPRO);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_9:
  free_otm_ctx(o, -1);
}

static void
obt_jw_8(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_8\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_8;
  }

  /**  8) post doxm owned = true
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_jw_9, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, owned, true);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_8:
  free_otm_ctx(o, -1);
}

static void
obt_jw_7(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_7\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_7;
  }

  /**  7) post pstat rowneruuid
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_8, HIGH_QOS, o)) {
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    char uuid[37];
    oc_uuid_to_str(my_uuid, uuid, 37);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_7:
  free_otm_ctx(o, -1);
}

static void
obt_jw_6(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_6\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_6;
  }

  oc_device_t *device = o->device;
  oc_sec_cred_t *c = oc_sec_get_cred(&device->uuid, 0);
  if (!c) {
    goto err_obt_jw_6;
  }

  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  char uuid[37];
  oc_uuid_to_str(my_uuid, uuid, 37);
  char suuid[37];
  oc_uuid_to_str(&device->uuid, suuid, 37);

#define OXM_JUST_WORKS "oic.sec.doxm.jw"
  bool derived = oc_sec_derive_owner_psk(
    ep, (const uint8_t *)OXM_JUST_WORKS, strlen(OXM_JUST_WORKS),
    device->uuid.id, 16, my_uuid->id, 16, c->key, 16);
#undef OXM_JUST_WORKS
  if (!derived) {
    goto err_obt_jw_6;
  }

  int credid = oc_obt_get_next_id();

  /**  6) post cred rowneruuid, cred
   */
  if (oc_init_post("/oic/sec/cred", ep, NULL, &obt_jw_7, HIGH_QOS, o)) {
    c->credid = credid;
    c->credtype = 1;
    memcpy(c->subjectuuid.id, device->uuid.id, 16);

    oc_rep_start_root_object();
    oc_rep_set_array(root, creds);
    oc_rep_object_array_start_item(creds);

    oc_rep_set_int(creds, credid, c->credid);
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
      oc_sec_dump_cred(0);
      return;
    }
  }

err_obt_jw_6:
  free_otm_ctx(o, -1);
}

static void
obt_jw_5(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_5\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_5;
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

  /**  5) <store peer uuid> ; post acl rowneruuid
   */
  oc_device_t *device = o->device;

  /* Store peer device's now fixed uuid in local device object */
  memcpy(device->uuid.id, peer.id, 16);

  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);

  if (oc_init_post("/oic/sec/acl2", ep, NULL, &obt_jw_6, HIGH_QOS, o)) {
    oc_uuid_t *my_uuid = oc_core_get_device_id(0);
    char uuid[37];
    oc_uuid_to_str(my_uuid, uuid, 37);

    oc_rep_start_root_object();
    oc_rep_set_text_string(root, rowneruuid, uuid);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

err_obt_jw_5:
  free_otm_ctx(o, -1);
}

static void
obt_jw_4(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_4\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_4;
  }

  /**  4) get doxm
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/doxm", ep, NULL, &obt_jw_5, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_4:
  free_otm_ctx(o, -1);
}

static void
obt_jw_3(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_3\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_3;
  }

  oc_dostype_t s = parse_dos(data->payload);
  if (s == OC_DOS_RFOTM) {
    /**  3) post doxm oxmsel=0, rowneruuid, devowneruuid
     */
    oc_device_t *device = o->device;
    oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/doxm", ep, NULL, &obt_jw_4, HIGH_QOS, o)) {
      oc_uuid_t *my_uuid = oc_core_get_device_id(0);
      char uuid[37];
      oc_uuid_to_str(my_uuid, uuid, 37);

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

err_obt_jw_3:
  free_otm_ctx(o, -1);
}

static void
obt_jw_2(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_otm_ctx_l, data->user_data)) {
    return;
  }

  OC_DBG("In obt_jw_2\n");
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_obt_jw_2;
  }

  /**  2) get pstat s=rfotm?
   */
  oc_device_t *device = o->device;
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_do_get("/oic/sec/pstat", ep, NULL, &obt_jw_3, HIGH_QOS, o)) {
    return;
  }

err_obt_jw_2:
  free_otm_ctx(o, -1);
}

/*
  OTM sequence:
  1) <anon ecdh>+post pstat s=reset
  2) get pstat s=rfotm?
  3) post doxm oxmsel=0, rowneruuid, devowneruuid
  4) get doxm
  5) <store peer uuid> ; post acl rowneruuid
  6) post cred rowneruuid, cred
  7) post pstat rowneruuid
  8) post doxm owned = true
  9) post pstat s=rfpro
  10) get pstat s=rfpro?
  11) post pstat s=rfnop, isop=true
  12) <close DTLS> ; <tls psk> ; get pstat s=rfnop?
  13) <close DTLS>
*/
int
oc_obt_perform_just_works_otm(oc_device_t *device, oc_obt_status_cb_t cb,
                              void *data)
{
  OC_DBG("In oc_obt_perform_just_works_otm\n");

  /* Remove device from temporary cache */
  if (owned_device(&device->uuid)) {
    free_device(device);
    return -1;
  }

  oc_otm_ctx_t *o = (oc_otm_ctx_t *)oc_memb_alloc(&oc_otm_ctx_m);
  if (!o) {
    return -1;
  }

  o->cb.cb = cb;
  o->cb.data = data;
  o->device = device;

  /**  1) <anon ecdh>+post pstat s=reset
   */
  oc_sec_dtls_elevate_anon_ciphersuite();

  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (oc_init_post("/oic/sec/pstat", ep, NULL, &obt_jw_2, HIGH_QOS, o)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, OC_DOS_RESET);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      oc_list_add(oc_otm_ctx_l, o);
      oc_set_delayed_callback(o, otm_request_timeout_cb, OBT_CB_TIMEOUT);
      return 0;
    }
  }

  free_device(o->device);
  oc_memb_free(&oc_otm_ctx_m, o);

  return -1;
}

/* Device discovery */
static void
obt_check_owned(oc_client_response_t *data)
{
  oc_remove_delayed_callback(data->user_data, free_device);

  bool owned = false;
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) == 5 &&
          memcmp(oc_string(rep->name), "owned", 5) == 0) {
        owned = rep->value.boolean;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  oc_device_t *device = (oc_device_t *)data->user_data;

  if (!owned) {
    oc_list_add(oc_cache, device);
  } else {
    /* Device is owned by somebody else */
    if (!owned_device(&device->uuid)) {
      free_device(device);
    } else {
      oc_list_add(oc_devices, device);
    }
  }
}

static oc_discovery_flags_t
obt_discovery_cb(const char *anchor, const char *uri, oc_string_array_t types,
                 oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
                 oc_resource_properties_t bm, void *user_data)
{
  (void)interfaces;
  (void)bm;
  int i;
  oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  oc_uuid_t uuid;
  oc_str_to_uuid(anchor + 6, &uuid);
  if (memcmp(my_uuid->id, uuid.id, 16) == 0) {
    oc_free_server_endpoints(endpoint);
    return OC_CONTINUE_DISCOVERY;
  }

  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "oic.r.doxm", 10) == 0) {
      oc_endpoint_t *ep = get_unsecure_endpoint(endpoint);
      oc_device_t *device = oc_memb_alloc(&oc_devices_s);
      if (!device) {
        oc_free_server_endpoints(endpoint);
        return OC_STOP_DISCOVERY;
      }
      memcpy(device->uuid.id, uuid.id, 16);
      device->endpoint = endpoint;
      oc_set_delayed_callback(device, free_device, OBT_CB_TIMEOUT);
      if ((long)user_data == OC_OBT_UNOWNED_DISCOVERY) {
        oc_do_get(uri, ep, "owned=FALSE", &obt_check_owned, HIGH_QOS, device);
      } else {
        oc_do_get(uri, ep, "owned=TRUE", &obt_check_owned, HIGH_QOS, device);
      }
      return OC_CONTINUE_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}

/* Unowned device discovery */
static oc_event_callback_retval_t
trigger_unowned_device_cb(void *data)
{
  oc_devicelist_cb_t *c = (oc_devicelist_cb_t *)data;
  oc_device_t *device_list = (oc_device_t *)oc_list_head(oc_cache);
  c->cb(device_list, c->data);
  oc_memb_free(&oc_devicelist_s, c);
  return OC_EVENT_DONE;
}

int
oc_obt_discover_unowned_devices(oc_obt_devicelist_cb_t cb, void *data)
{
  oc_devicelist_cb_t *c = (oc_devicelist_cb_t *)oc_memb_alloc(&oc_devicelist_s);
  if (!c) {
    return -1;
  }
  c->cb = cb;
  c->data = data;
  /* Clear temporary device cache */
  oc_device_t *device = (oc_device_t *)oc_list_pop(oc_cache);
  while (device != NULL) {
    free_device(device);
    device = (oc_device_t *)oc_list_pop(oc_cache);
  }
  if (oc_do_ip_discovery("oic.r.doxm", &obt_discovery_cb,
                         (void *)OC_OBT_UNOWNED_DISCOVERY)) {
    oc_set_delayed_callback(c, trigger_unowned_device_cb, DISCOVERY_CB_DELAY);
    return 0;
  }
  oc_memb_free(&oc_devicelist_s, c);
  return -1;
}

/* Owned device disvoery */
static oc_event_callback_retval_t
trigger_owned_device_cb(void *data)
{
  oc_devicelist_cb_t *c = (oc_devicelist_cb_t *)data;
  oc_device_t *device_list = (oc_device_t *)oc_list_head(oc_devices);
  c->cb(device_list, c->data);
  oc_memb_free(&oc_devicelist_s, c);
  return OC_EVENT_DONE;
}

int
oc_obt_discover_owned_devices(oc_obt_devicelist_cb_t cb, void *data)
{
  oc_devicelist_cb_t *c = (oc_devicelist_cb_t *)oc_memb_alloc(&oc_devicelist_s);
  if (!c) {
    return -1;
  }
  c->cb = cb;
  c->data = data;
  /* Clear owned device cache */
  oc_device_t *device = (oc_device_t *)oc_list_pop(oc_devices);
  while (device != NULL) {
    free_device(device);
    device = (oc_device_t *)oc_list_pop(oc_devices);
  }

  if (oc_do_ip_discovery("oic.r.doxm", &obt_discovery_cb,
                         (void *)OC_OBT_OWNED_DISCOVERY)) {
    oc_set_delayed_callback(c, trigger_owned_device_cb, DISCOVERY_CB_DELAY);
    return 0;
  }
  oc_memb_free(&oc_devicelist_s, c);
  return -1;
}

/* Helper sequence to switch between pstat device states */
static void
free_switch_dos_state(oc_switch_dos_ctx_t *d)
{
  oc_list_remove(oc_switch_dos_ctx_l, d);
  oc_memb_free(&oc_switch_dos_ctx_m, d);
}

static void
free_switch_dos_ctx(oc_switch_dos_ctx_t *d, int status)
{
  oc_status_cb_t cb = d->cb;
  free_switch_dos_state(d);
  cb.cb(status, cb.data);
}

static void
pstat_GET_dos2(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_switch_dos_ctx_l, data->user_data)) {
    return;
  }

  oc_switch_dos_ctx_t *d = (oc_switch_dos_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_switch_dos_ctx(d, -1);
    return;
  }

  oc_dostype_t s = parse_dos(data->payload);
  oc_dostype_t r = d->dos;
  if (s == r || (r == OC_DOS_RESET && s == OC_DOS_RFOTM)) {
    free_switch_dos_ctx(d, 0);
  } else {
    free_switch_dos_ctx(d, -1);
  }
}

static void
pstat_POST_dos1_to_dos2(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_switch_dos_ctx_l, data->user_data)) {
    return;
  }

  oc_switch_dos_ctx_t *d = (oc_switch_dos_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_switch_dos_ctx(d, -1);
    return;
  }

  oc_endpoint_t *ep = get_secure_endpoint(d->device->endpoint);
  if (!oc_do_get("/oic/sec/pstat", ep, NULL, &pstat_GET_dos2, HIGH_QOS, d)) {
    free_switch_dos_ctx(d, -1);
  }
}

static oc_switch_dos_ctx_t *
switch_dos(oc_device_t *device, oc_dostype_t dos, oc_obt_status_cb_t cb,
           void *data)
{
  oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
  if (!ep) {
    return NULL;
  }

  oc_switch_dos_ctx_t *d =
    (oc_switch_dos_ctx_t *)oc_memb_alloc(&oc_switch_dos_ctx_m);
  if (!d) {
    return NULL;
  }

  /* oc_switch_dos_ctx_t */
  d->device = device;
  d->dos = dos;
  /* oc_status_cb_t */
  d->cb.cb = cb;
  d->cb.data = data;

  if (oc_init_post("/oic/sec/pstat", ep, NULL, &pstat_POST_dos1_to_dos2,
                   HIGH_QOS, d)) {
    oc_rep_start_root_object();
    oc_rep_set_object(root, dos);
    oc_rep_set_int(dos, s, dos);
    oc_rep_close_object(root, dos);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      oc_list_add(oc_switch_dos_ctx_l, d);
      return d;
    }
  }

  oc_memb_free(&oc_switch_dos_ctx_m, d);
  return NULL;
}

/* Perform hard RESET */
static void
free_hard_reset_ctx(oc_hard_reset_ctx_t *ctx, int status)
{
  oc_status_cb_t cb = ctx->cb;
  oc_endpoint_t *ep = get_secure_endpoint(ctx->device->endpoint);
  char subjectuuid[37];
  oc_uuid_to_str(&ctx->device->uuid, subjectuuid, 37);
  oc_sec_dtls_close_connection(ep);
  free_device(ctx->device);
  if (ctx->switch_dos) {
    free_switch_dos_state(ctx->switch_dos);
  }
  oc_memb_free(&oc_hard_reset_ctx_m, ctx);
  if (status >= 0) {
    /* Remove device's credential from OBT's credential store */
    if (oc_cred_remove_subject(subjectuuid, 0)) {
      cb.cb(0, cb.data);
      return;
    }
  }
  cb.cb(-1, cb.data);
}

static oc_event_callback_retval_t
hard_reset_timeout_cb(void *data)
{
  free_hard_reset_ctx(data, -1);
  return OC_EVENT_DONE;
}

static void
hard_reset_cb(int status, void *data)
{
  oc_hard_reset_ctx_t *d = (oc_hard_reset_ctx_t *)data;
  d->switch_dos = NULL;
  oc_remove_delayed_callback(data, hard_reset_timeout_cb);
  free_hard_reset_ctx(data, status);
}

int
oc_obt_device_hard_reset(oc_device_t *device, oc_obt_status_cb_t cb, void *data)
{
  oc_hard_reset_ctx_t *d =
    (oc_hard_reset_ctx_t *)oc_memb_alloc(&oc_hard_reset_ctx_m);
  if (!d) {
    return -1;
  }

  d->cb.cb = cb;
  d->cb.data = data;
  d->device = device;

  d->switch_dos = switch_dos(device, OC_DOS_RESET, hard_reset_cb, d);
  if (!d->switch_dos) {
    free_device(device);
    oc_memb_free(&oc_hard_reset_ctx_m, d);
    return -1;
  }

  oc_set_delayed_callback(d, hard_reset_timeout_cb, OBT_CB_TIMEOUT);

  return 0;
}

/* Provision pairwise credentials */
static void
free_credprov_state(oc_credprov_ctx_t *p, int status)
{
  oc_endpoint_t *ep = get_secure_endpoint(p->device1->endpoint);
  oc_sec_dtls_close_connection(ep);
  ep = get_secure_endpoint(p->device2->endpoint);
  oc_sec_dtls_close_connection(ep);
  free_device(p->device1);
  free_device(p->device2);
  p->cb.cb(status, p->cb.data);
  if (p->switch_dos) {
    free_switch_dos_state(p->switch_dos);
  }
  oc_list_remove(oc_credprov_ctx_l, p);
  oc_memb_free(&oc_credprov_ctx_m, p);
}

static oc_event_callback_retval_t
credprov_request_timeout_cb(void *data)
{
  free_credprov_state(data, -1);
  return OC_EVENT_DONE;
}

static void
free_credprov_ctx(oc_credprov_ctx_t *ctx, int status)
{
  oc_remove_delayed_callback(ctx, credprov_request_timeout_cb);
  free_credprov_state(ctx, status);
}

static void
device2_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    free_credprov_ctx(p, 0);
  } else {
    free_credprov_ctx(p, -1);
  }
}

static void
device1_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    p->switch_dos = switch_dos(p->device2, OC_DOS_RFNOP, device2_RFNOP, p);
    if (p->switch_dos) {
      return;
    }
  }

  free_credprov_ctx(p, -1);
}

static void
device2_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_credprov_ctx(p, -1);
    return;
  }

  p->switch_dos = switch_dos(p->device1, OC_DOS_RFNOP, device1_RFNOP, p);
  if (!p->switch_dos) {
    free_credprov_ctx(p, -1);
  }
}

static void
device1_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_credprov_ctx(p, -1);
    return;
  }

  char d1uuid[37];
  oc_uuid_to_str(&p->device1->uuid, d1uuid, 37);

  oc_endpoint_t *ep = get_secure_endpoint(p->device2->endpoint);
  int credid = oc_obt_get_next_id();

  if (oc_init_post("/oic/sec/cred", ep, NULL, &device2_cred, HIGH_QOS, p)) {
    oc_rep_start_root_object();
    oc_rep_set_array(root, creds);
    oc_rep_object_array_start_item(creds);

    oc_rep_set_int(creds, credid, credid);
    oc_rep_set_int(creds, credtype, 1);
    oc_rep_set_text_string(creds, subjectuuid, d1uuid);

    oc_rep_set_object(creds, privatedata);
    oc_rep_set_byte_string(privatedata, data, p->key, 16);
    oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
    oc_rep_close_object(creds, privatedata);

    oc_rep_object_array_end_item(creds);
    oc_rep_close_array(root, creds);
    oc_rep_end_root_object();
    if (oc_do_post()) {
      return;
    }
  }

  free_credprov_ctx(p, -1);
}

static void
device2_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    int i;
    for (i = 0; i < 4; i++) {
      unsigned int r = oc_random_value();
      memcpy(&p->key[i * 4], &r, sizeof(r));
      i += 4;
    }

    char d2uuid[37];
    oc_uuid_to_str(&p->device2->uuid, d2uuid, 37);

    oc_endpoint_t *ep = get_secure_endpoint(p->device1->endpoint);

    int credid = oc_obt_get_next_id();

    if (oc_init_post("/oic/sec/cred", ep, NULL, &device1_cred, HIGH_QOS, p)) {
      oc_rep_start_root_object();
      oc_rep_set_array(root, creds);
      oc_rep_object_array_start_item(creds);

      oc_rep_set_int(creds, credid, credid);
      oc_rep_set_int(creds, credtype, 1);
      oc_rep_set_text_string(creds, subjectuuid, d2uuid);

      oc_rep_set_object(creds, privatedata);
      oc_rep_set_byte_string(privatedata, data, p->key, 16);
      oc_rep_set_text_string(privatedata, encoding, "oic.sec.encoding.raw");
      oc_rep_close_object(creds, privatedata);

      oc_rep_object_array_end_item(creds);
      oc_rep_close_array(root, creds);
      oc_rep_end_root_object();
      if (oc_do_post()) {
        return;
      }
    }
  }

  free_credprov_state(p, -1);
}

static void
device1_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data;

  p->switch_dos = NULL;
  if (status >= 0) {
    p->switch_dos = switch_dos(p->device2, OC_DOS_RFPRO, device2_RFPRO, p);
    if (!p->switch_dos) {
      free_credprov_ctx(p, -1);
    }
  }
}

int
oc_obt_provision_pairwise_credentials(oc_device_t *device1,
                                      oc_device_t *device2,
                                      oc_obt_status_cb_t cb, void *data)
{
  oc_credprov_ctx_t *p = oc_memb_alloc(&oc_credprov_ctx_m);
  if (!p) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device1 = device1;
  p->device2 = device2;

  p->switch_dos = switch_dos(device1, OC_DOS_RFPRO, device1_RFPRO, p);
  if (!p->switch_dos) {
    free_device(device1);
    free_device(device2);
    oc_memb_free(&oc_credprov_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_credprov_ctx_l, p);
  oc_set_delayed_callback(p, credprov_request_timeout_cb, OBT_CB_TIMEOUT);

  return 0;
}

/* Provision access-control entries */
static oc_sec_ace_t *
oc_obt_new_ace(void)
{
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_memb_alloc(&oc_aces_m);
  if (ace) {
    OC_LIST_STRUCT_INIT(ace, resources);
    ace->aceid = oc_obt_get_next_id();
  }
  return ace;
}

oc_sec_ace_t *
oc_obt_new_ace_for_subject(oc_uuid_t *uuid)
{
  oc_sec_ace_t *ace = oc_obt_new_ace();
  if (ace) {
    ace->subject_type = OC_SUBJECT_UUID;
    memcpy(ace->subject.uuid.id, uuid->id, 16);
  }
  return ace;
}

oc_sec_ace_t *
oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn)
{
  oc_sec_ace_t *ace = oc_obt_new_ace();
  if (ace) {
    ace->subject_type = OC_SUBJECT_CONN;
    ace->subject.conn = conn;
  }
  return ace;
}

oc_ace_res_t *
oc_obt_ace_new_resource(oc_sec_ace_t *ace)
{
  oc_ace_res_t *res = (oc_ace_res_t *)oc_memb_alloc(&oc_res_m);
  if (res) {
    oc_list_add(ace->resources, res);
  }
  return res;
}

void
oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href)
{
  if (resource) {
    if (oc_string_len(resource->href) > 0) {
      oc_free_string(&resource->href);
    }
    oc_new_string(&resource->href, href, strlen(href));
  }
}

void
oc_obt_ace_resource_set_num_rt(oc_ace_res_t *resource, int num_resources)
{
  if (resource) {
    if (oc_string_array_get_allocated_size(resource->types) > 0) {
      oc_free_string_array(&resource->types);
    }
    oc_new_string_array(&resource->types, num_resources);
  }
}

void
oc_obt_ace_resource_bind_rt(oc_ace_res_t *resource, const char *rt)
{
  if (resource) {
    oc_string_array_add_item(resource->types, rt);
  }
}

void
oc_obt_ace_resource_bind_if(oc_ace_res_t *resource,
                            oc_interface_mask_t interface)
{
  if (resource) {
    resource->interfaces = interface;
  }
}

void
oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc)
{
  if (resource) {
    resource->wildcard = wc;
  }
}

void
oc_obt_ace_add_permission(oc_sec_ace_t *ace, oc_ace_permissions_t permission)
{
  if (ace) {
    ace->permission |= permission;
  }
}

static void
free_ace(oc_sec_ace_t *ace)
{
  if (ace) {
    oc_ace_res_t *res = (oc_ace_res_t *)oc_list_pop(ace->resources);
    while (res != NULL) {
      if (oc_string_len(res->href) > 0) {
        oc_free_string(&res->href);
      }
      if (oc_string_array_get_allocated_size(res->types) > 0) {
        oc_free_string_array(&res->types);
      }
      oc_memb_free(&oc_res_m, res);
      res = (oc_ace_res_t *)oc_list_pop(ace->resources);
    }
    oc_memb_free(&oc_aces_m, ace);
  }
}

void
oc_obt_free_ace(oc_sec_ace_t *ace)
{
  free_ace(ace);
}

static void
free_acl2prov_state(oc_acl2prov_ctx_t *request, int status)
{
  free_ace(request->ace);
  oc_endpoint_t *ep = get_secure_endpoint(request->device->endpoint);
  oc_sec_dtls_close_connection(ep);
  free_device(request->device);
  if (request->switch_dos) {
    free_switch_dos_state(request->switch_dos);
  }
  request->cb.cb(status, request->cb.data);
  oc_list_remove(oc_acl2prov_l, request);
  oc_memb_free(&oc_acl2prov_m, request);
}

static oc_event_callback_retval_t
acl2prov_timeout_cb(void *data)
{
  free_acl2prov_state(data, -1);
  return OC_EVENT_DONE;
}

static void
free_acl2prov_ctx(oc_acl2prov_ctx_t *r, int status)
{
  oc_remove_delayed_callback(r, acl2prov_timeout_cb);
  free_acl2prov_state(r, status);
}

static void
provision_ace_complete(int status, void *data)
{
  if (!is_item_in_list(oc_acl2prov_l, data)) {
    return;
  }

  oc_acl2prov_ctx_t *r = (oc_acl2prov_ctx_t *)data;
  r->switch_dos = NULL;

  if (status >= 0) {
    free_acl2prov_ctx(r, 0);
  } else {
    free_acl2prov_ctx(r, -1);
  }
}

static void
acl2_response(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_acl2prov_l, data->user_data)) {
    return;
  }

  oc_acl2prov_ctx_t *r = (oc_acl2prov_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_acl2prov_ctx(r, -1);
    return;
  }

  oc_device_t *device = r->device;

  r->switch_dos = switch_dos(device, OC_DOS_RFNOP, provision_ace_complete, r);
  if (!r->switch_dos) {
    free_acl2prov_ctx(r, -1);
  }
}

static void
provision_ace(int status, void *data)
{
  if (!is_item_in_list(oc_acl2prov_l, data)) {
    return;
  }

  oc_acl2prov_ctx_t *r = (oc_acl2prov_ctx_t *)data;
  r->switch_dos = NULL;

  if (status >= 0) {
    oc_device_t *device = r->device;
    oc_sec_ace_t *ace = r->ace;

    oc_endpoint_t *ep = get_secure_endpoint(device->endpoint);
    if (oc_init_post("/oic/sec/acl2", ep, NULL, &acl2_response, HIGH_QOS, r)) {
      oc_rep_start_root_object();

      oc_rep_set_array(root, aclist2);
      oc_rep_object_array_start_item(aclist2);

      oc_rep_set_object(aclist2, subject);
      switch (ace->subject_type) {
      case OC_SUBJECT_UUID: {
        char uuid[37];
        oc_uuid_to_str(&ace->subject.uuid, uuid, 37);
        oc_rep_set_text_string(subject, uuid, uuid);
      } break;
      case OC_SUBJECT_CONN: {
        switch (ace->subject.conn) {
        case OC_CONN_AUTH_CRYPT:
          oc_rep_set_text_string(subject, conntype, "auth-crypt");
          break;
        case OC_CONN_ANON_CLEAR:
          oc_rep_set_text_string(subject, conntype, "anon-clear");
          break;
        }
      } break;
      default:
        break;
      }
      oc_rep_close_object(aclist2, subject);

      oc_ace_res_t *res = (oc_ace_res_t *)oc_list_head(ace->resources);
      oc_rep_set_array(aclist2, resources);
      while (res != NULL) {
        oc_rep_object_array_start_item(resources);
        if (res->interfaces != 0) {
          oc_core_encode_interfaces_mask(oc_rep_object(resources),
                                         res->interfaces);
        }
        if (oc_string_array_get_allocated_size(res->types) > 0) {
          oc_rep_set_string_array(resources, rt, res->types);
        }
        if (oc_string_len(res->href) > 0) {
          oc_rep_set_text_string(resources, href, oc_string(res->href));
        } else {
          switch (res->wildcard) {
          case OC_ACE_WC_ALL_DISCOVERABLE:
            oc_rep_set_text_string(resources, wc, "+");
            break;
          case OC_ACE_WC_ALL_NON_DISCOVERABLE:
            oc_rep_set_text_string(resources, wc, "-");
            break;
          case OC_ACE_WC_ALL:
            oc_rep_set_text_string(resources, wc, "*");
            break;
          default:
            break;
          }
        }
        oc_rep_object_array_end_item(resources);
        res = res->next;
      }
      oc_rep_close_array(aclist2, resources);

      oc_rep_set_uint(aclist2, permission, ace->permission);

      oc_rep_set_int(aclist2, aceid, ace->aceid);

      oc_rep_object_array_end_item(aclist2);
      oc_rep_close_array(root, aclist2);

      oc_rep_end_root_object();

      if (oc_do_post()) {
        return;
      }
    }
  }

  free_acl2prov_ctx(r, -1);
}

int
oc_obt_provision_ace(oc_device_t *device, oc_sec_ace_t *ace,
                     oc_obt_status_cb_t cb, void *data)
{
  oc_acl2prov_ctx_t *r = (oc_acl2prov_ctx_t *)oc_memb_alloc(&oc_acl2prov_m);
  if (!r) {
    return -1;
  }

  r->cb.cb = cb;
  r->cb.data = data;
  r->ace = ace;
  r->device = device;

  r->switch_dos = switch_dos(device, OC_DOS_RFPRO, provision_ace, r);
  if (!r->switch_dos) {
    free_device(device);
    free_ace(ace);
    oc_memb_free(&oc_acl2prov_m, r);
    return -1;
  }

  oc_list_add(oc_acl2prov_l, r);
  oc_set_delayed_callback(r, acl2prov_timeout_cb, OBT_CB_TIMEOUT);

  return 0;
}

void
oc_obt_init(void)
{
  if (!oc_sec_is_operational(0)) {
    oc_uuid_t *uuid = oc_core_get_device_id(0);

    oc_sec_acl_t *acl = oc_sec_get_acl(0);
    oc_sec_doxm_t *doxm = oc_sec_get_doxm(0);
    oc_sec_creds_t *creds = oc_sec_get_creds(0);
    oc_sec_pstat_t *ps = oc_sec_get_pstat(0);

    memcpy(acl->rowneruuid.id, uuid->id, 16);

    memcpy(doxm->devowneruuid.id, uuid->id, 16);
    memcpy(doxm->deviceuuid.id, uuid->id, 16);
    doxm->owned = true;

    memcpy(creds->rowneruuid.id, uuid->id, 16);

    memcpy(ps->rowneruuid.id, uuid->id, 16);
    ps->tm = ps->cm = 0;
    ps->isop = true;
    ps->s = OC_DOS_RFNOP;

    oc_sec_dump_pstat(0);
    oc_sec_dump_doxm(0);
    oc_sec_dump_cred(0);
    oc_sec_dump_acl(0);
    oc_sec_dump_unique_ids(0);
  } else {
    oc_obt_load_state();
  }
}

#endif /* OC_SECURITY */

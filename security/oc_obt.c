/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
 *               2017-2019 Intel Corporation
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

#include "oc_config.h"
#ifdef OC_SECURITY
#ifndef OC_DYNAMIC_ALLOCATION
#error "ERROR: Please rebuild with OC_DYNAMIC_ALLOCATION"
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifndef OC_STORAGE
#error Preprocessor macro OC_SECURITY is defined but OC_STORAGE is not defined \
check oc_config.h and make sure OC_STORAGE is defined if OC_SECURITY is defined.
#endif

#include "api/oc_helpers_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_csr.h"
#include "oc_obt.h"
#include "oc_store.h"
#include "security/oc_acl_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_csr_internal.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_obt_internal.h"
#include "security/oc_roles_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_sdi_internal.h"
#include "security/oc_tls_internal.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <stdlib.h>

OC_MEMB(oc_discovery_s, oc_discovery_cb_t, 1);
OC_LIST(oc_discovery_cbs);

OC_MEMB(oc_otm_ctx_m, oc_otm_ctx_t, 1);
OC_LIST(oc_otm_ctx_l);

OC_MEMB(oc_switch_dos_ctx_m, oc_switch_dos_ctx_t, 1);
OC_LIST(oc_switch_dos_ctx_l);

OC_MEMB(oc_hard_reset_ctx_m, oc_hard_reset_ctx_t, 1);
OC_LIST(oc_hard_reset_ctx_l);

#ifdef OC_OSCORE
OC_MEMB(oc_oscoreprov_ctx_m, oc_oscoreprov_ctx_t, 1);
OC_LIST(oc_oscoreprov_ctx_l);

OC_MEMB(oc_oscoregroupprov_ctx_m, oc_oscoregroupprov_ctx_t, 1);
OC_LIST(oc_oscoregroupprov_ctx_l);
#endif /* OC_OSCORE */

OC_MEMB(oc_credprov_ctx_m, oc_credprov_ctx_t, 1);
OC_LIST(oc_credprov_ctx_l);

OC_MEMB(oc_credret_ctx_m, oc_credret_ctx_t, 1);
OC_LIST(oc_credret_ctx_l);

OC_MEMB(oc_creddel_ctx_m, oc_creddel_ctx_t, 1);
OC_LIST(oc_creddel_ctx_l);

#ifdef OC_PKI
OC_MEMB(oc_installtrust_ctx_m, oc_trustanchor_ctx_t, 1);
OC_LIST(oc_installtrust_ctx_l);
#endif /* OC_PKI */

OC_MEMB(oc_cred_m, oc_sec_cred_t, 1);
OC_MEMB(oc_creds_m, oc_sec_creds_t, 1);

OC_MEMB(oc_acl2prov_ctx_m, oc_acl2prov_ctx_t, 1);
OC_LIST(oc_acl2prov_ctx_l);

OC_MEMB(oc_aclret_ctx_m, oc_aclret_ctx_t, 1);
OC_LIST(oc_aclret_ctx_l);

OC_MEMB(oc_acedel_ctx_m, oc_acedel_ctx_t, 1);
OC_LIST(oc_acedel_ctx_l);

OC_MEMB(oc_aces_m, oc_sec_ace_t, 1);
OC_MEMB(oc_res_m, oc_ace_res_t, 1);

OC_MEMB(oc_acl_m, oc_sec_acl_t, 1);

#ifdef OC_PKI
OC_MEMB(oc_roles, oc_role_t, 1);
#endif /* OC_PKI */

/* Owned/unowned device caches */
OC_MEMB(oc_devices_s, oc_device_t, 1);
OC_LIST(oc_devices);
OC_LIST(oc_cache);

/* Public/Private key-pair for the local domain's root of trust */
#ifdef OC_PKI
static const char *g_root_subject = "C=US, O=OCF, CN=IoTivity-Lite OBT Root";
static uint8_t g_private_key[OC_ECDSA_PRIVKEY_SIZE] = { 0 };
static size_t g_private_key_size = 0;
static int g_root_cert_credid = 0;
#endif /* OC_PKI */

#ifdef OC_OSCORE
static uint8_t g_groupid[OSCORE_CTXID_LEN] = { 0 };
static uint8_t g_group_secret[OSCORE_MASTER_SECRET_LEN] = { 0 };
#endif /* OC_OSCORE */

/* Internal utility functions */
const oc_endpoint_t *
oc_obt_get_unsecure_endpoint(const oc_endpoint_t *endpoint)
{
  while (endpoint && endpoint->next != NULL && endpoint->flags & SECURED) {
    endpoint = endpoint->next;
  }
  return endpoint;
}

const oc_endpoint_t *
oc_obt_get_secure_endpoint(const oc_endpoint_t *endpoint)
{
  while (endpoint && endpoint->next != NULL && !(endpoint->flags & SECURED)) {
    endpoint = endpoint->next;
  }
  return endpoint;
}

static oc_device_t *
get_device_handle(const oc_uuid_t *uuid, oc_list_t list)
{
  oc_device_t *device = (oc_device_t *)oc_list_head(list);
  while (device) {
    if (memcmp(uuid->id, device->uuid.id, OC_ARRAY_SIZE(device->uuid.id)) ==
        0) {
      return device;
    }
    device = device->next;
  }
  return NULL;
}

oc_device_t *
oc_obt_get_cached_device_handle(const oc_uuid_t *uuid)
{
  return get_device_handle(uuid, oc_cache);
}

oc_device_t *
oc_obt_get_owned_device_handle(const oc_uuid_t *uuid)
{
  return get_device_handle(uuid, oc_devices);
}

bool
oc_obt_is_owned_device(const oc_uuid_t *uuid)
{
  /* Check if we already own this device by querying our creds */
  oc_sec_creds_t *creds = oc_sec_get_creds(0);
  oc_sec_cred_t *c = (oc_sec_cred_t *)oc_list_head(creds->creds);
  while (c != NULL) {
    if (memcmp(c->subjectuuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id)) == 0 &&
        c->owner_cred) {
      return true;
    }
    c = c->next;
  }
  return false;
}

oc_dostype_t
oc_obt_parse_dos(oc_rep_t *rep)
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

static oc_device_t *
cache_new_device(oc_list_t list, const oc_uuid_t *uuid,
                 const oc_endpoint_t *endpoint)
{
  oc_device_t *device = (oc_device_t *)oc_list_head(list);
  while (device != NULL) {
    if (memcmp(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id)) == 0) {
      break;
    }
    device = device->next;
  }

  if (!device) {
    device = oc_memb_alloc(&oc_devices_s);
    if (!device) {
      return NULL;
    }
    memcpy(device->uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
    oc_list_add(list, device);
  }

  if (device->endpoint) {
    oc_free_server_endpoints(device->endpoint);
  }

  oc_endpoint_t *ep = oc_new_endpoint();
  if (!ep) {
    oc_list_remove(list, device);
    oc_memb_free(&oc_devices_s, device);
    return NULL;
  }

  memcpy(ep, endpoint, sizeof(oc_endpoint_t));
  device->endpoint = ep;
  ep->next = NULL;
  return device;
}

static oc_event_callback_retval_t
free_device(void *data)
{
  oc_device_t *device = (oc_device_t *)data;
  oc_free_server_endpoints(device->endpoint);
  oc_list_remove(oc_cache, device);
  oc_list_remove(oc_devices, device);
  oc_memb_free(&oc_devices_s, device);
  return OC_EVENT_DONE;
}

#if defined(OC_PKI) || defined(OC_OSCORE)
static void
oc_obt_dump_state(void)
{
  uint8_t *buf = malloc(OC_MIN_APP_DATA_SIZE);
  if (!buf)
    return;
#ifdef OC_DYNAMIC_ALLOCATION
  oc_rep_new_realloc_v1(&buf, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* OC_DYNAMIC_ALLOCATION */
  oc_rep_new_v1(buf, OC_MIN_APP_DATA_SIZE);
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_rep_start_root_object();
#ifdef OC_PKI
  oc_rep_set_byte_string(root, private_key, g_private_key, g_private_key_size);
  oc_rep_set_int(root, credid, g_root_cert_credid);
#endif /* OC_PKI */
#ifdef OC_OSCORE
  oc_rep_set_byte_string(root, groupid, g_groupid, OSCORE_CTXID_LEN);
  oc_rep_set_byte_string(root, group_secret, g_group_secret,
                         OSCORE_MASTER_SECRET_LEN);
#endif /* OC_OSCORE */
  oc_rep_end_root_object();

#ifdef OC_DYNAMIC_ALLOCATION
  buf = oc_rep_shrink_encoder_buf(buf);
#endif /* OC_DYNAMIC_ALLOCATION */
  int size = oc_rep_get_encoded_payload_size();
  if (size > 0) {
    OC_DBG("oc_obt: dumped current state: size %d", size);
    oc_storage_write("obt_state", buf, size);
  }

  free(buf);
}

static void
oc_obt_load_state(void)
{
  uint8_t *buf = malloc(OC_MAX_APP_DATA_SIZE);
  if (!buf) {
    return;
  }

  long ret = oc_storage_read("obt_state", buf, OC_MAX_APP_DATA_SIZE);
  if (ret <= 0) {
    free(buf);
    return;
  }

  struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
  oc_rep_t *rep = NULL;
  int err = oc_parse_rep(buf, ret, &rep);
  if (err != 0) {
    oc_free_rep(rep);
    free(buf);
    return;
  }

  oc_rep_t *head = rep;
  while (rep != NULL) {
    switch (rep->type) {
#ifdef OC_PKI
    case OC_REP_INT:
#define CREDID "credid"
      if (oc_string_len(rep->name) == OC_CHAR_ARRAY_LEN(CREDID) &&
          memcmp(oc_string(rep->name), CREDID, OC_CHAR_ARRAY_LEN(CREDID)) ==
            0) {
        g_root_cert_credid = (int)rep->value.integer;
      }
      break;
#endif /* OC_PKI */
#if defined(OC_PKI) || defined(OC_OSCORE)
    case OC_REP_BYTE_STRING:
#ifdef OC_PKI
#define PRIVATE_KEY "private_key"
      if (oc_string_len(rep->name) == OC_CHAR_ARRAY_LEN(PRIVATE_KEY) &&
          memcmp(oc_string(rep->name), PRIVATE_KEY,
                 OC_CHAR_ARRAY_LEN(PRIVATE_KEY)) == 0) {
        g_private_key_size = oc_string_len(rep->value.string);
        memcpy(g_private_key, oc_string(rep->value.string), g_private_key_size);
        break;
      }
#endif /* OC_PKI */
#ifdef OC_OSCORE
#define GROUP_ID "groupid"
      if (oc_string_len(rep->name) == OC_CHAR_ARRAY_LEN(GROUP_ID) &&
          memcmp(oc_string(rep->name), GROUP_ID, OC_CHAR_ARRAY_LEN(GROUP_ID)) ==
            0) {
        memcpy(g_groupid, oc_string(rep->value.string), OSCORE_CTXID_LEN);
        break;
      }
#define GROUP_SECRET "group_secret"
      if (oc_string_len(rep->name) == OC_CHAR_ARRAY_LEN(GROUP_SECRET) &&
          memcmp(oc_string(rep->name), GROUP_SECRET,
                 OC_CHAR_ARRAY_LEN(GROUP_SECRET)) == 0) {
        memcpy(g_group_secret, oc_string(rep->value.string),
               OSCORE_MASTER_SECRET_LEN);
        break;
      }
#endif /* OC_OSCORE */
      break;
#endif /* OC_PKI || OC_OSCORE */
    default:
      break;
    }
    rep = rep->next;
  }

  oc_free_rep(head);
  oc_rep_set_pool(prev_rep_objects);
  free(buf);
}
#endif /* OC_PKI || OC_OSCORE */

#ifdef OC_OSCORE
static void
gen_oscore_ctxid(uint8_t *id, bool group)
{
  oc_random_buffer(id, OSCORE_CTXID_LEN);
  id[0] = group ? 0x02 : 0x01;
}
#endif /* OC_OSCORE */

struct list
{
  struct list *next;
};

static bool
is_item_in_list(oc_list_t list, const void *item)
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

bool
oc_obt_is_otm_ctx_valid(const oc_otm_ctx_t *ctx)
{
  return is_item_in_list(oc_otm_ctx_l, ctx);
}

oc_otm_ctx_t *
oc_obt_alloc_otm_ctx(void)
{
  oc_otm_ctx_t *o = (oc_otm_ctx_t *)oc_memb_alloc(&oc_otm_ctx_m);
  if (o) {
    oc_list_add(oc_otm_ctx_l, o);
  }
  return o;
}

/* End of utility functions */

/* Ownership Transfer */
static void
free_otm_state(oc_otm_ctx_t *o, int status, oc_obt_otm_t otm)
{
  if (!is_item_in_list(oc_otm_ctx_l, o)) {
    return;
  }
  oc_list_remove(oc_otm_ctx_l, o);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(o->device->endpoint);
  oc_tls_close_connection(ep);
  if (status == -1) {
    char suuid[OC_UUID_LEN];
    oc_uuid_to_str(&o->device->uuid, suuid, OC_UUID_LEN);
    oc_cred_remove_subject(suuid, 0);
    o->cb.cb(&o->device->uuid, status, o->cb.data);
    free_device(o->device);
  } else {
    if (otm != OC_OBT_RDP) {
      oc_list_remove(oc_cache, o->device);
      oc_list_add(oc_devices, o->device);
    }
    o->cb.cb(&o->device->uuid, status, o->cb.data);
  }
  oc_memb_free(&oc_otm_ctx_m, o);
}

void
oc_obt_free_otm_ctx(oc_otm_ctx_t *ctx, int status, oc_obt_otm_t otm)
{
  free_otm_state(ctx, status, otm);
}

/* Device discovery */
/* Owned/Unowned discovery timeout */
static oc_event_callback_retval_t
free_discovery_cb(void *data)
{
  oc_discovery_cb_t *c = (oc_discovery_cb_t *)data;
  if (is_item_in_list(oc_discovery_cbs, c)) {
    oc_list_remove(oc_discovery_cbs, c);
    oc_memb_free(&oc_discovery_s, c);
  }
  return OC_EVENT_DONE;
}

static oc_endpoint_t *
update_endpoint(const oc_rep_t *eps, const oc_endpoint_t *endpoint,
                const oc_uuid_t *di)
{
  for (const oc_rep_t *ep = eps; ep != NULL; ep = ep->next) {
    if (ep->type != OC_REP_STRING &&
        !oc_string_is_cstr_equal(&ep->name, "ep", OC_CHAR_ARRAY_LEN("ep"))) {
      continue;
    }

    oc_endpoint_t temp_ep;
    if (oc_string_to_endpoint(&ep->value.string, &temp_ep, NULL) != 0) {
      OC_ERR("oc_obt: error parsing endpoint");
      continue;
    }
    if (((endpoint->flags & IPV4) && (temp_ep.flags & IPV6)) ||
        ((endpoint->flags & IPV6) && (temp_ep.flags & IPV4))) {
      return NULL;
    }

    oc_endpoint_t *ep_new = oc_new_endpoint();
    if (ep_new == NULL) {
      OC_ERR("oc_obt: cannot allocate endpoint");
      return NULL;
    }

    memcpy(ep_new, &temp_ep, sizeof(oc_endpoint_t));
    ep_new->next = NULL;
    ep_new->device = endpoint->device;
    oc_endpoint_set_di(ep_new, di);
    ep_new->interface_index = endpoint->interface_index;
    oc_endpoint_set_local_address(ep_new, ep_new->interface_index);
    if (oc_ipv6_endpoint_is_link_local(ep_new) == 0 &&
        oc_ipv6_endpoint_is_link_local(endpoint) == 0) {
      ep_new->addr.ipv6.scope = endpoint->addr.ipv6.scope;
    }
    return ep_new;
  }

  return NULL;
}

static void
update_endpoints_from_links(oc_device_t *device, const oc_endpoint_t *endpoint,
                            const oc_uuid_t *di, const oc_rep_t *links)
{
  oc_endpoint_t *eps_cur = NULL;
  for (const oc_rep_t *link = links; link != NULL; link = link->next) {
    if (link->type != OC_REP_OBJECT_ARRAY) {
      continue;
    }
    for (const oc_rep_t *eps = link->value.object_array; eps != NULL;
         eps = eps->next) {
      oc_endpoint_t *ep_new = update_endpoint(eps->value.object, endpoint, di);
      if (ep_new == NULL) {
        continue;
      }

      if (eps_cur != NULL) {
        eps_cur->next = ep_new;
        eps_cur = eps_cur->next;
      } else {
        eps_cur = ep_new;
        device->endpoint = eps_cur;
      }
    }
  }
}

static void
get_endpoints(oc_client_response_t *data)
{
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return;
  }

  oc_rep_t *links = data->payload;
  if (links == NULL) {
    return;
  }
  const oc_string_t *anchor = NULL;
  assert(links->type == OC_REP_OBJECT);
  for (oc_rep_t *link = links->value.object; link != NULL; link = link->next) {
    if (link->type == OC_REP_STRING &&
        oc_string_is_cstr_equal(&link->name, "anchor",
                                OC_CHAR_ARRAY_LEN("anchor"))) {
      anchor = &link->value.string;
      break;
    }
  }

  if (anchor == NULL) {
    return;
  }

  oc_uuid_t di;
  memset(&di, 0, sizeof(oc_uuid_t));
  // skip "ocf://" prefix
  oc_str_to_uuid(oc_string(*anchor) + 6, &di);
  const oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  if (memcmp(my_uuid->id, di.id, OC_ARRAY_SIZE(di.id)) == 0) {
    return;
  }

  oc_discovery_cb_t *cb = NULL;
  oc_device_t *device = NULL;
  const oc_client_cb_t *ccb = (oc_client_cb_t *)data->client_cb;
  if (ccb->multicast) {
    cb = (oc_discovery_cb_t *)data->user_data;
    if (links && oc_obt_is_owned_device(&di)) {
      device = cache_new_device(oc_devices, &di, data->endpoint);
    }
  } else {
    device = (oc_device_t *)data->user_data;
    cb = (oc_discovery_cb_t *)device->ctx;
  }

  if (device == NULL) {
    return;
  }

  oc_free_server_endpoints(device->endpoint);
  device->endpoint = NULL;
  update_endpoints_from_links(device, data->endpoint, &di, links->value.object);

  if (!is_item_in_list(oc_discovery_cbs, cb) || device->endpoint == NULL) {
    return;
  }
  cb->cb(&device->uuid, device->endpoint, cb->data);
}

static void
obt_check_owned(oc_client_response_t *data)
{
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    return;
  }

  oc_uuid_t uuid;
  int owned = -1;
  const oc_rep_t *rep = data->payload;

  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_string_len(rep->name) == 10 &&
          memcmp(oc_string(rep->name), "deviceuuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &uuid);
      }
      break;
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) == 5 &&
          memcmp(oc_string(rep->name), "owned", 5) == 0) {
        owned = (int)rep->value.boolean;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (owned == -1) {
    return;
  }

  const oc_uuid_t *my_uuid = oc_core_get_device_id(0);
  if (memcmp(my_uuid->id, uuid.id, OC_ARRAY_SIZE(uuid.id)) == 0) {
    return;
  }

  oc_device_t *device = NULL;
  if (owned == 0) {
    device = cache_new_device(oc_cache, &uuid, data->endpoint);
  }
  if (device == NULL) {
    return;
  }
  device->ctx = data->user_data;
  if (!oc_do_get("/oic/res", device->endpoint, "rt=oic.r.doxm", &get_endpoints,
                 HIGH_QOS, device)) {
    OC_ERR("Could not send GET request to /oic/res");
  }
}

/* Unowned device discovery */
static int
discover_unowned_devices(uint8_t scope, oc_obt_discovery_cb_t cb, void *data)
{
  oc_discovery_cb_t *c = (oc_discovery_cb_t *)oc_memb_alloc(&oc_discovery_s);
  if (!c) {
    return -1;
  }
  c->cb = cb;
  c->data = data;

  if (scope == 0x02) {
    if (oc_do_ip_multicast("/oic/sec/doxm", "owned=FALSE", &obt_check_owned,
                           c)) {
      oc_list_add(oc_discovery_cbs, c);
      oc_set_delayed_callback(c, free_discovery_cb, DISCOVERY_CB_PERIOD);
      return 0;
    }
  } else if (scope == 0x03) {
    if (oc_do_realm_local_ipv6_multicast("/oic/sec/doxm", "owned=FALSE",
                                         &obt_check_owned, c)) {
      oc_list_add(oc_discovery_cbs, c);
      oc_set_delayed_callback(c, free_discovery_cb, DISCOVERY_CB_PERIOD);
      return 0;
    }
  } else if (scope == 0x05) {
    if (oc_do_site_local_ipv6_multicast("/oic/sec/doxm", "owned=FALSE",
                                        &obt_check_owned, c)) {
      oc_list_add(oc_discovery_cbs, c);
      oc_set_delayed_callback(c, free_discovery_cb, DISCOVERY_CB_PERIOD);
      return 0;
    }
  }

  oc_memb_free(&oc_discovery_s, c);
  return -1;
}

int
oc_obt_discover_unowned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                                 void *data)
{
  return discover_unowned_devices(0x03, cb, data);
}

int
oc_obt_discover_unowned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                                void *data)
{
  return discover_unowned_devices(0x05, cb, data);
}

int
oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t cb, void *data)
{
  return discover_unowned_devices(0x02, cb, data);
}

/* Owned device disvoery */
static int
discover_owned_devices(uint8_t scope, oc_obt_discovery_cb_t cb, void *data)
{
  oc_discovery_cb_t *c = (oc_discovery_cb_t *)oc_memb_alloc(&oc_discovery_s);
  if (!c) {
    return -1;
  }
  c->cb = cb;
  c->data = data;

  if (scope == 0x02) {
    if (oc_do_ip_multicast("/oic/res", "rt=oic.r.doxm", &get_endpoints, c)) {
      oc_list_add(oc_discovery_cbs, c);
      oc_set_delayed_callback(c, free_discovery_cb, DISCOVERY_CB_PERIOD);
      return 0;
    }
  } else if (scope == 0x03) {
    if (oc_do_realm_local_ipv6_multicast("/oic/res", "rt=oic.r.doxm",
                                         &get_endpoints, c)) {
      oc_list_add(oc_discovery_cbs, c);
      oc_set_delayed_callback(c, free_discovery_cb, DISCOVERY_CB_PERIOD);
      return 0;
    }
  } else if (scope == 0x05) {
    if (oc_do_site_local_ipv6_multicast("/oic/res", "rt=oic.r.doxm",
                                        &get_endpoints, c)) {
      oc_list_add(oc_discovery_cbs, c);
      oc_set_delayed_callback(c, free_discovery_cb, DISCOVERY_CB_PERIOD);
      return 0;
    }
  }

  oc_memb_free(&oc_discovery_s, c);
  return -1;
}

int
oc_obt_discover_owned_devices_realm_local_ipv6(oc_obt_discovery_cb_t cb,
                                               void *data)
{
  return discover_owned_devices(0x03, cb, data);
}

int
oc_obt_discover_owned_devices_site_local_ipv6(oc_obt_discovery_cb_t cb,
                                              void *data)
{
  return discover_owned_devices(0x05, cb, data);
}

int
oc_obt_discover_owned_devices(oc_obt_discovery_cb_t cb, void *data)
{
  return discover_owned_devices(0x02, cb, data);
}
/* End of device discovery */

/* Resource discovery */

int
oc_obt_discover_all_resources(const oc_uuid_t *uuid,
                              oc_discovery_all_handler_t handler, void *data)
{
  const oc_endpoint_t *ep = NULL;
  const oc_device_t *device = get_device_handle(uuid, oc_devices);

  if (device) {
    ep = oc_obt_get_secure_endpoint(device->endpoint);
  } else {
    device = get_device_handle(uuid, oc_cache);
    if (device) {
      ep = oc_obt_get_unsecure_endpoint(device->endpoint);
    }
  }

  if (!device || !ep) {
    return -1;
  }

  if (oc_do_ip_discovery_all_at_endpoint(handler, ep, data)) {
    return 0;
  }

  return -1;
}

/* End of resource discovery */

/* Helper sequence to switch between pstat device states */
static void
free_switch_dos_state(oc_switch_dos_ctx_t *d)
{
  if (!is_item_in_list(oc_switch_dos_ctx_l, d)) {
    return;
  }
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
pstat_POST_dos1_to_dos2(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_switch_dos_ctx_l, data->user_data)) {
    return;
  }

  oc_switch_dos_ctx_t *d = (oc_switch_dos_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST && data->code != OC_REQUEST_TIMEOUT) {
    free_switch_dos_ctx(d, -1);
    return;
  }

  free_switch_dos_ctx(d, 0);
}

static oc_switch_dos_ctx_t *
switch_dos(oc_device_t *device, oc_dostype_t dos, oc_obt_status_cb_t cb,
           void *data)
{
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
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

  if (!oc_init_post("/oic/sec/pstat", ep, NULL, &pstat_POST_dos1_to_dos2,
                    HIGH_QOS, d)) {
    OC_ERR("Could not init POST request to /oic/sec/pstat");
    goto err_switch_dos;
  }
  oc_rep_start_root_object();
  oc_rep_set_object(root, dos);
  oc_rep_set_int(dos, s, dos);
  oc_rep_close_object(root, dos);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/pstat");
    goto err_switch_dos;
  }

  oc_list_add(oc_switch_dos_ctx_l, d);
  return d;

err_switch_dos:
  oc_memb_free(&oc_switch_dos_ctx_m, d);
  return NULL;
}
/* End of switch dos sequence */

/* Hard RESET sequence */
static void
free_hard_reset_ctx(oc_hard_reset_ctx_t *ctx, int status)
{
  if (!is_item_in_list(oc_hard_reset_ctx_l, ctx)) {
    return;
  }
  oc_list_remove(oc_hard_reset_ctx_l, ctx);
  oc_device_status_cb_t cb = ctx->cb;
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(ctx->device->endpoint);
  oc_tls_close_connection(ep);
  if (status == 0) {
    /* Remove device's credential from OBT's credential store */
    char subjectuuid[OC_UUID_LEN];
    oc_uuid_to_str(&ctx->device->uuid, subjectuuid, OC_UUID_LEN);
    oc_cred_remove_subject(subjectuuid, 0);
    cb.cb(&ctx->device->uuid, 0, cb.data);
  } else {
    cb.cb(&ctx->device->uuid, -1, cb.data);
  }
  free_device(ctx->device);
  if (ctx->switch_dos) {
    free_switch_dos_state(ctx->switch_dos);
  }
  oc_memb_free(&oc_hard_reset_ctx_m, ctx);
}

static void
hard_reset_cb(int status, void *data)
{
  oc_hard_reset_ctx_t *d = (oc_hard_reset_ctx_t *)data;
  if (!is_item_in_list(oc_hard_reset_ctx_l, d)) {
    return;
  }
  d->switch_dos = NULL;
  free_hard_reset_ctx(data, status);
}

int
oc_obt_device_hard_reset(const oc_uuid_t *uuid, oc_obt_device_status_cb_t cb,
                         void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
    return -1;
  }

  oc_hard_reset_ctx_t *d =
    (oc_hard_reset_ctx_t *)oc_memb_alloc(&oc_hard_reset_ctx_m);
  if (d == NULL) {
    return -1;
  }

  d->cb.cb = cb;
  d->cb.data = data;
  d->device = device;
  d->switch_dos = switch_dos(device, OC_DOS_RESET, hard_reset_cb, d);
  if (d->switch_dos == NULL) {
    oc_memb_free(&oc_hard_reset_ctx_m, d);
    return -1;
  }

  oc_list_add(oc_hard_reset_ctx_l, d);
  return 0;
}
/* End of hard RESET sequence */

#ifdef OC_OSCORE
/* Provision pairwise OSCORE contexts sequence */
static void
free_oscoreprov_state(oc_oscoreprov_ctx_t *p, int status)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, p)) {
    return;
  }
  oc_list_remove(oc_oscoreprov_ctx_l, p);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  oc_tls_close_connection(ep);
  if (p->device2) {
    ep = oc_obt_get_secure_endpoint(p->device2->endpoint);
    oc_tls_close_connection(ep);
  }
  p->cb.cb(status, p->cb.data);
  if (p->switch_dos) {
    free_switch_dos_state(p->switch_dos);
    p->switch_dos = NULL;
  }
  oc_memb_free(&oc_oscoreprov_ctx_m, p);
}

static void
free_oscoreprov_ctx(oc_oscoreprov_ctx_t *ctx, int status)
{
  free_oscoreprov_state(ctx, status);
}

static void
device2oscore_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, data)) {
    return;
  }

  oc_oscoreprov_ctx_t *p = (oc_oscoreprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    free_oscoreprov_ctx(p, 0);
  } else {
    free_oscoreprov_ctx(p, -1);
  }
}

static void
device1oscore_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, data)) {
    return;
  }

  oc_oscoreprov_ctx_t *p = (oc_oscoreprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    p->switch_dos =
      switch_dos(p->device2, OC_DOS_RFNOP, device2oscore_RFNOP, p);
    if (p->switch_dos) {
      return;
    }
  }

  free_oscoreprov_ctx(p, -1);
}

static void
device2oscore_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, data->user_data)) {
    return;
  }

  oc_oscoreprov_ctx_t *p = (oc_oscoreprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_oscoreprov_ctx(p, -1);
    return;
  }

  p->switch_dos = switch_dos(p->device1, OC_DOS_RFNOP, device1oscore_RFNOP, p);
  if (!p->switch_dos) {
    free_oscoreprov_ctx(p, -1);
  }
}

static void
device1oscore_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, data->user_data)) {
    return;
  }

  oc_oscoreprov_ctx_t *p = (oc_oscoreprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_device1oscore_cred;
  }
  char d1uuid[OC_UUID_LEN];
  oc_uuid_to_str(&p->device1->uuid, d1uuid, OC_UUID_LEN);

  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device2->endpoint);
  if (!oc_init_post("/oic/sec/cred", ep, NULL, &device2oscore_cred, HIGH_QOS,
                    p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_device1oscore_cred;
  }

  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, OC_CREDTYPE_OSCORE);
  oc_rep_set_text_string(creds, subjectuuid, d1uuid);

  oc_rep_set_object(creds, privatedata);
  oc_rep_set_byte_string(privatedata, data, p->secret,
                         OSCORE_MASTER_SECRET_LEN);
  oc_rep_set_text_string_v1(privatedata, encoding, OC_ENCODING_RAW_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
  oc_rep_close_object(creds, privatedata);

  oc_rep_set_object(creds, oscore);

  char hex_str[OSCORE_CTXID_LEN * 2 + 1];
  size_t hex_str_len = OC_ARRAY_SIZE(hex_str);
  oc_conv_byte_array_to_hex_string(p->recvid, OSCORE_CTXID_LEN, hex_str,
                                   &hex_str_len);
  oc_rep_set_text_string_v1(oscore, senderid, hex_str, hex_str_len);

  hex_str_len = OC_ARRAY_SIZE(hex_str);
  oc_conv_byte_array_to_hex_string(p->sendid, OSCORE_CTXID_LEN, hex_str,
                                   &hex_str_len);
  oc_rep_set_text_string_v1(oscore, recipientid, hex_str, hex_str_len);

  oc_rep_close_object(creds, oscore);

  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_device1oscore_cred;
  }

  return;

err_device1oscore_cred:
  free_oscoreprov_ctx(p, -1);
}

static void
device2oscore_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, data)) {
    return;
  }

  oc_oscoreprov_ctx_t *p = (oc_oscoreprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status < 0) {
    goto err_device2oscore_RFPRO;
  }

  gen_oscore_ctxid(p->sendid, false);
  gen_oscore_ctxid(p->recvid, false);
  oc_random_buffer(p->secret, OC_ARRAY_SIZE(p->secret));

  char d2uuid[OC_UUID_LEN];
  oc_uuid_to_str(&p->device2->uuid, d2uuid, OC_UUID_LEN);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  if (!oc_init_post("/oic/sec/cred", ep, NULL, &device1oscore_cred, HIGH_QOS,
                    p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_device2oscore_RFPRO;
  }

  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, OC_CREDTYPE_OSCORE);
  oc_rep_set_text_string(creds, subjectuuid, d2uuid);

  oc_rep_set_object(creds, privatedata);
  oc_rep_set_byte_string(privatedata, data, p->secret,
                         OSCORE_MASTER_SECRET_LEN);
  oc_rep_set_text_string_v1(privatedata, encoding, OC_ENCODING_RAW_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
  oc_rep_close_object(creds, privatedata);

  oc_rep_set_object(creds, oscore);

  char hex_str[OSCORE_CTXID_LEN * 2 + 1];
  size_t hex_str_len = OC_ARRAY_SIZE(hex_str);
  oc_conv_byte_array_to_hex_string(p->sendid, OSCORE_CTXID_LEN, hex_str,
                                   &hex_str_len);
  oc_rep_set_text_string_v1(oscore, senderid, hex_str, hex_str_len);

  hex_str_len = OC_ARRAY_SIZE(hex_str);
  oc_conv_byte_array_to_hex_string(p->recvid, OSCORE_CTXID_LEN, hex_str,
                                   &hex_str_len);
  oc_rep_set_text_string_v1(oscore, recipientid, hex_str, hex_str_len);

  oc_rep_close_object(creds, oscore);

  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_device2oscore_RFPRO;
  }

  return;

err_device2oscore_RFPRO:
  free_oscoreprov_state(p, -1);
}

static void
device1oscore_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_oscoreprov_ctx_l, data)) {
    return;
  }
  oc_oscoreprov_ctx_t *p = (oc_oscoreprov_ctx_t *)data;

  p->switch_dos = NULL;
  if (status >= 0) {
    p->switch_dos =
      switch_dos(p->device2, OC_DOS_RFPRO, device2oscore_RFPRO, p);
    if (!p->switch_dos) {
      free_oscoreprov_ctx(p, -1);
    }
  } else {
    free_oscoreprov_ctx(p, -1);
  }
}

int
oc_obt_provision_pairwise_oscore_contexts(const oc_uuid_t *uuid1,
                                          const oc_uuid_t *uuid2,
                                          oc_obt_status_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid1) || !oc_obt_is_owned_device(uuid2)) {
    return -1;
  }

  oc_device_t *device1 = oc_obt_get_owned_device_handle(uuid1);
  if (device1 == NULL) {
    return -1;
  }
  oc_device_t *device2 = oc_obt_get_owned_device_handle(uuid2);
  if (device2 == NULL) {
    return -1;
  }

  oc_oscoreprov_ctx_t *p = oc_memb_alloc(&oc_oscoreprov_ctx_m);
  if (p == NULL) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device1 = device1;
  p->device2 = device2;

  oc_tls_select_psk_ciphersuite();

  p->switch_dos = switch_dos(device1, OC_DOS_RFPRO, device1oscore_RFPRO, p);
  if (p->switch_dos == NULL) {
    oc_memb_free(&oc_oscoreprov_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_oscoreprov_ctx_l, p);
  return 0;
}
/* End of provision pairwise OSCORE contexts sequence */
/* Provision Group OSCORE contexts */
static void
free_oscoregroupprov_state(oc_oscoregroupprov_ctx_t *request, int status)
{
  if (!is_item_in_list(oc_oscoregroupprov_ctx_l, request)) {
    return;
  }
  oc_list_remove(oc_oscoregroupprov_ctx_l, request);
  const oc_endpoint_t *ep =
    oc_obt_get_secure_endpoint(request->device->endpoint);
  oc_tls_close_connection(ep);
  if (request->switch_dos) {
    free_switch_dos_state(request->switch_dos);
  }
  if (oc_string_len(request->desc) > 0) {
    oc_free_string(&request->desc);
  }
  request->cb.cb(&request->device->uuid, status, request->cb.data);
  oc_memb_free(&oc_oscoregroupprov_ctx_m, request);
}

static void
deviceoscoregroup_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_oscoregroupprov_ctx_l, data)) {
    return;
  }

  oc_oscoregroupprov_ctx_t *p = (oc_oscoregroupprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    free_oscoregroupprov_state(p, 0);
  } else {
    free_oscoregroupprov_state(p, -1);
  }
}

static void
deviceoscoregroup_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_oscoregroupprov_ctx_l, data->user_data)) {
    return;
  }

  oc_oscoregroupprov_ctx_t *p = (oc_oscoregroupprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_oscoregroupprov_state(p, -1);
    return;
  }

  p->switch_dos =
    switch_dos(p->device, OC_DOS_RFNOP, deviceoscoregroup_RFNOP, p);
  if (!p->switch_dos) {
    free_oscoregroupprov_state(p, -1);
  }
}

static void
deviceoscoregroup_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_oscoregroupprov_ctx_l, data)) {
    return;
  }
  oc_oscoregroupprov_ctx_t *p = (oc_oscoregroupprov_ctx_t *)data;
  p->switch_dos = NULL;

  if (status < 0) {
    goto err_deviceoscoregroup_RFPRO;
  }

  char groupsub[OC_UUID_LEN];
  oc_uuid_to_str(&p->subjectuuid, groupsub, OC_UUID_LEN);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device->endpoint);
  if (!oc_init_post("/oic/sec/cred", ep, NULL, &deviceoscoregroup_cred,
                    HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_deviceoscoregroup_RFPRO;
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, p->type);
  oc_rep_set_text_string(creds, subjectuuid, groupsub);

  oc_rep_set_object(creds, privatedata);
  oc_rep_set_byte_string(privatedata, data, g_group_secret,
                         OSCORE_MASTER_SECRET_LEN);
  oc_rep_set_text_string_v1(privatedata, encoding, OC_ENCODING_RAW_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
  oc_rep_close_object(creds, privatedata);

  oc_rep_set_object(creds, oscore);

  char hex_str[OSCORE_CTXID_LEN * 2 + 1];
  size_t hex_str_len = OC_ARRAY_SIZE(hex_str);
  oc_conv_byte_array_to_hex_string(g_groupid, OSCORE_CTXID_LEN, hex_str,
                                   &hex_str_len);
  if (p->type == OC_CREDTYPE_OSCORE_MCAST_CLIENT) {
    oc_rep_set_text_string_v1(oscore, senderid, hex_str, hex_str_len);
  } else {
    oc_rep_set_text_string_v1(oscore, recipientid, hex_str, hex_str_len);
  }
  oc_rep_set_text_string_v1(oscore, desc, oc_string(p->desc),
                            oc_string_len(p->desc));
  oc_rep_close_object(creds, oscore);
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_deviceoscoregroup_RFPRO;
  }

  return;

err_deviceoscoregroup_RFPRO:
  free_oscoregroupprov_state(p, -1);
}

static int
obt_provision_group_oscore_context(const oc_uuid_t *uuid,
                                   const oc_uuid_t *subjectuuid,
                                   const char *desc,
                                   oc_obt_device_status_cb_t cb,
                                   oc_sec_credtype_t type, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
    return -1;
  }

  oc_oscoregroupprov_ctx_t *p = oc_memb_alloc(&oc_oscoregroupprov_ctx_m);
  if (p == NULL) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device = device;
  p->type = type;
  if (desc) {
    oc_new_string(&p->desc, desc, strlen(desc));
  }
  memcpy(p->subjectuuid.id, subjectuuid->id, OC_ARRAY_SIZE(subjectuuid->id));

  oc_tls_select_psk_ciphersuite();

  p->switch_dos = switch_dos(device, OC_DOS_RFPRO, deviceoscoregroup_RFPRO, p);
  if (!p->switch_dos) {
    oc_free_string(&p->desc);
    oc_memb_free(&oc_oscoregroupprov_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_oscoregroupprov_ctx_l, p);
  return 0;
}

int
oc_obt_provision_client_group_oscore_context(const oc_uuid_t *uuid,
                                             const char *desc,
                                             oc_obt_device_status_cb_t cb,
                                             void *data)
{
  oc_uuid_t subjectuuid;
  memset(&subjectuuid, 0, sizeof(oc_uuid_t));
  memcpy(subjectuuid.id, g_groupid, OSCORE_CTXID_LEN);
  memcpy(subjectuuid.id + OSCORE_CTXID_LEN, g_groupid, OSCORE_CTXID_LEN);
  return obt_provision_group_oscore_context(
    uuid, &subjectuuid, desc, cb, OC_CREDTYPE_OSCORE_MCAST_CLIENT, data);
}

int
oc_obt_provision_server_group_oscore_context(const oc_uuid_t *uuid,
                                             const oc_uuid_t *subjectuuid,
                                             const char *desc,
                                             oc_obt_device_status_cb_t cb,
                                             void *data)
{
  return obt_provision_group_oscore_context(
    uuid, subjectuuid, desc, cb, OC_CREDTYPE_OSCORE_MCAST_SERVER, data);
}
/* End of provision group OSCORE contexts */
#endif /* OC_OSCORE */

/* Provision pairwise credentials sequence */
static void
free_credprov_state(oc_credprov_ctx_t *p, int status)
{
  if (!is_item_in_list(oc_credprov_ctx_l, p)) {
    return;
  }
  oc_list_remove(oc_credprov_ctx_l, p);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  oc_tls_close_connection(ep);
  if (p->device2) {
    ep = oc_obt_get_secure_endpoint(p->device2->endpoint);
    oc_tls_close_connection(ep);
  }
  p->cb.cb(status, p->cb.data);
#ifdef OC_PKI
  if (p->roles) {
    oc_obt_free_roleid(p->roles);
    p->roles = NULL;
  }
#endif /* OC_PKI */
  if (p->switch_dos) {
    free_switch_dos_state(p->switch_dos);
    p->switch_dos = NULL;
  }
  oc_memb_free(&oc_credprov_ctx_m, p);
}

static void
free_credprov_ctx(oc_credprov_ctx_t *ctx, int status)
{
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
    goto err_device2_cred;
  }

  p->switch_dos = switch_dos(p->device1, OC_DOS_RFNOP, device1_RFNOP, p);
  if (!p->switch_dos) {
    goto err_device2_cred;
  }

  return;

err_device2_cred:
  free_credprov_ctx(p, -1);
}

static void
device1_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_device1_cred;
  }

  char d1uuid[OC_UUID_LEN];
  oc_uuid_to_str(&p->device1->uuid, d1uuid, OC_UUID_LEN);

  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device2->endpoint);

  if (!oc_init_post("/oic/sec/cred", ep, NULL, &device2_cred, HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_device1_cred;
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, 1);
  oc_rep_set_text_string(creds, subjectuuid, d1uuid);

  oc_rep_set_object(creds, privatedata);
  oc_rep_set_byte_string(privatedata, data, p->key, OC_ARRAY_SIZE(p->key));
  oc_rep_set_text_string_v1(privatedata, encoding, OC_ENCODING_RAW_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
  oc_rep_close_object(creds, privatedata);

  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_device1_cred;
  }

  return;

err_device1_cred:
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

  if (status < 0) {
    OC_DBG("Could not switch device2 to RFPRO");
    goto err_device2_RFPRO;
  }
  oc_random_buffer(p->key, OC_ARRAY_SIZE(p->key));

  char d2uuid[OC_UUID_LEN];
  oc_uuid_to_str(&p->device2->uuid, d2uuid, OC_UUID_LEN);

  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);

  if (!oc_init_post("/oic/sec/cred", ep, NULL, &device1_cred, HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_device2_RFPRO;
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, 1);
  oc_rep_set_text_string_v1(creds, subjectuuid, d2uuid,
                            oc_strnlen(d2uuid, OC_UUID_LEN));

  oc_rep_set_object(creds, privatedata);
  oc_rep_set_byte_string(privatedata, data, p->key, OC_ARRAY_SIZE(p->key));
  oc_rep_set_text_string_v1(privatedata, encoding, OC_ENCODING_RAW_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
  oc_rep_close_object(creds, privatedata);

  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_device2_RFPRO;
  }

  return;

err_device2_RFPRO:
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
  } else {
    free_credprov_ctx(p, -1);
  }
}

int
oc_obt_provision_pairwise_credentials(const oc_uuid_t *uuid1,
                                      const oc_uuid_t *uuid2,
                                      oc_obt_status_cb_t cb, void *data)
{

  if (!oc_obt_is_owned_device(uuid1) || !oc_obt_is_owned_device(uuid2)) {
    return -1;
  }

  oc_device_t *device1 = oc_obt_get_owned_device_handle(uuid1);
  if (device1 == NULL) {
    return -1;
  }

  oc_device_t *device2 = oc_obt_get_owned_device_handle(uuid2);
  if (device2 == NULL) {
    return -1;
  }

  oc_credprov_ctx_t *p = oc_memb_alloc(&oc_credprov_ctx_m);
  if (p == NULL) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device1 = device1;
  p->device2 = device2;

  oc_tls_select_psk_ciphersuite();

  p->switch_dos = switch_dos(device1, OC_DOS_RFPRO, device1_RFPRO, p);
  if (p->switch_dos == NULL) {
    oc_memb_free(&oc_credprov_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_credprov_ctx_l, p);
  return 0;
}
/* End of provision pairwise credentials sequence */

#ifdef OC_PKI
/* Provision trust anchor sequence */
static void
free_trustanchor_state(oc_trustanchor_ctx_t *p, int status)
{
  if (!is_item_in_list(oc_installtrust_ctx_l, p)) {
    return;
  }
  oc_list_remove(oc_installtrust_ctx_l, p);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  oc_tls_close_connection(ep);

  p->cb.cb(status, p->cb.data);

  if (p->switch_dos) {
    free_switch_dos_state(p->switch_dos);
    p->switch_dos = NULL;
  }
  oc_memb_free(&oc_installtrust_ctx_m, p);
}

/* Construct list of role ids to encode into a role certificate */
oc_role_t *
oc_obt_add_roleid(oc_role_t *roles, const char *role, const char *authority)
{
  oc_role_t *roleid = (oc_role_t *)oc_memb_alloc(&oc_roles);
  if (roleid) {
    oc_new_string(&roleid->role, role, strlen(role));
    if (authority) {
      oc_new_string(&roleid->authority, authority, strlen(authority));
    }
    roleid->next = roles;
  }
  return roleid;
}

void
oc_obt_free_roleid(oc_role_t *roles)
{
  oc_role_t *r = roles;
  while (r) {
    oc_role_t *next = r->next;
    oc_free_string(&r->role);
    oc_free_string(&r->authority);
    oc_memb_free(&oc_roles, r);
    r = next;
  }
}

/* Provision identity/role certificates */

static void
device_RFNOP(int status, void *data)
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
device_authcrypt_roles(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_device_authcrypt_roles;
  }

  /**  7) switch dos to RFNOP
   */
  p->switch_dos = switch_dos(p->device1, OC_DOS_RFNOP, device_RFNOP, p);
  if (p->switch_dos) {
    return;
  }

err_device_authcrypt_roles:
  free_credprov_ctx(p, -1);
}

static void
device_cred(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_device_cred;
  }

  /**  6) post acl2 with auth-crypt RW ACE for /oic/sec/roles
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  if (!oc_init_post("/oic/sec/acl2", ep, NULL, &device_authcrypt_roles,
                    HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/acl2");
    goto err_device_cred;
  }
  oc_rep_start_root_object();

  oc_rep_set_array(root, aclist2);
  oc_rep_object_array_start_item(aclist2);

  oc_rep_set_object(aclist2, subject);
  oc_rep_set_text_string_v1(subject, conntype, "auth-crypt",
                            OC_CHAR_ARRAY_LEN("auth-crypt"));
  oc_rep_close_object(aclist2, subject);

  oc_rep_set_array(aclist2, resources);
  oc_rep_object_array_start_item(resources);
  oc_rep_set_text_string_v1(resources, href, OCF_SEC_ROLES_URI,
                            OC_CHAR_ARRAY_LEN(OCF_SEC_ROLES_URI));
  oc_rep_object_array_end_item(resources);
  oc_rep_close_array(aclist2, resources);

  oc_rep_set_uint(aclist2, permission, OC_PERM_RETRIEVE | OC_PERM_UPDATE);

  oc_rep_object_array_end_item(aclist2);
  oc_rep_close_array(root, aclist2);

  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/acl2");
    goto err_device_cred;
  }

  return;

err_device_cred:
  free_credprov_ctx(p, -1);
}

static int
device_generate_cert_for_CSR(const unsigned char *csr, size_t csr_len,
                             const oc_role_t *roles, unsigned char *pem_buffer,
                             size_t pem_buffer_size)
{
  mbedtls_x509_csr c;
  int ret = mbedtls_x509_csr_parse(&c, csr, csr_len);
  if (ret < 0) {
    OC_ERR("unable to parse CSR %d", ret);
    return -1;
  }

  /**  5) validate csr
   */
  if (!oc_sec_csr_validate(&c, MBEDTLS_PK_ECKEY,
                           oc_sec_certs_md_algorithms_allowed())) {
    goto err_device_generate_cert_for_CSR;
  }

  char subject[512] = { 0 };
  if (oc_sec_csr_extract_subject_DN(&c, subject, OC_ARRAY_SIZE(subject)) < 0) {
    goto err_device_generate_cert_for_CSR;
  }

  uint8_t pub_key[OC_ECDSA_PUBKEY_SIZE] = { 0 };
  ret = oc_sec_csr_extract_public_key(&c, pub_key, OC_ARRAY_SIZE(pub_key));
  if (ret < 0) {
    goto err_device_generate_cert_for_CSR;
  }
  size_t pub_key_size = (size_t)ret;

  if (roles == NULL) {
    /**  5) generate identity cert
     */
    oc_obt_generate_identity_cert_data_t gen = {
      .subject_name = subject,
      .public_key = pub_key,
      .public_key_size = pub_key_size,
      .issuer_name = g_root_subject,
      .issuer_private_key = g_private_key,
      .issuer_private_key_size = g_private_key_size,
      .signature_md_alg = oc_sec_certs_md_signature_algorithm(),
    };
    ret = oc_obt_generate_identity_cert_pem(gen, pem_buffer, pem_buffer_size);
    if (ret < 0) {
      goto err_device_generate_cert_for_CSR;
    }
    mbedtls_x509_csr_free(&c);
    return ret;
  }
  /**  5) generate role cert
   */
  oc_obt_generate_role_cert_data_t gen = {
    .roles = roles,
    .subject_name = subject,
    .public_key = pub_key,
    .public_key_size = pub_key_size,
    .issuer_name = g_root_subject,
    .issuer_private_key = g_private_key,
    .issuer_private_key_size = g_private_key_size,
    .signature_md_alg = oc_sec_certs_md_signature_algorithm(),
  };
  ret = oc_obt_generate_role_cert_pem(gen, pem_buffer, pem_buffer_size);
  if (ret < 0) {
    goto err_device_generate_cert_for_CSR;
  }
  mbedtls_x509_csr_free(&c);
  return ret;

err_device_generate_cert_for_CSR:
  mbedtls_x509_csr_free(&c);
  return -1;
}

static void
device_CSR(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;
  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_device_CSR;
  }

  size_t enc_len = 0;
  char *enc = NULL;
  if (!oc_rep_get_string(data->payload, "encoding", &enc, &enc_len) ||
      enc_len == 0) {
    goto err_device_CSR;
  }
  oc_sec_encoding_t encoding = oc_cred_encoding_from_string(enc, enc_len);
  if (encoding != OC_ENCODING_PEM) {
    goto err_device_CSR;
  }

  size_t csr_len = 0;
  char *csr = NULL;
  if (!oc_rep_get_string(data->payload, "csr", &csr, &csr_len)) {
    goto err_device_CSR;
  }
  csr_len++;

  unsigned char cert_pem[4096] = { '\0' };
  int ret =
    device_generate_cert_for_CSR((const unsigned char *)csr, csr_len, p->roles,
                                 cert_pem, OC_ARRAY_SIZE(cert_pem));
  if (ret < 0) {
    goto err_device_CSR;
  }

  /**  5) post cred with identity/role cert
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);

  if (!oc_init_post("/oic/sec/cred", ep, NULL, &device_cred, HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_device_CSR;
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, OC_CREDTYPE_CERT);
  oc_rep_set_text_string_v1(creds, subjectuuid, "*", OC_CHAR_ARRAY_LEN("*"));

  oc_rep_set_object(creds, publicdata);
  oc_rep_set_text_string(publicdata, data, (const char *)cert_pem);
  oc_rep_set_text_string_v1(publicdata, encoding, OC_ENCODING_PEM_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_PEM_STR));
  oc_rep_close_object(creds, publicdata);
  if (p->roles) {
    oc_rep_set_text_string_v1(creds, credusage, OC_CREDUSAGE_ROLE_CERT_STR,
                              OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_ROLE_CERT_STR));
  } else {
    oc_rep_set_text_string_v1(
      creds, credusage, OC_CREDUSAGE_IDENTITY_CERT_STR,
      OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_IDENTITY_CERT_STR));
  }
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_device_CSR;
  }

  return;

err_device_CSR:
  free_credprov_state(p, -1);
}

static void
device_root(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_device_root;
  }

  /**  4) get csr
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  if (!oc_do_get(OCF_SEC_CSR_URI, ep, NULL, &device_CSR, HIGH_QOS, p)) {
    OC_ERR("Could not issue GET request to /oic/sec/csr");
    goto err_device_root;
  }

  return;

err_device_root:
  free_credprov_ctx(p, -1);
}

static void
device_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data;

  p->switch_dos = NULL;
  if (status < 0) {
    OC_DBG("Could not switch device to RFPRO");
    goto err_device_RFPRO;
  }
  const oc_sec_cred_t *root = oc_sec_get_cred_by_credid(g_root_cert_credid, 0);
  if (!root) {
    OC_ERR("Could not get root cert");
    goto err_device_RFPRO;
  }

  /**  3) post cred with trustca
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  if (!oc_init_post("/oic/sec/cred", ep, NULL, &device_root, HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_device_RFPRO;
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, OC_CREDTYPE_CERT);
  oc_rep_set_text_string_v1(creds, subjectuuid, "*", OC_CHAR_ARRAY_LEN("*"));

  oc_rep_set_object(creds, publicdata);
  oc_rep_set_text_string_v1(publicdata, data, oc_string(root->publicdata.data),
                            oc_string_len(root->publicdata.data));
  oc_rep_set_text_string_v1(publicdata, encoding, OC_ENCODING_PEM_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_PEM_STR));
  oc_rep_close_object(creds, publicdata);

  oc_rep_set_text_string_v1(creds, credusage, OC_CREDUSAGE_TRUSTCA_STR,
                            OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_TRUSTCA_STR));

  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_device_RFPRO;
  }

  return;

err_device_RFPRO:
  free_credprov_state(p, -1);
}

static void
supports_cert_creds(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_credprov_ctx_l, data->user_data)) {
    return;
  }

  oc_credprov_ctx_t *p = (oc_credprov_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_supports_cert_creds;
  }

  int64_t sct = 0;
  if (oc_rep_get_int(data->payload, "sct", &sct)) {
    /* Confirm that the device handles certificate credentials */
    if (sct & 0x0000000000000008) {
      /**  2) switch dos to RFPRO
       */
      p->switch_dos = switch_dos(p->device1, OC_DOS_RFPRO, device_RFPRO, p);
      if (p->switch_dos) {
        return;
      }
    }
  }

err_supports_cert_creds:
  free_credprov_state(p, -1);
}

/*
  Provision role certificate:
  1) get doxm
  2) switch dos to RFPRO
  3) post cred with trustca
  4) get csr
  5) validate csr, generate role cert, post cred with role cert
  6) post acl2 with auth-crypt RW ACE for /oic/sec/roles
  7) switch dos to RFNOP
*/
int
oc_obt_provision_role_certificate(oc_role_t *roles, const oc_uuid_t *uuid,
                                  oc_obt_status_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    OC_ERR("device is not owned");
    return -1;
  }
  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
    OC_ERR("could not obtain device handle");
    return -1;
  }

  oc_credprov_ctx_t *p = oc_memb_alloc(&oc_credprov_ctx_m);
  if (p == NULL) {
    OC_ERR("could not allocate API context");
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device1 = device;
  p->device2 = NULL;
  p->roles = roles;

  oc_tls_select_psk_ciphersuite();

  /**  1) get doxm
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_do_get("/oic/sec/doxm", ep, NULL, &supports_cert_creds, HIGH_QOS,
                 p)) {
    OC_ERR("Could not issue GET request to /oic/sec/doxm");
    oc_memb_free(&oc_credprov_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_credprov_ctx_l, p);
  return 0;
}

/*
  Provision identity certificate:
  1) switch dos to RFPRO
  2) post cred with trustca
  3) get csr
  4) validate csr, generate identity cert, post cred with identity cert
  5) post acl2 with auth-crypt RW ACE for /oic/sec/roles
  6) switch dos to RFNOP
*/
int
oc_obt_provision_identity_certificate(const oc_uuid_t *uuid,
                                      oc_obt_status_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
    return -1;
  }

  oc_credprov_ctx_t *p = oc_memb_alloc(&oc_credprov_ctx_m);
  if (p == NULL) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device1 = device;
  p->device2 = NULL;

  oc_tls_select_psk_ciphersuite();

  /**  1) get doxm
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_do_get("/oic/sec/doxm", ep, NULL, &supports_cert_creds, HIGH_QOS,
                 p)) {
    OC_ERR("Could not issue GET request to /oic/sec/doxm");
    oc_memb_free(&oc_credprov_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_credprov_ctx_l, p);
  return 0;
}

static void
trustanchor_device_RFNOP_complete(int status, void *response_data)
{
  oc_trustanchor_ctx_t *p = (oc_trustanchor_ctx_t *)response_data;
  p->switch_dos = NULL;

  if (status >= 0) {
    free_trustanchor_state(p, 0);
  } else {
    free_trustanchor_state(p, -1);
  }
}

static void
trustanchor_device_RFNOP(oc_client_response_t *data)
{
  OC_DBG("trustanchor_device_RFNOP");
  if (!is_item_in_list(oc_installtrust_ctx_l, data->user_data)) {
    return;
  }

  oc_trustanchor_ctx_t *p = (oc_trustanchor_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_trustanchor_device_RFNOP;
  }

  p->switch_dos =
    switch_dos(p->device1, OC_DOS_RFNOP, trustanchor_device_RFNOP_complete, p);
  if (p->switch_dos) {
    return;
  }

err_trustanchor_device_RFNOP:
  free_trustanchor_state(p, -1);
}

static void
// trustanchor_device_RFPRO(oc_client_response_t* response_data)
trustanchor_device_RFPRO(int status, void *response_data)
{
  OC_DBG("trustanchor_device_RFPRO");
  if (!is_item_in_list(oc_installtrust_ctx_l, response_data)) {
    return;
  }

  oc_trustanchor_ctx_t *p = (oc_trustanchor_ctx_t *)response_data;
  if (status < 0) {
    goto err_trustanchor_device_RFPRO;
  }
  const oc_sec_cred_t *root = oc_sec_get_cred_by_credid(g_root_cert_credid, 0);
  if (!root) {
    goto err_trustanchor_device_RFPRO;
  }

  /**  3) post cred with trustca
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device1->endpoint);
  if (!oc_init_post("/oic/sec/cred", ep, NULL, &trustanchor_device_RFNOP,
                    HIGH_QOS, p)) {
    OC_ERR("Could not init POST request to /oic/sec/cred");
    goto err_trustanchor_device_RFPRO;
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, OC_CREDTYPE_CERT);
  oc_rep_set_text_string(creds, subjectuuid, p->trustanchor_subject);

  oc_rep_set_object(creds, publicdata);
  oc_rep_set_text_string(publicdata, data, p->trustanchor);
  oc_rep_set_text_string_v1(publicdata, encoding, OC_ENCODING_PEM_STR,
                            OC_CHAR_ARRAY_LEN(OC_ENCODING_PEM_STR));
  oc_rep_close_object(creds, publicdata);

  oc_rep_set_text_string_v1(creds, credusage, OC_CREDUSAGE_TRUSTCA_STR,
                            OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_TRUSTCA_STR));

  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/cred");
    goto err_trustanchor_device_RFPRO;
  }

  return;

err_trustanchor_device_RFPRO:
  free_trustanchor_state(p, -1);
}

static void
trustanchor_supports_cert_creds(oc_client_response_t *data)
{
  OC_DBG("trustanchor_supports_cert_creds");
  if (!is_item_in_list(oc_installtrust_ctx_l, data->user_data)) {
    return;
  }

  oc_trustanchor_ctx_t *p = (oc_trustanchor_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    goto err_trustanchor_supports_cert_creds;
  }

  int64_t sct = 0;
  if (oc_rep_get_int(data->payload, "sct", &sct)) {
    /* Confirm that the device handles certificate credentials */
    if (sct & 0x0000000000000008) {
      /**  2) switch dos to RFPRO
       */
      p->switch_dos =
        switch_dos(p->device1, OC_DOS_RFPRO, trustanchor_device_RFPRO, p);
      if (p->switch_dos) {
        return;
      }
    }
  }

err_trustanchor_supports_cert_creds:
  free_trustanchor_state(p, -1);
  // oc_memb_free(&oc_trustanchor_ctx_t, p);
}

/*
  Provision trust anchor (certificate):
  1) check if creds is supported
  2) switch dos to RFPRO
  2) post cred with trustca
  3) switch dos to RFNOP
*/
int
oc_obt_provision_trust_anchor(const char *certificate, size_t certificate_size,
                              const char *subject, const oc_uuid_t *uuid,
                              oc_obt_status_cb_t cb, void *data)
{
  OC_DBG("oc_obt_provision_trust_anchor");
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }
  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
    return -1;
  }

  oc_trustanchor_ctx_t *p = oc_memb_alloc(&oc_installtrust_ctx_m);
  if (p == NULL) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->trustanchor = certificate;
  p->trustanchor_size = certificate_size;
  strcpy(p->trustanchor_subject, subject);
  p->device1 = device;
  oc_tls_select_psk_ciphersuite();

  /**  1) check if certificates is supported
   */
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_do_get("/oic/sec/doxm", ep, NULL, &trustanchor_supports_cert_creds,
                 HIGH_QOS, p)) {
    OC_ERR("Could not issue GET request to /oic/sec/doxm");
    oc_memb_free(&oc_installtrust_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_installtrust_ctx_l, p);
  return 0;
}

#endif /* OC_PKI */

/* Provision role ACE for wildcard "*" resource with RW permissions */
int
oc_obt_provision_role_wildcard_ace(const oc_uuid_t *subject, const char *role,
                                   const char *authority,
                                   oc_obt_device_status_cb_t cb, void *data)
{
  oc_sec_ace_t *ace = oc_obt_new_ace_for_role(role, authority);
  if (ace == NULL) {
    goto error;
  }

  oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
  if (res == NULL) {
    goto error;
  }

  oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL);
  oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE | OC_PERM_UPDATE);

  if (oc_obt_provision_ace(subject, ace, cb, data) < 0) {
    goto error;
  }
  return 0;

error:
  oc_obt_free_ace(ace);
  return -1;
}

/* Provision auth-crypt ACE for the wildcard "*" resource with RW permissions */
int
oc_obt_provision_auth_wildcard_ace(const oc_uuid_t *subject,
                                   oc_obt_device_status_cb_t cb, void *data)
{
  oc_sec_ace_t *ace = oc_obt_new_ace_for_connection(OC_CONN_AUTH_CRYPT);
  if (ace == NULL) {
    return -1;
  }

  oc_ace_res_t *res = oc_obt_ace_new_resource(ace);
  if (res == NULL) {
    goto error;
  }

  oc_obt_ace_resource_set_wc(res, OC_ACE_WC_ALL);
  oc_obt_ace_add_permission(ace, OC_PERM_RETRIEVE | OC_PERM_UPDATE);

  if (oc_obt_provision_ace(subject, ace, cb, data) < 0) {
    goto error;
  }
  return 0;

error:
  oc_obt_free_ace(ace);
  return -1;
}

/* Provision access-control entries */
static oc_sec_ace_t *
oc_obt_new_ace(void)
{
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_memb_alloc(&oc_aces_m);
  if (ace) {
    OC_LIST_STRUCT_INIT(ace, resources);
  }
  return ace;
}

oc_sec_ace_t *
oc_obt_new_ace_for_subject(const oc_uuid_t *uuid)
{
  oc_sec_ace_t *ace = oc_obt_new_ace();
  if (ace) {
    ace->subject_type = OC_SUBJECT_UUID;
    memcpy(ace->subject.uuid.id, uuid->id, OC_ARRAY_SIZE(uuid->id));
  }
  return ace;
}

oc_sec_ace_t *
oc_obt_new_ace_for_role(const char *role, const char *authority)
{
  if (!role) {
    return NULL;
  }
  oc_sec_ace_t *ace = oc_obt_new_ace();
  if (ace) {
    ace->subject_type = OC_SUBJECT_ROLE;
    oc_new_string(&ace->subject.role.role, role, strlen(role));
    if (authority) {
      oc_new_string(&ace->subject.role.authority, authority, strlen(authority));
    }
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
    oc_free_string(&resource->href);
    oc_new_string(&resource->href, href, strlen(href));
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
      oc_free_string(&res->href);
      oc_memb_free(&oc_res_m, res);
      res = (oc_ace_res_t *)oc_list_pop(ace->resources);
    }
    if (ace->subject_type == OC_SUBJECT_ROLE) {
      oc_free_string(&ace->subject.role.role);
      oc_free_string(&ace->subject.role.authority);
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
  if (!is_item_in_list(oc_acl2prov_ctx_l, request)) {
    return;
  }
  oc_list_remove(oc_acl2prov_ctx_l, request);
  free_ace(request->ace);
  const oc_endpoint_t *ep =
    oc_obt_get_secure_endpoint(request->device->endpoint);
  oc_tls_close_connection(ep);
  if (request->switch_dos) {
    free_switch_dos_state(request->switch_dos);
  }
  request->cb.cb(&request->device->uuid, status, request->cb.data);
  oc_memb_free(&oc_acl2prov_ctx_m, request);
}

static void
free_acl2prov_ctx(oc_acl2prov_ctx_t *r, int status)
{
  free_acl2prov_state(r, status);
}

static void
provision_ace_complete(int status, void *data)
{
  if (!is_item_in_list(oc_acl2prov_ctx_l, data)) {
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
  if (!is_item_in_list(oc_acl2prov_ctx_l, data->user_data)) {
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
  if (!is_item_in_list(oc_acl2prov_ctx_l, data)) {
    return;
  }

  oc_acl2prov_ctx_t *r = (oc_acl2prov_ctx_t *)data;
  r->switch_dos = NULL;

  if (status < 0) {
    goto err_provision_ace;
  }
  const oc_device_t *device = r->device;
  oc_sec_ace_t *ace = r->ace;

  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_init_post("/oic/sec/acl2", ep, NULL, &acl2_response, HIGH_QOS, r)) {
    OC_ERR("Could not init POST request to /oic/sec/acl2");
    goto err_provision_ace;
  }

  oc_rep_start_root_object();
  oc_rep_set_array(root, aclist2);
  oc_rep_object_array_start_item(aclist2);

  oc_rep_set_object(aclist2, subject);
  switch (ace->subject_type) {
  case OC_SUBJECT_UUID: {
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(&ace->subject.uuid, uuid, OC_UUID_LEN);
    oc_rep_set_text_string_v1(subject, uuid, uuid, OC_UUID_LEN);
  } break;
  case OC_SUBJECT_CONN: {
    switch (ace->subject.conn) {
    case OC_CONN_AUTH_CRYPT:
      oc_rep_set_text_string_v1(subject, conntype, "auth-crypt",
                                OC_CHAR_ARRAY_LEN("auth-crypt"));
      break;
    case OC_CONN_ANON_CLEAR:
      oc_rep_set_text_string_v1(subject, conntype, "anon-clear",
                                OC_CHAR_ARRAY_LEN("anon-clear"));
      break;
    }
  } break;
  case OC_SUBJECT_ROLE: {
    oc_rep_set_text_string_v1(subject, role, oc_string(ace->subject.role.role),
                              oc_string_len(ace->subject.role.role));
    if (oc_string_len(ace->subject.role.authority) > 0) {
      oc_rep_set_text_string_v1(subject, authority,
                                oc_string(ace->subject.role.authority),
                                oc_string_len(ace->subject.role.authority));
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
    if (oc_string_len(res->href) > 0) {
      oc_rep_set_text_string_v1(resources, href, oc_string(res->href),
                                oc_string_len(res->href));
    } else {
      switch (res->wildcard) {
      case OC_ACE_WC_ALL_SECURED:
        oc_rep_set_text_string_v1(resources, wc, "+", OC_CHAR_ARRAY_LEN("+"));
        break;
      case OC_ACE_WC_ALL_PUBLIC:
        oc_rep_set_text_string_v1(resources, wc, "-", OC_CHAR_ARRAY_LEN("-"));
        break;
      case OC_ACE_WC_ALL:
        oc_rep_set_text_string_v1(resources, wc, "*", OC_CHAR_ARRAY_LEN("*"));
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

  oc_rep_object_array_end_item(aclist2);
  oc_rep_close_array(root, aclist2);

  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_ERR("Could not do POST request to /oic/sec/acl2");
    goto err_provision_ace;
  }

  return;

err_provision_ace:
  free_acl2prov_ctx(r, -1);
}

int
oc_obt_provision_ace(const oc_uuid_t *uuid, oc_sec_ace_t *ace,
                     oc_obt_device_status_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }
  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
    return -1;
  }

  oc_acl2prov_ctx_t *r = (oc_acl2prov_ctx_t *)oc_memb_alloc(&oc_acl2prov_ctx_m);
  if (r == NULL) {
    return -1;
  }

  r->cb.cb = cb;
  r->cb.data = data;
  r->ace = ace;
  r->device = device;

  oc_tls_select_psk_ciphersuite();

  r->switch_dos = switch_dos(device, OC_DOS_RFPRO, provision_ace, r);
  if (r->switch_dos == NULL) {
    oc_memb_free(&oc_acl2prov_ctx_m, r);
    return -1;
  }

  oc_list_add(oc_acl2prov_ctx_l, r);
  return 0;
}
/* End of provision ACE sequence */

/* Retrieving credentials */

void
oc_obt_free_creds(oc_sec_creds_t *creds)
{
  oc_sec_cred_t *cred = oc_list_head(creds->creds);
  while (cred != NULL) {
    oc_sec_cred_t *next = cred->next;
    oc_free_string(&cred->role.role);
    oc_free_string(&cred->role.authority);
    oc_free_string(&cred->privatedata.data);
#ifdef OC_PKI
    oc_free_string(&cred->publicdata.data);
#endif /* OC_PKI */
    oc_memb_free(&oc_cred_m, cred);
    cred = next;
  }
  oc_memb_free(&oc_creds_m, creds);
}

static bool
decode_cred(oc_rep_t *rep, oc_sec_creds_t *creds)
{
  size_t len = 0;

  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    /* rowneruuid */
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &creds->rowneruuid);
      }
      break;
    /* creds */
    case OC_REP_OBJECT_ARRAY: {
      if (len == 5 && (memcmp(oc_string(rep->name), "creds", 5) == 0 ||
                       memcmp(oc_string(rep->name), "roles", 5) == 0)) {
        oc_rep_t *creds_array = rep->value.object_array;
        /* array of oic.sec.cred */
        while (creds_array != NULL) {
          oc_sec_cred_t *cr = (oc_sec_cred_t *)oc_memb_alloc(&oc_cred_m);
          if (!cr) {
            goto error_decode_cred;
          }
          oc_list_add(creds->creds, cr);
          oc_rep_t *cred = creds_array->value.object;
          while (cred != NULL) {
            len = oc_string_len(cred->name);
            switch (cred->type) {
            /* credid and credtype  */
            case OC_REP_INT:
              if (len == 6 && memcmp(oc_string(cred->name), "credid", 6) == 0) {
                cr->credid = (int)cred->value.integer;
              } else if (len == 8 &&
                         memcmp(oc_string(cred->name), "credtype", 8) == 0) {
                cr->credtype = cred->value.integer;
              }
              break;
            /* subjectuuid and credusage */
            case OC_REP_STRING:
              if (len == 11 &&
                  memcmp(oc_string(cred->name), "subjectuuid", 11) == 0) {
                oc_str_to_uuid(oc_string(cred->value.string), &cr->subjectuuid);
              }
#ifdef OC_PKI
              else if (len == 9 &&
                       memcmp(oc_string(cred->name), "credusage", 9) == 0) {
                cr->credusage = oc_cred_parse_credusage(&cred->value.string);
              }
#endif /* OC_PKI */
              break;
            /* publicdata, privatedata and roleid */
            case OC_REP_OBJECT: {
              oc_rep_t *data = cred->value.object;
              if ((len == 11 &&
                   memcmp(oc_string(cred->name), "privatedata", 11) == 0)
#ifdef OC_PKI
                  || (len == 10 &&
                      memcmp(oc_string(cred->name), "publicdata", 10) == 0)
#endif /* OC_PKI */
              ) {
                while (data != NULL) {
                  switch (data->type) {
                  case OC_REP_STRING: {
                    if (oc_string_len(data->name) == 8 &&
                        memcmp("encoding", oc_string(data->name), 8) == 0) {
                      oc_sec_encoding_t encoding =
                        oc_cred_parse_encoding(&data->value.string);
                      if (len == 11) {
                        cr->privatedata.encoding = encoding;
                      }
#ifdef OC_PKI
                      else {
                        cr->publicdata.encoding = encoding;
                      }
#endif /* OC_PKI */
                    } else if (oc_string_len(data->name) == 4 &&
                               memcmp(oc_string(data->name), "data", 4) == 0) {
                      if (oc_string_len(data->value.string) == 0) {
                        goto next_item;
                      }
                      if (len == 11) {
                        oc_new_string(&cr->privatedata.data,
                                      oc_string(data->value.string),
                                      oc_string_len(data->value.string));
                      }
#ifdef OC_PKI
                      else {
                        oc_new_string(&cr->publicdata.data,
                                      oc_string(data->value.string),
                                      oc_string_len(data->value.string));
                      }
#endif /* OC_PKI */
                    }
                  } break;
                  case OC_REP_BYTE_STRING: {
                    if (oc_string_len(data->name) == 4 &&
                        memcmp(oc_string(data->name), "data", 4) == 0) {
                      if (oc_string_len(data->value.string) == 0) {
                        goto next_item;
                      }
                      if (len == 11) {
                        oc_new_string(&cr->privatedata.data,
                                      oc_string(data->value.string),
                                      oc_string_len(data->value.string));
                      }
#ifdef OC_PKI
                      else {
                        oc_new_string(&cr->publicdata.data,
                                      oc_string(data->value.string),
                                      oc_string_len(data->value.string));
                      }
#endif /* OC_PKI */
                    }
                  } break;
                  default:
                    break;
                  }
                next_item:
                  data = data->next;
                }
              } else if (len == 6 &&
                         memcmp(oc_string(cred->name), "roleid", 6) == 0) {
                while (data != NULL) {
                  len = oc_string_len(data->name);
                  if (len == 4 &&
                      memcmp(oc_string(data->name), "role", 4) == 0) {
                    oc_new_string(&cr->role.role, oc_string(data->value.string),
                                  oc_string_len(data->value.string));
                  } else if (len == 9 && memcmp(oc_string(data->name),
                                                "authority", 9) == 0) {
                    oc_new_string(&cr->role.authority,
                                  oc_string(data->value.string),
                                  oc_string_len(data->value.string));
                  }
                  data = data->next;
                }
              }
            } break;
            case OC_REP_BOOL:
              if (len == 10 &&
                  memcmp(oc_string(cred->name), "owner_cred", 10) == 0) {
                cr->owner_cred = cred->value.boolean;
              }
              break;
            default:
              break;
            }
            cred = cred->next;
          }
          creds_array = creds_array->next;
        }
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }

  return true;

error_decode_cred:
  return false;
}

static void
cred_rsrc(oc_client_response_t *data)
{
  oc_credret_ctx_t *ctx = (oc_credret_ctx_t *)data->user_data;
  if (!is_item_in_list(oc_credret_ctx_l, ctx)) {
    return;
  }
  oc_list_remove(oc_credret_ctx_l, ctx);
  oc_sec_creds_t *creds = NULL;
  if (data->code < OC_STATUS_BAD_REQUEST) {
    creds = (oc_sec_creds_t *)oc_memb_alloc(&oc_creds_m);
    if (creds) {
      OC_LIST_STRUCT_INIT(creds, creds);
      OC_DBG("oc_obt: decoding /oic/sec/cred payload");
      if (!decode_cred(data->payload, creds)) {
        OC_DBG("oc_obt: error decoding /oic/sec/cred payload");
      }
      if (oc_list_length(creds->creds) > 0) {
        ctx->cb(creds, ctx->data);
      } else {
        oc_memb_free(&oc_creds_m, creds);
        creds = NULL;
      }
    }
  }
  if (!creds) {
    ctx->cb(NULL, ctx->data);
  }
  oc_memb_free(&oc_credret_ctx_m, ctx);
}

int
oc_obt_retrieve_creds(const oc_uuid_t *uuid, oc_obt_creds_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  const oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (!device) {
    return -1;
  }

  oc_credret_ctx_t *r = (oc_credret_ctx_t *)oc_memb_alloc(&oc_credret_ctx_m);
  if (!r) {
    return -1;
  }

  r->cb = cb;
  r->data = data;

  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_do_get("/oic/sec/cred", ep, NULL, &cred_rsrc, HIGH_QOS, r)) {
    OC_ERR("could not issue GET request to /oic/sec/cred");
    oc_memb_free(&oc_credret_ctx_m, r);
    return -1;
  }

  oc_list_add(oc_credret_ctx_l, r);
  return 0;
}

/* Deleting Credentials */

static void
free_creddel_state(oc_creddel_ctx_t *p, int status)
{
  if (!is_item_in_list(oc_creddel_ctx_l, p)) {
    return;
  }
  oc_list_remove(oc_creddel_ctx_l, p);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device->endpoint);
  oc_tls_close_connection(ep);
  p->cb.cb(status, p->cb.data);
  if (p->switch_dos) {
    free_switch_dos_state(p->switch_dos);
    p->switch_dos = NULL;
  }
  oc_memb_free(&oc_creddel_ctx_m, p);
}

static void
free_creddel_ctx(oc_creddel_ctx_t *ctx, int status)
{
  free_creddel_state(ctx, status);
}

static void
creddel_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_creddel_ctx_l, data)) {
    return;
  }

  oc_creddel_ctx_t *p = (oc_creddel_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    free_creddel_ctx(p, 0);
  } else {
    free_creddel_ctx(p, -1);
  }
}

static void
cred_del(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_creddel_ctx_l, data->user_data)) {
    return;
  }

  oc_creddel_ctx_t *p = (oc_creddel_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_creddel_ctx(p, -1);
    return;
  }

  p->switch_dos = switch_dos(p->device, OC_DOS_RFNOP, creddel_RFNOP, p);
  if (!p->switch_dos) {
    free_creddel_state(p, -1);
  }
}

static void
creddel_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_creddel_ctx_l, data)) {
    return;
  }

  oc_creddel_ctx_t *p = (oc_creddel_ctx_t *)data;

  p->switch_dos = NULL;
  if (status < 0) {
    OC_DBG("oc_obt: could not switch to RFPRO");
    goto err_creddel_RFPRO;
  }
  char query[64];
  snprintf(query, 64, "credid=%d", p->credid);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device->endpoint);
  if (!oc_do_delete("/oic/sec/cred", ep, query, &cred_del, HIGH_QOS, p)) {
    OC_ERR("could not issue DELETE request to /oic/sec/cred");
    goto err_creddel_RFPRO;
  }

  return;

err_creddel_RFPRO:
  free_creddel_ctx(p, -1);
}

int
oc_obt_delete_cred_by_credid(const oc_uuid_t *uuid, int credid,
                             oc_obt_status_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (!device) {
    return -1;
  }

  oc_creddel_ctx_t *p = oc_memb_alloc(&oc_creddel_ctx_m);
  if (!p) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device = device;
  p->credid = credid;

  oc_tls_select_psk_ciphersuite();

  p->switch_dos = switch_dos(device, OC_DOS_RFPRO, creddel_RFPRO, p);
  if (!p->switch_dos) {
    oc_memb_free(&oc_creddel_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_creddel_ctx_l, p);
  return 0;
}

/* Retrieve ACL */

static bool
decode_acl(oc_rep_t *rep, oc_sec_acl_t *acl)
{
  size_t len = 0;
  while (rep != NULL) {
    len = oc_string_len(rep->name);
    switch (rep->type) {
    case OC_REP_STRING:
      if (len == 10 && memcmp(oc_string(rep->name), "rowneruuid", 10) == 0) {
        oc_str_to_uuid(oc_string(rep->value.string), &acl->rowneruuid);
      }
      break;
    case OC_REP_OBJECT_ARRAY: {
      oc_rep_t *aclist2 = rep->value.object_array;
      OC_LIST_STRUCT_INIT(acl, subjects);

      while (aclist2 != NULL) {
        oc_sec_ace_t *ac = (oc_sec_ace_t *)oc_memb_alloc(&oc_aces_m);
        if (!ac) {
          goto error_decode_acl;
        }
        OC_LIST_STRUCT_INIT(ac, resources);
        oc_list_add(acl->subjects, ac);
        oc_rep_t *resources = NULL;
        oc_rep_t *ace = aclist2->value.object;
        while (ace != NULL) {
          len = oc_string_len(ace->name);
          switch (ace->type) {
          case OC_REP_INT:
            if (len == 10 &&
                memcmp(oc_string(ace->name), "permission", 10) == 0) {
              ac->permission = (uint16_t)ace->value.integer;
            } else if (len == 5 &&
                       memcmp(oc_string(ace->name), "aceid", 5) == 0) {
              ac->aceid = (int)ace->value.integer;
            }
            break;
          case OC_REP_OBJECT_ARRAY:
            if (len == 9 && memcmp(oc_string(ace->name), "resources", 9) == 0)
              resources = ace->value.object_array;
            break;
          case OC_REP_OBJECT: {
            oc_rep_t *sub = ace->value.object;
            while (sub != NULL) {
              len = oc_string_len(sub->name);
              if (len == 4 && memcmp(oc_string(sub->name), "uuid", 4) == 0) {
                oc_str_to_uuid(oc_string(sub->value.string), &ac->subject.uuid);
                ac->subject_type = OC_SUBJECT_UUID;
              } else if (len == 4 &&
                         memcmp(oc_string(sub->name), "role", 4) == 0) {
                oc_new_string(&ac->subject.role.role,
                              oc_string(sub->value.string),
                              oc_string_len(sub->value.string));
                ac->subject_type = OC_SUBJECT_ROLE;
              } else if (len == 9 &&
                         memcmp(oc_string(sub->name), "authority", 9) == 0) {
                oc_new_string(&ac->subject.role.authority,
                              oc_string(sub->value.string),
                              oc_string_len(sub->value.string));
                ac->subject_type = OC_SUBJECT_ROLE;
              } else if (len == 8 &&
                         memcmp(oc_string(sub->name), "conntype", 8) == 0) {
                if (oc_string_len(sub->value.string) == 10 &&
                    memcmp(oc_string(sub->value.string), "auth-crypt", 10) ==
                      0) {
                  ac->subject.conn = OC_CONN_AUTH_CRYPT;
                } else if (oc_string_len(sub->value.string) == 10 &&
                           memcmp(oc_string(sub->value.string), "anon-clear",
                                  10) == 0) {
                  ac->subject.conn = OC_CONN_ANON_CLEAR;
                }
                ac->subject_type = OC_SUBJECT_CONN;
              }
              sub = sub->next;
            }
          } break;
          default:
            break;
          }
          ace = ace->next;
        }

        while (resources != NULL) {
          oc_ace_res_t *res = (oc_ace_res_t *)oc_memb_alloc(&oc_res_m);
          if (!res) {
            goto error_decode_acl;
          }
          oc_list_add(ac->resources, res);

          oc_rep_t *resource = resources->value.object;

          while (resource != NULL) {
            switch (resource->type) {
            case OC_REP_STRING:
              if (oc_string_len(resource->name) == 4 &&
                  memcmp(oc_string(resource->name), "href", 4) == 0) {
                oc_new_string(&res->href, oc_string(resource->value.string),
                              oc_string_len(resource->value.string));
              } else if (oc_string_len(resource->name) == 2 &&
                         memcmp(oc_string(resource->name), "wc", 2) == 0) {
                if (oc_string(resource->value.string)[0] == '*') {
                  res->wildcard = OC_ACE_WC_ALL;
                }
                if (oc_string(resource->value.string)[0] == '+') {
                  res->wildcard = OC_ACE_WC_ALL_SECURED;
                }
                if (oc_string(resource->value.string)[0] == '-') {
                  res->wildcard = OC_ACE_WC_ALL_PUBLIC;
                }
              }
              break;
            default:
              break;
            }
            resource = resource->next;
          }
          resources = resources->next;
        }
        aclist2 = aclist2->next;
      }
    } break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;

error_decode_acl:
  return false;
}

void
oc_obt_free_acl(oc_sec_acl_t *acl)
{
  oc_sec_ace_t *ace = (oc_sec_ace_t *)oc_list_pop(acl->subjects);
  while (ace) {
    oc_sec_ace_t *next = ace->next;
    oc_obt_free_ace(ace);
    ace = next;
  }
  oc_memb_free(&oc_acl_m, acl);
}

static void
acl2_rsrc(oc_client_response_t *data)
{
  oc_aclret_ctx_t *ctx = (oc_aclret_ctx_t *)data->user_data;
  if (!is_item_in_list(oc_aclret_ctx_l, ctx)) {
    return;
  }
  oc_list_remove(oc_aclret_ctx_l, ctx);
  oc_sec_acl_t *acl = NULL;
  if (data->code < OC_STATUS_BAD_REQUEST) {
    acl = (oc_sec_acl_t *)oc_memb_alloc(&oc_acl_m);
    if (acl) {
      OC_DBG("oc_obt: decoding /oic/sec/acl2 payload");
      if (!decode_acl(data->payload, acl)) {
        OC_DBG("oc_obt: error decoding /oic/sec/acl2 payload");
      }
      if (oc_list_length(acl->subjects) > 0) {
        ctx->cb(acl, ctx->data);
      } else {
        oc_memb_free(&oc_acl_m, acl);
        acl = NULL;
      }
    }
  }
  if (!acl) {
    ctx->cb(NULL, ctx->data);
  }
  oc_memb_free(&oc_aclret_ctx_m, ctx);
}

int
oc_obt_retrieve_acl(const oc_uuid_t *uuid, oc_obt_acl_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  const oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (!device) {
    return -1;
  }

  oc_aclret_ctx_t *r = (oc_aclret_ctx_t *)oc_memb_alloc(&oc_aclret_ctx_m);
  if (!r) {
    return -1;
  }

  r->cb = cb;
  r->data = data;

  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_do_get("/oic/sec/acl2", ep, NULL, &acl2_rsrc, HIGH_QOS, r)) {
    OC_ERR("could not issue GET request to /oic/sec/acl2");
    oc_memb_free(&oc_aclret_ctx_m, r);
    return -1;
  }

  oc_list_add(oc_aclret_ctx_l, r);
  return 0;
}

/* Deleting ACEs */

static void
free_acedel_state(oc_acedel_ctx_t *p, int status)
{
  if (!is_item_in_list(oc_acedel_ctx_l, p)) {
    return;
  }
  oc_list_remove(oc_acedel_ctx_l, p);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device->endpoint);
  oc_tls_close_connection(ep);
  p->cb.cb(status, p->cb.data);
  if (p->switch_dos) {
    free_switch_dos_state(p->switch_dos);
    p->switch_dos = NULL;
  }
  oc_memb_free(&oc_acedel_ctx_m, p);
}

static void
free_acedel_ctx(oc_acedel_ctx_t *ctx, int status)
{
  free_acedel_state(ctx, status);
}

static void
acedel_RFNOP(int status, void *data)
{
  if (!is_item_in_list(oc_acedel_ctx_l, data)) {
    return;
  }

  oc_acedel_ctx_t *p = (oc_acedel_ctx_t *)data;
  p->switch_dos = NULL;

  if (status >= 0) {
    free_acedel_ctx(p, 0);
  } else {
    free_acedel_ctx(p, -1);
  }
}

static void
ace_del(oc_client_response_t *data)
{
  if (!is_item_in_list(oc_acedel_ctx_l, data->user_data)) {
    return;
  }

  oc_acedel_ctx_t *p = (oc_acedel_ctx_t *)data->user_data;

  if (data->code >= OC_STATUS_BAD_REQUEST) {
    free_acedel_ctx(p, -1);
    return;
  }

  p->switch_dos = switch_dos(p->device, OC_DOS_RFNOP, acedel_RFNOP, p);
  if (!p->switch_dos) {
    free_acedel_state(p, -1);
  }
}

static void
acedel_RFPRO(int status, void *data)
{
  if (!is_item_in_list(oc_acedel_ctx_l, data)) {
    return;
  }

  oc_acedel_ctx_t *p = (oc_acedel_ctx_t *)data;
  p->switch_dos = NULL;
  if (status < 0) {
    OC_DBG("oc_obt: could not switch to RFPRO");
    goto err_acedel_RFPRO;
  }
  char query[64];
  snprintf(query, 64, "aceid=%d", p->aceid);
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(p->device->endpoint);
  if (!oc_do_delete("/oic/sec/acl2", ep, query, &ace_del, HIGH_QOS, p)) {
    OC_ERR("could not issue DELETE request to /oic/sec/acl2");
    goto err_acedel_RFPRO;
  }

  return;

err_acedel_RFPRO:
  free_acedel_ctx(p, -1);
}

int
oc_obt_delete_ace_by_aceid(const oc_uuid_t *uuid, int aceid,
                           oc_obt_status_cb_t cb, void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (!device) {
    return -1;
  }

  oc_acedel_ctx_t *p = oc_memb_alloc(&oc_acedel_ctx_m);
  if (!p) {
    return -1;
  }

  p->cb.cb = cb;
  p->cb.data = data;
  p->device = device;
  p->aceid = aceid;

  oc_tls_select_psk_ciphersuite();

  p->switch_dos = switch_dos(device, OC_DOS_RFPRO, acedel_RFPRO, p);
  if (!p->switch_dos) {
    oc_memb_free(&oc_acedel_ctx_m, p);
    return -1;
  }

  oc_list_add(oc_acedel_ctx_l, p);

  return 0;
}

oc_sec_creds_t *
oc_obt_retrieve_own_creds(void)
{
  return oc_sec_get_creds(0);
}

int
oc_obt_delete_own_cred_by_credid(int credid)
{
  oc_sec_cred_t *cred = oc_sec_get_cred_by_credid(credid, 0);
  if (cred) {
    oc_sec_remove_cred(cred, 0);
    return 0;
  }
  return -1;
}

int
oc_obt_update_cloud_conf_device(const oc_uuid_t *uuid, const char *url,
                                const char *at, const char *apn,
                                const char *cis, const char *sid,
                                oc_response_handler_t cb, void *user_data)
{
  const oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
#if OC_ERR_IS_ENABLED
    char di[OC_UUID_LEN];
    oc_uuid_to_str(uuid, di, OC_UUID_LEN);
    OC_ERR("Could not find device from udn %s", di);
#endif /* OC_ERR_IS_ENABLED */
    return -1;
  }
  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (ep == NULL) {
    OC_ERR("Could not find ep from device");
    return -1;
  }

  OC_DBG("at %s", at);
  OC_DBG("apn %s", apn);
  OC_DBG("cis %s", cis);
  OC_DBG("sid %s", sid);
  if (!oc_init_post(url, ep, NULL, cb, LOW_QOS, user_data)) {
    OC_ERR("Could not init POST request");
    return -1;
  }
  oc_rep_start_root_object();
  oc_rep_set_text_string(root, at, at);
  oc_rep_set_text_string(root, apn, apn);
  oc_rep_set_text_string(root, cis, cis);
  oc_rep_set_text_string(root, sid, sid);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("Could not send POST request");
    return -1;
  }

  OC_DBG("Sent POST request");
  return 0;
}

int
oc_obt_retrieve_cloud_conf_device(const oc_uuid_t *uuid, const char *url,
                                  oc_response_handler_t cb, void *user_data)
{
  // TODO get the URL from the device
  // char url[200] = "/CoapCloudConfResURI";

  // oc_device_t* device = oc_obt_get_cached_device_handle(uuid);
  const oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
#if OC_ERR_IS_ENABLED
    char di[OC_UUID_LEN];
    oc_uuid_to_str(uuid, di, OC_UUID_LEN);
    OC_ERR("Could not find device from udn %s", di);
#endif /* OC_ERR_IS_ENABLED */
    return -1;
  }
  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (ep == NULL) {
    OC_ERR("Could not find ep from device");
    return -1;
  }

  if (!oc_do_get(url, ep, NULL, cb, LOW_QOS, user_data)) {
    OC_ERR("Could not send GET request");
    return -1;
  }

  return 0;
}

int
oc_obt_retrieve_d2dserverlist(const oc_uuid_t *uuid, oc_response_handler_t cb,
                              void *data)
{
  if (!oc_obt_is_owned_device(uuid)) {
    return -1;
  }

  const oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (!device) {
    return -1;
  }

  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (!oc_do_get("/d2dserverlist", ep, NULL, cb, LOW_QOS, data)) {
    OC_ERR("Could not send GET request to /d2dserverlist");
    return -1;
  }

  return 0;
}

int
oc_obt_post_d2dserverlist(const oc_uuid_t *uuid, const char *query,
                          const char *url, oc_response_handler_t cb,
                          void *user_data)
{
  const oc_device_t *cloud_proxy = oc_obt_get_owned_device_handle(uuid);
  if (cloud_proxy == NULL) {
#if OC_ERR_IS_ENABLED
    char di[OC_UUID_LEN];
    oc_uuid_to_str(uuid, di, OC_UUID_LEN);
    OC_ERR("Could not find cloud_proxy from udn %s", di);
#endif /* OC_ERR_IS_ENABLED */
    return -1;
  }
  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(cloud_proxy->endpoint);
  if (ep == NULL) {
    OC_ERR("Could not find ep from cloud_proxy");
    return -1;
  }

  if (!oc_init_post(url, ep, query, cb, LOW_QOS, user_data)) {
    OC_ERR("Could not init POST request");
    return -1;
  }
  if (!oc_do_post()) {
    OC_ERR("Could not send POST request");
    return -1;
  }

  OC_DBG("Sent POST request %s?%s", url, query);
  return 0;
}

static const oc_endpoint_t *
obt_get_endpoint(const oc_uuid_t *uuid)
{
  const oc_device_t *device;
  if (!oc_obt_is_owned_device(uuid)) {
    device = oc_obt_get_cached_device_handle(uuid);
  } else {
    device = oc_obt_get_owned_device_handle(uuid);
  }
  if (device == NULL) {
    return NULL;
  }

  char di[OC_UUID_LEN];
  oc_uuid_to_str(&(device->uuid), di, OC_ARRAY_SIZE(di));
  OC_DBG("[C] Target uuid = %s", di);

  if (!oc_obt_is_owned_device(uuid)) {
    return oc_obt_get_unsecure_endpoint(device->endpoint);
  }
  return oc_obt_get_secure_endpoint(device->endpoint);
}

/* General GET, POST and DELETE */
int
oc_obt_general_get(const oc_uuid_t *uuid, const char *url,
                   oc_response_handler_t cb, void *data)
{
  const oc_endpoint_t *ep = obt_get_endpoint(uuid);
  if (ep == NULL) {
    OC_ERR("Could not find ep from device");
    return -1;
  }
  oc_tls_select_psk_ciphersuite();
  if (!oc_do_get(url, ep, NULL, cb, HIGH_QOS, data)) {
    OC_ERR("Could not send GET request");
    return -1;
  }
  return 0;
}

int
oc_obt_general_post(const oc_uuid_t *uuid, const char *query, const char *url,
                    oc_response_handler_t cb, void *user_data,
                    char **payload_properties, char **payload_values,
                    char **payload_types, int array_size)
{
  const oc_device_t *device = oc_obt_get_owned_device_handle(uuid);
  if (device == NULL) {
#if OC_ERR_IS_ENABLED
    char di[OC_UUID_LEN];
    oc_uuid_to_str(uuid, di, OC_UUID_LEN);
    OC_ERR("Could not find device from udn %s", di);
#endif /* OC_ERR_IS_ENABLED */
    return -1;
  }
  oc_tls_select_psk_ciphersuite();
  const oc_endpoint_t *ep = oc_obt_get_secure_endpoint(device->endpoint);
  if (ep == NULL) {
    OC_ERR("Could not find ep from device");
    return -1;
  }

  if (!oc_init_post(url, ep, query, cb, HIGH_QOS, user_data)) {
    OC_ERR("Could not init POST request");
    return -1;
  }
  oc_rep_start_root_object();
  for (int i = 0; i < array_size; i++) {
    if (strstr(payload_types[i], "bool") != NULL) {
      long payload_int = strtol(payload_values[i], NULL, 10);
      bool payload_bool = (payload_int != 0 ? true : false);

      oc_rep_encode_text_string(&root_map, payload_properties[i],
                                strlen(payload_properties[i]));
      oc_rep_encode_boolean(&root_map, payload_bool);

    } else if (strstr(payload_types[i], "int") != NULL) {
      long payload_int = strtol(payload_values[i], NULL, 10);

      oc_rep_encode_text_string(&root_map, payload_properties[i],
                                strlen(payload_properties[i]));
      oc_rep_encode_int(&root_map, payload_int);
    } else if (strstr(payload_types[i], "float") != NULL) {
      double payload_double = strtod(payload_values[i], NULL);

      oc_rep_encode_text_string(&root_map, payload_properties[i],
                                strlen(payload_properties[i]));
      oc_rep_encode_double(&root_map, payload_double);
    } else if (strstr(payload_types[i], "str") != NULL) {
      oc_rep_encode_text_string(&root_map, payload_properties[i],
                                strlen(payload_properties[i]));
      if ((const char *)payload_values[i] != NULL) {
        oc_rep_encode_text_string(&root_map, payload_values[i],
                                  strlen(payload_values[i]));
      } else {
        oc_rep_encode_text_string(&root_map, "", 0);
      }
    } else if (strstr(payload_types[i], "bytes") != NULL) {
      size_t byte_string_len = (strlen(payload_values[i]) + 1) / 2;
      unsigned char payload_byte_string[10240];

      const char *pos = payload_values[i];
      for (size_t j = 0; j < byte_string_len; j++) {
        sscanf(pos, "%2hhx", &payload_byte_string[j]);
        pos += 2;
      }

      oc_rep_encode_text_string(&root_map, payload_properties[i],
                                strlen(payload_properties[i]));
      oc_rep_encode_byte_string(&root_map, payload_byte_string,
                                byte_string_len);
    }
  }
  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_ERR("Could not send POST request");
    return -1;
  }
  OC_DBG("\n\n\nSent POST request %s?%s\n\n", url, query);
  return 0;
}

int
oc_obt_general_delete(const oc_uuid_t *uuid, const char *query, const char *url,
                      oc_response_handler_t cb, void *data)
{
  const oc_endpoint_t *ep = obt_get_endpoint(uuid);
  if (ep == NULL) {
    OC_ERR("Could not find ep from device");
    return -1;
  }
  oc_tls_select_psk_ciphersuite();
  if (!oc_do_delete(url, ep, query, cb, HIGH_QOS, data)) {
    OC_ERR("Could not send DELETE request");
    return -1;
  }
  return 0;
}

void
oc_obt_set_sd_info(const char *name, bool priv)
{
  oc_sec_sdi_t *sdi = oc_sec_sdi_get(0);
  oc_free_string(&sdi->name);
  oc_new_string(&sdi->name, name, strlen(name));
  sdi->priv = priv;
  oc_sec_dump_sdi(0);
}

#ifdef OC_PKI
static int
oc_obt_generate_root_cred(void)
{
  uint8_t public_key[OC_ECDSA_PUBKEY_SIZE];
  size_t public_key_size = 0;
  if (oc_sec_ecdsa_generate_keypair(0, oc_sec_certs_ecp_group_id(), public_key,
                                    OC_ECDSA_PUBKEY_SIZE, &public_key_size,
                                    g_private_key, OC_ARRAY_SIZE(g_private_key),
                                    &g_private_key_size) < 0) {
    OC_ERR("oc_obt: could not generate ECDSA keypair for local domain root "
           "certificate");
    return -1;
  }
  if (public_key_size > OC_ECDSA_PUBKEY_SIZE) {
    OC_ERR("oc_obt: invalid ECDSA keypair for local domain root certificate");
    return -1;
  }
  oc_obt_generate_root_cert_data_t cert_data = {
    .subject_name = g_root_subject,
    .public_key = public_key,
    .public_key_size = public_key_size,
    .private_key = g_private_key,
    .private_key_size = g_private_key_size,
    .signature_md_alg = oc_sec_certs_md_signature_algorithm(),
  };
  return oc_obt_generate_self_signed_root_cert(cert_data, 0);
}
#endif /* OC_PKI */

/* OBT initialization and shutdown */
int
oc_obt_init(void)
{
  OC_DBG("oc_obt:OBT init");
  if (oc_sec_is_operational(/*device*/ 0)) {
#if defined(OC_PKI) || defined(OC_OSCORE)
    oc_obt_load_state();
#endif /* OC_PKI || OC_OSCORE */
    OC_DBG("oc_obt: device(%d) already operational", 0);
    return 0;
  }

  if (oc_sec_self_own(/*device*/ 0) != 0) {
    OC_DBG("oc_obt: returning from oc_obt_init() with errors");
    return -1;
  }

#ifdef OC_OSCORE
  OC_DBG("oc_obt: generating OSCORE group context id");
  gen_oscore_ctxid(g_groupid, true);
  OC_DBG("oc_obt: generating OSCORE group secret");
  oc_random_buffer(g_group_secret, OC_ARRAY_SIZE(g_group_secret));
#endif /* OC_OSCORE */

#if defined(OC_PKI) || defined(OC_OSCORE)
#ifdef OC_PKI
  g_root_cert_credid = oc_obt_generate_root_cred();
  if (g_root_cert_credid <= 0) {
    OC_DBG("oc_obt: returning from oc_obt_init() with errors");
    return -1;
  }
#endif /* OC_PKI */
  oc_obt_dump_state();
#endif /* OC_PKI || OC_OSCORE */

  OC_DBG("oc_obt: successfully returning from oc_obt_init()");
  return 0;
}

void
oc_obt_shutdown(void)
{
  oc_device_t *device = (oc_device_t *)oc_list_pop(oc_cache);
  while (device) {
    oc_free_server_endpoints(device->endpoint);
    oc_memb_free(&oc_devices_s, device);
    device = (oc_device_t *)oc_list_pop(oc_cache);
  }
  device = (oc_device_t *)oc_list_pop(oc_devices);
  while (device) {
    oc_free_server_endpoints(device->endpoint);
    oc_memb_free(&oc_devices_s, device);
    device = (oc_device_t *)oc_list_pop(oc_devices);
  }
  oc_discovery_cb_t *cb = (oc_discovery_cb_t *)oc_list_head(oc_discovery_cbs);
  while (cb) {
    free_discovery_cb(cb);
    cb = (oc_discovery_cb_t *)oc_list_head(oc_discovery_cbs);
  }
}

#endif /* OC_SECURITY */

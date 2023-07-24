/****************************************************************************
 *
 * Copyright (c) 2017 Intel Corporation
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

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "port/oc_assert.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"

#if defined(OC_INTROSPECTION) && defined(OC_IDD_API)
#include "oc_introspection.h"
#endif /* OC_INTROSPECTION && OC_IDD_API */

#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define CHAR_ARRAY_LEN(x) (sizeof(x) - 1)

static pthread_mutex_t mutex;
static pthread_cond_t cv;

static OC_ATOMIC_INT8_T quit = 0;

static double temp = 5.0;
static double temp_K = (5.0 + 273.15);
static double temp_F = (5.0 * 9 / 5 + 32);
static double min_C = 0.0;
static double max_C = 100.0;
static double min_K = 273.15;
static double max_K = 373.15;
static double min_F = 32;
static double max_F = 212;
typedef enum { C = 100, F, K } units_t;
static units_t temp_units = C;
static bool switch_state = false;
static const char *mfg_persistent_uuid = "f6e10d9c-a1c9-43ba-a800-f1b0aad2a889";

static pthread_t toggle_switch_thread;
static oc_resource_t *temp_resource = NULL;
static oc_resource_t *bswitch = NULL;
#ifdef OC_COLLECTIONS
static oc_resource_t *col = NULL;
#endif /* OC_COLLECTIONS */

oc_define_interrupt_handler(toggle_switch)
{
  if (bswitch) {
    oc_notify_observers(bswitch);
  }
}

static void *
toggle_switch_resource(void *data)
{
  (void)data;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    getchar();
    if (OC_ATOMIC_LOAD8(quit) != 1) {
      printf("\nSwitch toggled\n");
      switch_state = !switch_state;
      oc_signal_interrupt_handler(toggle_switch);
    }
  }
  return NULL;
}

static int
app_init(void)
{
  oc_activate_interrupt_handler(toggle_switch);
  int err = oc_init_platform("Intel", NULL, NULL);

  err |= oc_add_device("/oic/d", "oic.d.switch", "Temp_sensor", "ocf.2.2.5",
                       "ocf.res.1.3.0,ocf.sh.1.3.0", NULL, NULL);
  printf("\tSwitch device added.\n");
#if defined(OC_IDD_API)
  FILE *fp;
  uint8_t *buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read smart_home_server_linux_IDD.cbor\n"
    "\tIntrospection data not set for device.\n";
  fp = fopen("./smart_home_server_linux_IDD.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t *)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      printf("\tIntrospection data set for device.\n");
    } else {
      printf("%s", introspection_error);
    }
    free(buffer);
  } else {
    printf("%s", introspection_error);
  }
#endif

  if (err >= 0) {
    oc_uuid_t my_uuid;
    oc_str_to_uuid(mfg_persistent_uuid, &my_uuid);
    oc_set_immutable_device_identifier(0, &my_uuid);
  }
  return err;
}

static void
get_temp(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)user_data;
  printf("GET_temp:\n");
  bool invalid_query = false;
  const char *units;
  units_t u = temp_units;
  int units_len =
    oc_get_query_value_v1(request, "units", CHAR_ARRAY_LEN("units"), &units);
  if (units_len != -1) {
    if (units[0] == 'K') {
      u = K;
    } else if (units[0] == 'F') {
      u = F;
    } else if (units[0] == 'C') {
      u = C;
    } else {
      invalid_query = true;
    }
  }

  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
  case OC_IF_S:
    switch (u) {
    case C:
      oc_rep_set_text_string(root, units, "C");
      oc_rep_set_double(root, temperature, temp);
      break;
    case F:
      oc_rep_set_text_string(root, units, "F");
      oc_rep_set_double(root, temperature, temp_F);
      break;
    case K:
      oc_rep_set_text_string(root, units, "K");
      oc_rep_set_double(root, temperature, temp_K);
      break;
    }
    break;
  default:
    break;
  }

  oc_rep_set_array(root, range);
  switch (u) {
  case C:
    oc_rep_add_double(range, min_C);
    oc_rep_add_double(range, max_C);
    break;
  case K:
    oc_rep_add_double(range, min_K);
    oc_rep_add_double(range, max_K);
    break;
  case F:
    oc_rep_add_double(range, min_F);
    oc_rep_add_double(range, max_F);
    break;
  }
  oc_rep_close_array(root, range);

  oc_rep_end_root_object();

  if (invalid_query)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_OK);
}

static void
post_temp(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  printf("POST_temp:\n");
  bool out_of_range = false;
  double t = -1;
  units_t units = C;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_DOUBLE:
      t = rep->value.double_p;
      break;
    case OC_REP_STRING:
      if (oc_string(rep->value.string)[0] == 'C') {
        units = C;
      } else if (oc_string(rep->value.string)[0] == 'F') {
        units = F;
      } else if (oc_string(rep->value.string)[0] == 'K') {
        units = K;
      } else {
        out_of_range = true;
      }
      break;
    default:
      out_of_range = true;
      break;
    }
    rep = rep->next;
  }

  if (t == -1) {
    out_of_range = true;
  }

  if (!out_of_range && t != -1 &&
      ((units == C && t < min_C && t > max_C) ||
       (units == F && t < min_F && t > max_F) ||
       (units == K && t < min_K && t > max_K))) {
    out_of_range = true;
  }

  if (!out_of_range) {
    if (units == C) {
      temp = t;
      temp_F = (temp * 9 / 5) + 32;
      temp_K = (temp + 273.15);
    } else if (units == F) {
      temp_F = t;
      temp = (temp_F - 32) * 5 / 9;
      temp_K = (temp + 273.15);
    } else if (units == K) {
      temp_K = t;
      temp = (temp_K - 273.15);
      temp_F = (temp * 9 / 5) + 32;
    }
    temp_units = units;
  }

  oc_rep_start_root_object();
  switch (temp_units) {
  case C:
    oc_rep_set_double(root, temperature, temp);
    oc_rep_set_text_string(root, units, "C");
    oc_rep_set_array(root, range);
    oc_rep_add_double(range, min_C);
    oc_rep_add_double(range, max_C);
    oc_rep_close_array(root, range);
    break;
  case F:
    oc_rep_set_double(root, temperature, temp_F);
    oc_rep_set_text_string(root, units, "F");
    oc_rep_set_array(root, range);
    oc_rep_add_double(range, min_F);
    oc_rep_add_double(range, max_F);
    oc_rep_close_array(root, range);
    break;
  case K:
    oc_rep_set_double(root, temperature, temp_K);
    oc_rep_set_array(root, range);
    oc_rep_add_double(range, min_K);
    oc_rep_add_double(range, max_K);
    oc_rep_close_array(root, range);
    oc_rep_set_text_string(root, units, "K");
    break;
  }
  oc_rep_end_root_object();

  if (out_of_range)
    oc_send_response(request, OC_STATUS_FORBIDDEN);
  else
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
get_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)user_data;
  printf("GET_switch:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, switch_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
}

static void
post_switch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  printf("POST_switch:\n");
  bool state = false, bad_request = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      break;
    default:
      if (oc_string_len(rep->name) > 2) {
        if (strncmp(oc_string(rep->name), "x.", 2) == 0) {
          break;
        }
      }
      bad_request = true;
      break;
    }
    rep = rep->next;
  }

  if (!bad_request) {
    switch_state = state;
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, switch_state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

#ifdef OC_COLLECTIONS
#ifdef OC_COLLECTIONS_IF_CREATE
/* Resource creation and request handlers for oic.r.switch.binary instances */
typedef struct oc_switch_t
{
  struct oc_switch_t *next;
  oc_resource_t *resource;
  bool state;
} oc_switch_t;
OC_MEMB(switch_s, oc_switch_t, 1);
OC_LIST(switches);

static bool
set_switch_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                      void *data)
{
  (void)resource;
  oc_switch_t *cswitch = (oc_switch_t *)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      cswitch->state = rep->value.boolean;
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

static void
get_switch_properties(const oc_resource_t *resource,
                      oc_interface_mask_t iface_mask, void *data)
{
  oc_switch_t *cswitch = (oc_switch_t *)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(resource);
  /* fall through */
  case OC_IF_A:
    oc_rep_set_boolean(root, value, cswitch->state);
    break;
  default:
    break;
  }
}

static void
post_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;
  oc_rep_t *rep = request->request_payload;
  bool bad_request = false;
  while (rep) {
    switch (rep->type) {
    case OC_REP_BOOL:
      if (oc_string_len(rep->name) != 5 ||
          memcmp(oc_string(rep->name), "value", 5) != 0) {
        bad_request = true;
      }
      break;
    default:
      if (oc_string_len(rep->name) > 2) {
        if (strncmp(oc_string(rep->name), "x.", 2) == 0) {
          break;
        }
      }
      bad_request = true;
      break;
    }
    rep = rep->next;
  }

  if (!bad_request) {
    set_switch_properties(request->resource, request->request_payload, cswitch);
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, cswitch->state);
  oc_rep_end_root_object();

  if (!bad_request) {
    oc_send_response(request, OC_STATUS_CHANGED);
  } else {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
}

static void
get_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  oc_rep_start_root_object();
  get_switch_properties(request->resource, iface_mask, user_data);
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static oc_resource_t *
get_switch_instance(const char *href, const oc_string_array_t *types,
                    oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
                    size_t device)
{
  oc_switch_t *cswitch = (oc_switch_t *)oc_memb_alloc(&switch_s);
  if (cswitch) {
    cswitch->resource = oc_new_resource(
      NULL, href, oc_string_array_get_allocated_size(*types), device);
    if (cswitch->resource) {
      size_t i;
      for (i = 0; i < oc_string_array_get_allocated_size(*types); i++) {
        const char *rt = oc_string_array_get_item(*types, i);
        oc_resource_bind_resource_type(cswitch->resource, rt);
      }
      oc_resource_bind_resource_interface(cswitch->resource, iface_mask);
      cswitch->resource->properties = bm;
      oc_resource_set_default_interface(cswitch->resource, OC_IF_A);
      oc_resource_set_request_handler(cswitch->resource, OC_GET, get_cswitch,
                                      cswitch);
      oc_resource_set_request_handler(cswitch->resource, OC_POST, post_cswitch,
                                      cswitch);
      oc_resource_set_properties_cbs(cswitch->resource, get_switch_properties,
                                     cswitch, set_switch_properties, cswitch);
      oc_add_resource(cswitch->resource);

      oc_list_add(switches, cswitch);
      return cswitch->resource;
    } else {
      oc_memb_free(&switch_s, cswitch);
    }
  }
  return NULL;
}

static void
free_switch_instance(oc_resource_t *resource)
{
  oc_switch_t *cswitch = (oc_switch_t *)oc_list_head(switches);
  while (cswitch) {
    if (cswitch->resource == resource) {
      oc_delete_resource(resource);
      oc_list_remove(switches, cswitch);
      oc_memb_free(&switch_s, cswitch);
      return;
    }
    cswitch = cswitch->next;
  }
}

#endif /* OC_COLLECTIONS_IF_CREATE */

/* Setting custom Collection-level properties */
int64_t battery_level = 94;
static bool
set_platform_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                        void *data)
{
  (void)resource;
  (void)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_INT:
      if (oc_string_len(rep->name) == 2 &&
          memcmp(oc_string(rep->name), "bl", 2) == 0) {
        battery_level = rep->value.integer;
      }
      break;
    default:
      break;
    }
    rep = rep->next;
  }
  return true;
}

static void
get_platform_properties(const oc_resource_t *resource,
                        oc_interface_mask_t iface_mask, void *data)
{
  (void)resource;
  (void)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_rep_set_int(root, x.org.openconnectivity.bl, battery_level);
    break;
  default:
    break;
  }
}
#endif /* OC_COLLECTIONS */

static bool
register_temp(void)
{
  temp_resource = oc_new_resource(NULL, "/temp", 1, 0);
  if (temp_resource == NULL) {
    printf("ERROR: cannot allocate /temp resource\n");
    return false;
  }
  oc_resource_bind_resource_type(temp_resource, "oic.r.temperature");
  oc_resource_bind_resource_interface(temp_resource, OC_IF_A);
  oc_resource_bind_resource_interface(temp_resource, OC_IF_S);
  oc_resource_set_default_interface(temp_resource, OC_IF_A);
  oc_resource_set_discoverable(temp_resource, true);
  oc_resource_set_periodic_observable(temp_resource, 1);
  oc_resource_set_request_handler(temp_resource, OC_GET, get_temp, NULL);
  oc_resource_set_request_handler(temp_resource, OC_POST, post_temp, NULL);
  oc_resource_tag_func_desc(temp_resource, OC_ENUM_HEATING);
  oc_resource_tag_pos_desc(temp_resource, OC_POS_CENTRE);
  if (!oc_add_resource(temp_resource)) {
    printf("ERROR: cannot add /temp resource to device\n");
    return false;
  }
  printf("\tTemperature resource added.\n");
  return true;
}

static bool
register_switch(void)
{
  bswitch = oc_new_resource(NULL, "/switch", 1, 0);
  if (bswitch == NULL) {
    printf("ERROR: cannot allocate /switch resource\n");
    return false;
  }
  oc_resource_bind_resource_type(bswitch, "oic.r.switch.binary");
  oc_resource_bind_resource_interface(bswitch, OC_IF_A);
  oc_resource_set_default_interface(bswitch, OC_IF_A);
  oc_resource_set_observable(bswitch, true);
  oc_resource_set_discoverable(bswitch, true);
  oc_resource_set_request_handler(bswitch, OC_GET, get_switch, NULL);
  oc_resource_set_request_handler(bswitch, OC_POST, post_switch, NULL);
  oc_resource_tag_func_desc(bswitch, OC_ENUM_SMART);
  oc_resource_tag_pos_rel(bswitch, 0.34, 0.5, 0.8);
  oc_resource_tag_pos_desc(bswitch, OC_POS_TOP);
  if (!oc_add_resource(bswitch)) {
    printf("ERROR: cannot add /switch resource to device\n");
    return false;
  }
  printf("\tSwitch resource added.\n");
  return true;
}

#ifdef OC_COLLECTIONS

static bool
register_platform_collection(void)
{
  col = oc_new_collection(NULL, "/platform", 1, 0);
  if (col == NULL) {
    printf("ERROR: cannot allocate /platform collection\n");
    return false;
  }
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);

  if (!oc_collection_add_supported_rt(col, "oic.r.switch.binary")) {
    printf(
      "ERROR: cannot add supported resource type to /platform collection\n");
    return false;
  }
  if (!oc_collection_add_mandatory_rt(col, "oic.r.switch.binary")) {
    printf(
      "ERROR: cannot add mandatory resource type to /platform collection\n");
    return false;
  }

#ifdef OC_COLLECTIONS_IF_CREATE
  oc_resource_bind_resource_interface(col, OC_IF_CREATE);
  if (!oc_collections_add_rt_factory("oic.r.switch.binary", get_switch_instance,
                                     free_switch_instance)) {
    printf("ERROR: cannot add factory for oic.r.switch.binary\n");
    return false;
  }
#endif /* OC_COLLECTIONS_IF_CREATE */

  /* The following enables baseline RETRIEVEs/UPDATEs to Collection properties
   */
  oc_resource_set_properties_cbs(col, get_platform_properties, NULL,
                                 set_platform_properties, NULL);
  if (!oc_add_collection_v1(col)) {
    printf("ERROR: cannot add /platform collection\n");
    return false;
  }

  oc_link_t *l1 = oc_new_link(bswitch);
  if (l1 == NULL) {
    printf("ERROR: cannot allocate /switch link\n");
    return false;
  }
  oc_collection_add_link(col, l1);
  /* Add a defined or custom link parameter to this link */
  if (!oc_link_add_link_param(l1, "x.org.openconnectivity.name",
                              "platform_switch")) {
    printf("ERROR: cannot add link parameter to /switch link\n");
    return false;
  }

  printf("\tResources added to collection.\n");
  return true;
}

#endif /* OC_COLLECTIONS */

static void
register_resources(void)
{
  if (!register_temp()) {
    oc_abort("Failed to register /temp resource\n");
  }
  if (!register_switch()) {
    oc_abort("Failed to register /switch resource\n");
  }

#ifdef OC_COLLECTIONS
  if (!register_platform_collection()) {
    oc_abort("Failed to register /platform collection\n");
  }
#endif /* OC_COLLECTIONS */
}

static void
signal_event_loop(void)
{
  pthread_cond_signal(&cv);
}

static void
handle_signal(int signal)
{
  (void)signal;
  OC_ATOMIC_STORE8(quit, 1);
  signal_event_loop();
}

#ifdef OC_SECURITY
static void
random_pin_cb(const unsigned char *pin, size_t pin_len, void *data)
{
  (void)data;
  printf("\n\nRandom PIN: %.*s\n\n", (int)pin_len, pin);
}
#endif /* OC_SECURITY */

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    printf("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    printf("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    printf("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    printf("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    printf("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  size_t to_read = (size_t)pem_len;
  if (fread(buffer, 1, to_read, fp) < (size_t)pem_len) {
    printf("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  fclose(fp);
  buffer[pem_len] = '\0';
  *buffer_len = (size_t)pem_len;
  return 0;
}
#endif /* OC_SECURITY && OC_PKI */

static void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  char cert[8192];
  size_t cert_len = 8192;
  if (read_pem("pki_certs/ee.pem", cert, &cert_len) < 0) {
    printf("ERROR: unable to read certificates\n");
    return;
  }

  char key[4096];
  size_t key_len = 4096;
  if (read_pem("pki_certs/key.pem", key, &key_len) < 0) {
    printf("ERROR: unable to read private key");
    return;
  }

  int ee_credid = oc_pki_add_mfg_cert(0, (const unsigned char *)cert, cert_len,
                                      (const unsigned char *)key, key_len);

  if (ee_credid < 0) {
    printf("ERROR installing manufacturer EE cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem("pki_certs/subca1.pem", cert, &cert_len) < 0) {
    printf("ERROR: unable to read certificates\n");
    return;
  }
  int subca_credid = oc_pki_add_mfg_intermediate_cert(
    0, ee_credid, (const unsigned char *)cert, cert_len);

  if (subca_credid < 0) {
    printf("ERROR installing intermediate CA cert\n");
    return;
  }

  cert_len = 8192;
  if (read_pem("pki_certs/rootca1.pem", cert, &cert_len) < 0) {
    printf("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)cert, cert_len);
  if (rootca_credid < 0) {
    printf("ERROR installing root cert\n");
    return;
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, ee_credid);
#endif /* OC_SECURITY && OC_PKI */
}

static void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, sizeof(buffer));

  printf("Started device with ID: %s\n", buffer);
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    printf("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    printf("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    printf("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    printf("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    return false;
  }
  pthread_condattr_destroy(&attr);
  return true;
}

static void
deinit(void)
{
  pthread_cond_destroy(&cv);
  pthread_mutex_destroy(&mutex);
}

static void
run_loop(void)
{
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    next_event_mt = oc_main_poll_v1();
    pthread_mutex_lock(&mutex);
    if (next_event_mt == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      struct timespec next_event = { 1, 0 };
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                           &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&cv, &mutex, &next_event);
    }
    pthread_mutex_unlock(&mutex);
  }
}

int
main(void)
{
  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };

  oc_set_con_res_announced(false);
  // max app data size set to 13k large enough to hold full IDD
  oc_set_max_app_data_size(13312);

  /* set the latency to 240 seconds*/
  /* if no latency is needed then remove the next line */
  oc_core_set_latency(240);
  /* set the MTU size to the (minimum IPv6 MTU - size of UDP/IP headers) */
  /* DTLS handshake messages would be fragmented to fit within this size */
  /* This enables certificate-based DTLS handshakes over Thread */
  oc_set_mtu_size(1232);
#ifdef OC_STORAGE
  oc_storage_config("./smart_home_server_linux_creds");
#endif /* OC_STORAGE */

  oc_set_factory_presets_cb(factory_presets_cb, NULL);
#ifdef OC_SECURITY
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif /* OC_SECURITY */

  if (pthread_create(&toggle_switch_thread, NULL, &toggle_switch_resource,
                     NULL) != 0) {
    deinit();
    return -1;
  }

  printf("Initializing Smart Home Server.\n");
  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }
  display_device_uuid();
  printf("Waiting for Client...\n");
  printf("Hit 'Enter' at any time to toggle switch resource\n");
  run_loop();
  oc_main_shutdown();
  printf("\nPress any key to exit...\n");
  pthread_join(toggle_switch_thread, NULL);
  deinit();
  return 0;
}

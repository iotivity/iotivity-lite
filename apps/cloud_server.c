/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
#include <signal.h>
#include <inttypes.h>

static int quit;

#if defined(_WIN32)
#include <windows.h>

static CONDITION_VARIABLE cv;
static CRITICAL_SECTION cs;

static void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}

static void
handle_signal(int signal)
{
  signal_event_loop();
  quit = 1;
}

static int
init(void)
{
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);

  signal(SIGINT, handle_signal);
  return 0;
}

static void
run(void)
{
  while (quit != 1) {
    oc_clock_time_t next_event = oc_main_poll();
    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    } else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(
          &cv, &cs, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }
}

#elif defined(__linux__) || defined(__ANDROID_API__)
#include <pthread.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

static void
handle_signal(int signal)
{
  if (signal == SIGPIPE) {
    return;
  }
  signal_event_loop();
  quit = 1;
}

static int
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

  if (pthread_mutex_init(&mutex, NULL) < 0) {
    OC_ERR("pthread_mutex_init failed!");
    return -1;
  }
  return 0;
}

static void
run(void)
{
  while (quit != 1) {
    oc_clock_time_t next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      struct timespec ts;
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
}

#else
#error "Unsupported OS"
#endif

// define application specific values.
static const char *spec_version = "ocf.2.0.5";
static const char *data_model_version = "ocf.res.1.3.0";

static const char *resource_rt = "core.light";
static const char *device_rt = "oic.d.cloudDevice";
static const char *device_name = "CloudServer";

static const char *manufacturer = "ocfcloud.com";

#ifdef OC_SECURITY
static const char *cis;
static const char *auth_code;
static const char *sid;
static const char *apn;
#else  /* OC_SECURITY */
static const char *cis = "coap+tcp://127.0.0.1:5683";
static const char *auth_code = "test";
static const char *sid = "00000000-0000-0000-0000-000000000001";
static const char *apn = "plgd";
#endif /* OC_SECURITY */

static void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  PRINT("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    PRINT("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    PRINT("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    PRINT("\t\t-Refreshed Token\n");
  }
}

static int
app_init(void)
{
  oc_set_con_res_announced(true);
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  return ret;
}

struct light_t
{
  bool state;
  int64_t power;
};

struct light_t light1 = { 0 };

static void
get_handler(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  struct light_t *light = (struct light_t *)user_data;

  PRINT("get_handler:\n");

  oc_rep_start_root_object();
  switch (iface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, light->state);
    oc_rep_set_int(root, power, light->power);
    oc_rep_set_text_string(root, name, "Light");
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  struct light_t *light = (struct light_t *)user_data;
  (void)iface_mask;
  printf("post_handler:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    char *key = oc_string(rep->name);
    printf("key: %s ", key);
    if (key && !strcmp(key, "state")) {
      switch (rep->type) {
      case OC_REP_BOOL:
        light->state = rep->value.boolean;
        PRINT("value: %d\n", light->state);
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    } else if (key && !strcmp(key, "power")) {
      switch (rep->type) {
      case OC_REP_INT:
        light->power = rep->value.integer;
        PRINT("value: %" PRId64 "\n", light->power);
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
register_lights(void)
{
  oc_resource_t *res1 = oc_new_resource(NULL, "/light/1", 1, 0);
  oc_resource_bind_resource_type(res1, resource_rt);
  oc_resource_bind_resource_interface(res1, OC_IF_RW);
  oc_resource_set_default_interface(res1, OC_IF_RW);
  oc_resource_set_discoverable(res1, true);
  oc_resource_set_observable(res1, true);
  oc_resource_set_request_handler(res1, OC_GET, get_handler, &light1);
  oc_resource_set_request_handler(res1, OC_POST, post_handler, &light1);
  oc_cloud_add_resource(res1);
  oc_add_resource(res1);
}

#ifdef OC_COLLECTIONS

/* Setting custom Collection-level properties */
int64_t g_battery_level = 94;

static bool
set_switches_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
  (void)resource;
  (void)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_INT:
      if (oc_string_len(rep->name) == 2 &&
          memcmp(oc_string(rep->name), "bl", 2) == 0) {
        g_battery_level = rep->value.integer;
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
get_switches_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                        void *data)
{
  (void)resource;
  (void)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_rep_set_int(root, x.org.openconnectivity.bl, g_battery_level);
    break;
  default:
    break;
  }
}

/* Resource creation and request handlers for oic.r.switch.binary instances */
typedef struct oc_switch_t
{
  struct oc_switch_t *next;
  oc_resource_t *resource;
  uint16_t id;
  bool state;
} oc_switch_t;

#ifdef OC_COLLECTIONS_IF_CREATE

OC_MEMB(switch_s, oc_switch_t, 1);
OC_LIST(switches); // list of switch instances ordered by id

static bool
set_switch_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
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
get_switch_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask,
                      void *data)
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

static void
delete_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
  OC_DBG("%s", __func__);
  (void)request;
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;

  oc_delayed_delete_resource(cswitch->resource);
  oc_send_response(request, OC_STATUS_DELETED);
}

/**
 *  Get pointer to the first element that either has no following element
 *  or the following element has an id with larger increment than 1
 *
 *  Example: list of three elements with ids 1, 2 and 5, it will return
 *    the second element (id=2) because the next id in order should be 3.
 *    Since it is 5 and the list is ordered we know 3 is free to use.
 */
static oc_switch_t* get_next_free_position()
{
  oc_switch_t* item = oc_list_head(switches);
  if (!item || item->id != 1) {
    return NULL;
  }

  for(uint16_t id = 1;
    oc_list_item_next(item) != NULL && ((oc_switch_t*)oc_list_item_next(item))->id == ++id;
    item = oc_list_item_next(item)) {
    ;
  }

  return item;
}

static oc_event_callback_retval_t
register_to_cloud(void* res)
{
  oc_resource_t* r = (oc_resource_t*)res;
  oc_cloud_add_resource(r);
  return OC_EVENT_DONE;
}

static oc_resource_t*
get_switch_instance(const char *href, oc_string_array_t *types,
                    oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
                    size_t device)
{
  (void)href;
  oc_switch_t *cswitch = (oc_switch_t *)oc_memb_alloc(&switch_s);
  if (cswitch) {
    uint16_t cswitch_id = 1;
    oc_switch_t *prev = get_next_free_position();
    if (prev) {
      cswitch_id = prev->id + 1;
    }
    const size_t href_size = sizeof("/switches/") + 5; // 5 = max number of digits in uint16_t value
    char cswitch_href[href_size];
    snprintf(cswitch_href, sizeof(cswitch_href), "/switches/%u", (unsigned)cswitch_id);

    cswitch->resource = oc_new_resource(
      NULL, cswitch_href, oc_string_array_get_allocated_size(*types), device);
    if (cswitch->resource) {
      cswitch->id = cswitch_id;
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
      oc_resource_set_request_handler(cswitch->resource, OC_DELETE, delete_cswitch,
                                      cswitch);
      oc_resource_set_request_handler(cswitch->resource, OC_POST, post_cswitch,
                                      cswitch);
      oc_resource_set_properties_cbs(cswitch->resource, get_switch_properties,
                                     cswitch, set_switch_properties, cswitch);
      oc_add_resource(cswitch->resource);
      oc_set_delayed_callback(cswitch->resource, register_to_cloud, 0);
      oc_list_insert(switches, prev, cswitch);
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
  OC_DBG("%s", __func__);
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

static void
register_collection(void)
{
  oc_resource_t* col = oc_new_collection(NULL, "/switches", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);
  oc_resource_set_observable(col, true);

  oc_collection_add_supported_rt(col, "oic.r.switch.binary");
  oc_collection_add_mandatory_rt(col, "oic.r.switch.binary");
#ifdef OC_COLLECTIONS_IF_CREATE
  oc_resource_bind_resource_interface(col, OC_IF_CREATE);
  oc_collections_add_rt_factory("oic.r.switch.binary", get_switch_instance,
                                free_switch_instance);
#endif /* OC_COLLECTIONS_IF_CREATE */
  /* The following enables baseline RETRIEVEs/UPDATEs to Collection properties
   */
  oc_resource_set_properties_cbs(col, get_switches_properties, NULL,
                                 set_switches_properties, NULL);
  oc_add_collection(col);
  PRINT("\tResources added to collection.\n");

  oc_cloud_add_resource(col);
  PRINT("\tCollection resource published.\n");
}
#endif /* OC_COLLECTIONS */

static void
register_con()
{
  oc_resource_t* con_res = oc_core_get_resource_by_index(OCF_CON, 0);
  oc_cloud_add_resource(con_res);
}

static void
register_resources(void)
{
  register_lights();
#ifdef OC_COLLECTIONS
  register_collection();
#endif /* OC_COLLECTIONS */
  register_con();
}

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    PRINT("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    PRINT("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len > (long)*buffer_len) {
    PRINT("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    PRINT("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  if (fread(buffer, 1, pem_len, fp) < (size_t)pem_len) {
    PRINT("ERROR: unable to read PEM\n");
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
  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    PRINT("ERROR: unable to read certificates\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root cert\n");
    return;
  }
#endif /* OC_SECURITY && OC_PKI */
}

int
main(int argc, char *argv[])
{
  if (argc == 1) {
    PRINT("./cloud_server <device-name-without-spaces> <auth-code> <cis> <sid> "
          "<apn>\n");
#ifndef OC_SECURITY
    PRINT("Using default parameters: device_name: %s, auth_code: %s, cis: %s, "
          "sid: %s, "
          "apn: %s\n",
          device_name, auth_code, cis, sid, apn);
#endif /* !OC_SECURITY */
  }
  if (argc > 1) {
    device_name = argv[1];
    PRINT("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
    auth_code = argv[2];
    PRINT("auth_code: %s\n", argv[2]);
  }
  if (argc > 3) {
    cis = argv[3];
    PRINT("cis : %s\n", argv[3]);
  }
  if (argc > 4) {
    sid = argv[4];
    PRINT("sid: %s\n", argv[4]);
  }
  if (argc > 5) {
    apn = argv[5];
    PRINT("apn: %s\n", argv[5]);
  }

  int ret = init();
  if (ret < 0) {
    return ret;
  }

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };
#ifdef OC_STORAGE
  oc_storage_config("./cloud_server_creds/");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);

  ret = oc_main_init(&handler);
  if (ret < 0)
    return ret;

  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx) {
    oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    if (cis) {
      oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
    }
  }

  run();

  oc_cloud_manager_stop(ctx);
  oc_main_shutdown();
  return 0;
}

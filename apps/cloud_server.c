/****************************************************************************
 *
 * Copyright 2019 Jozef Kralik All Rights Reserved.
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "oc_acl.h"
#include "oc_api.h"
#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_log.h"
#include "oc_pki.h"
#include "oc_clock_util.h"
#include "port/oc_assert.h"
#include "util/oc_compiler.h"
#include "util/oc_features.h"
#include "util/oc_process.h"

#ifdef OC_HAS_FEATURE_ETAG
#include "oc_etag.h"
#endif /* OC_HAS_FEATURE_ETAG */

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "plgd/plgd_time.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef _MSC_VER
#include <getopt.h>
#endif /* _MSC_VER */

#define ARRAY_SIZE(array) (sizeof(array) / sizeof((array)[0]))
#define CHAR_ARRAY_LEN(x) (sizeof(x) - 1)

static bool g_quit = false;

#ifdef _WIN32
#include <windows.h>

static CONDITION_VARIABLE g_cv;
static CRITICAL_SECTION g_cs;

static void
signal_event_loop(void)
{
  EnterCriticalSection(&g_cs);
  WakeConditionVariable(&g_cv);
  LeaveCriticalSection(&g_cs);
}

static void
handle_signal(int signal)
{
  (void)signal;
  g_quit = true;
  signal_event_loop();
}

static int
init(void)
{
  InitializeCriticalSection(&g_cs);
  InitializeConditionVariable(&g_cv);
  signal(SIGINT, handle_signal);
  return 0;
}

static void
deinit(void)
{
  // no-op
}

static void
run_loop(void)
{
  while (!g_quit) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    EnterCriticalSection(&g_cs);
    if (oc_main_needs_poll()) {
      LeaveCriticalSection(&g_cs);
      continue;
    }
    if (next_event_mt == 0) {
      SleepConditionVariableCS(&g_cv, &g_cs, INFINITE);
    } else {
      oc_clock_time_t now_mt = oc_clock_time_monotonic();
      if (now_mt < next_event_mt) {
        SleepConditionVariableCS(
          &g_cv, &g_cs,
          (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
      }
    }
    LeaveCriticalSection(&g_cs);
  }
}

#elif defined(__linux__) || defined(__ANDROID_API__)
#include <math.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h> // suseconds_t
#include <unistd.h>

static pthread_mutex_t g_mutex;
static pthread_cond_t g_cv;

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&g_mutex);
  pthread_cond_signal(&g_cv);
  pthread_mutex_unlock(&g_mutex);
}

static void
handle_signal(int signal)
{
  if (signal == SIGPIPE) {
    return;
  }
  g_quit = true;
  signal_event_loop();
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  int err = pthread_mutex_init(&g_mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&g_mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&g_mutex);
    return false;
  }
  err = pthread_cond_init(&g_cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&g_mutex);
    return false;
  }
  pthread_condattr_destroy(&attr);
  return true;
}

static void
deinit(void)
{
  pthread_cond_destroy(&g_cv);
  pthread_mutex_destroy(&g_mutex);
}

static void
run_loop(void)
{
  while (!g_quit) {
    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    pthread_mutex_lock(&g_mutex);
    if (oc_main_needs_poll()) {
      pthread_mutex_unlock(&g_mutex);
      continue;
    }
    if (next_event_mt == 0) {
      pthread_cond_wait(&g_cv, &g_mutex);
    } else {
      struct timespec next_event = { 1, 0 };
      oc_clock_time_t next_event_cv;
      if (oc_clock_monotonic_time_to_posix(next_event_mt, CLOCK_MONOTONIC,
                                           &next_event_cv)) {
        next_event = oc_clock_time_to_timespec(next_event_cv);
      }
      pthread_cond_timedwait(&g_cv, &g_mutex, &next_event);
    }
    pthread_mutex_unlock(&g_mutex);
  }
}

#ifdef OC_HAS_FEATURE_PLGD_TIME

static bool
is_root(void)
{
  return geteuid() == 0;
}

static int
set_system_time(oc_clock_time_t time, void *data)
{
  (void)data;
  struct timeval now;
  now.tv_sec = (time_t)(time / OC_CLOCK_SECOND);
  oc_clock_time_t rem_ticks = time % OC_CLOCK_SECOND;
  now.tv_usec = (suseconds_t)(((double)rem_ticks * 1.e06) / OC_CLOCK_SECOND);
  return settimeofday(&now, NULL);
}

#endif /* OC_HAS_FEATURE_PLGD_TIME */

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
static oc_connectivity_ports_t g_ports;
static size_t g_num_devices = 1;

#ifdef OC_SECURITY
static const char *cis;
static const char *auth_code;
static const char *sid;
static const char *apn;
#ifdef OC_PKI
#include <mbedtls/sha256.h>
static bool simulate_tpm = false;
static uint8_t manufacturer_private_key[4096];
const char *manufacturer_reference_private_key = "IDevID";
#endif /* OC_PKI */
#else  /* OC_SECURITY */
static const char *cis = "coap+tcp://127.0.0.1:5683";
static const char *auth_code = "test";
static const char *sid = "00000000-0000-0000-0000-000000000001";
static const char *apn = "plgd";
#endif /* OC_SECURITY */
#ifdef OC_HAS_FEATURE_PLGD_TIME
static oc_clock_time_t g_time = (oc_clock_time_t)-1;
static bool g_set_system_time = false;
#endif /* OC_HAS_FEATURE_PLGD_TIME */

static void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    OC_PRINTF("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    OC_PRINTF("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    OC_PRINTF("\t\t-Refreshed Token\n");
  }
}

static bool
factory_device_name(size_t device, char *buf, size_t buf_len)
{
  int written = 0;
  if (device == 0) {
    written = snprintf(buf, buf_len, "%s", device_name);
  } else {
    written = snprintf(buf, buf_len, "%s-%d", device_name, (int)device);
  }
  return (written < 0 || written >= (int)buf_len) ? false : true;
}

#ifdef OC_HAS_FEATURE_PLGD_TIME
static int
print_time(oc_clock_time_t time, void *data)
{
  (void)data;
  char ts[64] = { 0 };
  oc_clock_encode_time_rfc3339(time, ts, sizeof(ts));
  OC_PRINTF("plgd time: %s\n", ts);
  return 0;
}

static void
plgd_time_init(void)
{
#if defined(__linux__) || defined(__ANDROID_API__)
  if (g_set_system_time) {
    OC_PRINTF("using settimeofday to set system time\n");
    plgd_time_configure(/*use_in_mbedtls*/ false, set_system_time, NULL);
    return;
  }
  OC_PRINTF("using plgd time in mbedTLS\n");
  plgd_time_configure(/*use_in_mbedtls*/ true, print_time, NULL);
#else  /* !__linux__ && !__ANDROID_API__ */
  OC_PRINTF("using plgd time in mbedTLS\n");
  plgd_time_configure(/*use_in_mbedtls*/ true, print_time, NULL);
#endif /* __linux__ || __ANDROID_API__ */
}

#endif /* OC_HAS_FEATURE_PLGD_TIME */

static int
app_init(void)
{
  oc_set_con_res_announced(true);
  if (oc_init_platform(manufacturer, NULL, NULL) != 0) {
    OC_PRINTF("ERROR: failed to initialize platform\n");
    return -1;
  }
#ifdef OC_HAS_FEATURE_PLGD_TIME
  plgd_time_init();
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  for (size_t i = 0; i < g_num_devices; ++i) {
    char dev_name[128];
    const char *dev_name_ptr = device_name;
    if (factory_device_name(i, dev_name, sizeof(dev_name))) {
      dev_name_ptr = dev_name;
    }

    oc_add_new_device_t new_device = {
      .uri = "oic/d",
      .rt = device_rt,
      .name = dev_name_ptr,
      .spec_version = spec_version,
      .data_model_version = data_model_version,
      .add_device_cb = NULL,
      .add_device_cb_data = NULL,
    };
    if (i == 0) {
      new_device.ports = g_ports;
    }
    if (oc_add_device_v1(new_device) != 0) {
      OC_PRINTF("ERROR: failed to register new device\n");
      return -1;
    }
  }
  return 0;
}

struct light_t
{
  bool state;
  int64_t power;
};

static int num_resources = 1;
static struct light_t *lights;

static void
get_handler(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  struct light_t *light = (struct light_t *)user_data;

  OC_PRINTF("get_handler:\n");

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
  OC_PRINTF("post_handler:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    char *key = oc_string(rep->name);
    OC_PRINTF("key: %s ", key);
    if (key && !strcmp(key, "state")) {
      switch (rep->type) {
      case OC_REP_BOOL:
        light->state = rep->value.boolean;
        OC_PRINTF("value: %d\n", light->state);
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    } else if (key && !strcmp(key, "power")) {
      switch (rep->type) {
      case OC_REP_INT:
        light->power = rep->value.integer;
        OC_PRINTF("value: %" PRId64 "\n", light->power);
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

static bool
register_lights(void)
{
  if (num_resources > 0) {
    lights = (struct light_t *)calloc(num_resources, sizeof(struct light_t));
    if (lights == NULL) {
      OC_PRINTF("ERROR: Could not allocate memory for lights\n");
      return false;
    }
  }
  for (int i = 0; i < num_resources; i++) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf) - 1, "/light/%d", i + 1);
    if (n < 0) {
      continue;
    }
    buf[n] = 0;
    oc_resource_t *res = oc_new_resource(NULL, buf, 1, 0);
    if (res == NULL) {
      OC_PRINTF("ERROR: could not create %s resource\n", buf);
      return false;
    }

    oc_resource_bind_resource_type(res, resource_rt);
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_observable(res, true);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_set_access_in_RFOTM(res, true,
                                    OC_PERM_UPDATE | OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
    oc_resource_set_request_handler(res, OC_GET, get_handler, &lights[i]);
    oc_resource_set_request_handler(res, OC_POST, post_handler, &lights[i]);
    if (!oc_add_resource(res)) {
      OC_PRINTF("ERROR: Could not add %s resource to device\n", buf);
      return false;
    }
    if (oc_cloud_add_resource(res) < 0) {
      OC_PRINTF("ERROR: Could not add %s resource to cloud\n", buf);
      return false;
    }
  }
  return true;
}

#ifdef OC_COLLECTIONS

/* Setting custom Collection-level properties */
static int64_t g_battery_level = 94;

static bool
set_switches_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                        void *data)
{
  (void)resource;
  (void)data;
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_INT) {
      if (oc_string_len(rep->name) == CHAR_ARRAY_LEN("bl") &&
          memcmp(oc_string(rep->name), "bl", CHAR_ARRAY_LEN("bl")) == 0) {
        g_battery_level = rep->value.integer;
      }
    }
  }
  return true;
}

static void
get_switches_properties(const oc_resource_t *resource,
                        oc_interface_mask_t iface_mask, void *data)
{
  (void)resource;
  (void)data;
  if (iface_mask == OC_IF_BASELINE) {
    oc_rep_set_int(root, x.org.openconnectivity.bl, g_battery_level);
  }
}

/* Resource creation and request handlers for oic.r.switch.binary instances */
typedef struct oc_switch_t
{
  struct oc_switch_t *next;
  oc_resource_t *resource;
  bool state;
} oc_switch_t;

#ifdef OC_COLLECTIONS_IF_CREATE

OC_MEMB(switch_s, oc_switch_t, 1);
OC_LIST(switches);

static bool
set_switch_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                      void *data)
{
  (void)resource;
  oc_switch_t *cswitch = (oc_switch_t *)data;
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_BOOL) {
      cswitch->state = rep->value.boolean;
    }
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
      if (oc_string_len(rep->name) != CHAR_ARRAY_LEN("value") ||
          memcmp(oc_string(rep->name), "value", CHAR_ARRAY_LEN("value")) != 0) {
        bad_request = true;
      }
      break;
    default:
      if (oc_string_len(rep->name) > CHAR_ARRAY_LEN("x.")) {
        if (strncmp(oc_string(rep->name), "x.", CHAR_ARRAY_LEN("x.")) == 0) {
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
  OC_PRINTF("%s\n", __func__);
  (void)request;
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;

  oc_delayed_delete_resource(cswitch->resource);
  oc_send_response(request, OC_STATUS_DELETED);
}

static oc_event_callback_retval_t
register_to_cloud(void *res)
{
  oc_resource_t *r = (oc_resource_t *)res;
  oc_cloud_add_resource(r);
  return OC_EVENT_DONE;
}

static oc_resource_t *
get_switch_instance(const char *href, const oc_string_array_t *types,
                    oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
                    size_t device)
{
  oc_switch_t *cswitch = (oc_switch_t *)oc_memb_alloc(&switch_s);
  if (cswitch == NULL) {
    OC_PRINTF("ERROR: insufficient memory to add new switch instance");
    return NULL;
  }
  cswitch->resource = oc_new_resource(
    NULL, href, oc_string_array_get_allocated_size(*types), device);
  if (cswitch->resource == NULL) {
    OC_PRINTF("ERROR: could not create /switch instance");
    oc_memb_free(&switch_s, cswitch);
    return NULL;
  }
  for (size_t i = 0; i < oc_string_array_get_allocated_size(*types); i++) {
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
  oc_list_add(switches, cswitch);
  return cswitch->resource;
}

static void
free_switch_instance(oc_resource_t *resource)
{
  OC_PRINTF("%s\n", __func__);
  oc_switch_t *cswitch = (oc_switch_t *)oc_list_head(switches);
  while (cswitch) {
    if (cswitch->resource == resource) {
      oc_remove_delayed_callback(cswitch->resource, register_to_cloud);
      oc_cloud_delete_resource(resource);
      oc_delete_resource(resource);
      oc_list_remove(switches, cswitch);
      oc_memb_free(&switch_s, cswitch);
      return;
    }
    cswitch = cswitch->next;
  }
}

#endif /* OC_COLLECTIONS_IF_CREATE */

static bool
register_collection(void)
{
  oc_resource_t *col = oc_new_collection(NULL, "/switches", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);
  oc_resource_set_observable(col, true);

  if (!oc_collection_add_supported_rt(col, "oic.r.switch.binary")) {
    OC_PRINTF("ERROR: could not add supported resource type to collection\n");
    return false;
  }
  if (!oc_collection_add_mandatory_rt(col, "oic.r.switch.binary")) {
    OC_PRINTF("ERROR: could not add mandatory resource type to collection\n");
    return false;
  }

#ifdef OC_COLLECTIONS_IF_CREATE
  oc_resource_bind_resource_interface(col, OC_IF_CREATE);
  if (!oc_collections_add_rt_factory("oic.r.switch.binary", get_switch_instance,
                                     free_switch_instance)) {
    OC_PRINTF("ERROR: could not register rt factory\n");
    return false;
  }
#endif /* OC_COLLECTIONS_IF_CREATE */
  /* The following enables baseline RETRIEVEs/UPDATEs to Collection properties
   */
  oc_resource_set_properties_cbs(col, get_switches_properties, NULL,
                                 set_switches_properties, NULL);
  if (!oc_add_collection_v1(col)) {
    OC_PRINTF("ERROR: could not register /switches collection\n");
    return false;
  }
  OC_PRINTF("\tResources added to collection.\n");

  if (oc_cloud_add_resource(col) < 0) {
    OC_PRINTF("ERROR: could not publish /switches collection\n");
    return false;
  }
  OC_PRINTF("\tCollection resource published.\n");
  return true;
}
#endif /* OC_COLLECTIONS */

static bool
register_con(size_t device)
{
  oc_resource_t *con_res = oc_core_get_resource_by_index(OCF_CON, device);
  return oc_cloud_add_resource(con_res) == 0;
}

#ifdef OC_MNT
static bool
register_mnt(size_t device)
{
  oc_resource_t *mnt_res = oc_core_get_resource_by_index(OCF_MNT, device);
  return oc_cloud_add_resource(mnt_res) == 0;
}
#endif /* OC_MNT */

#ifdef OC_HAS_FEATURE_PLGD_TIME
static bool
register_plgd_time(size_t device)
{
  oc_resource_t *ptime_res = oc_core_get_resource_by_index(PLGD_TIME, device);
  return oc_cloud_add_resource(ptime_res) == 0;
}
#endif /* OC_HAS_FEATURE_PLGD_TIME */

static void
register_resources(void)
{
  if (!register_lights()) {
    oc_abort("ERROR: could not register lights\n");
  }
#ifdef OC_COLLECTIONS
  if (!register_collection()) {
    oc_abort("ERROR: could not register collection\n");
  }
#endif /* OC_COLLECTIONS */
  for (size_t i = 0; i < g_num_devices; ++i) {
    if (!register_con(i)) {
      oc_abort("ERROR: could not register con resource\n");
    }
#ifdef OC_MNT
    if (!register_mnt(i)) {
      oc_abort("ERROR: could not register mnt resource\n");
    }
#endif /* OC_MNT */
#ifdef OC_HAS_FEATURE_PLGD_TIME
    if (!register_plgd_time(i)) {
      oc_abort("ERROR: could not register plgd time resource\n");
    }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  }
}

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
read_pem(const char *file_path, char *buffer, size_t *buffer_len)
{
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    return -1;
  }
  if (fseek(fp, 0, SEEK_END) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  long pem_len = ftell(fp);
  if (pem_len < 0) {
    OC_PRINTF("ERROR: could not obtain length of file\n");
    fclose(fp);
    return -1;
  }
  if (pem_len >= (long)*buffer_len) {
    OC_PRINTF("ERROR: buffer provided too small\n");
    fclose(fp);
    return -1;
  }
  if (fseek(fp, 0, SEEK_SET) != 0) {
    OC_PRINTF("ERROR: unable to read PEM\n");
    fclose(fp);
    return -1;
  }
  size_t to_read = (size_t)pem_len;
  if (fread(buffer, 1, to_read, fp) < (size_t)pem_len) {
    OC_PRINTF("ERROR: unable to read PEM\n");
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
  // preserve name after factory reset
  oc_device_info_t *dev = oc_core_get_device_info(device);
  char dev_name[128];
  const char *dev_name_ptr = device_name;
  if (factory_device_name(device, dev_name, sizeof(dev_name))) {
    dev_name_ptr = dev_name;
  }
  oc_free_string(&dev->name);
  oc_new_string(&dev->name, dev_name_ptr, strlen(dev_name_ptr));

  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    OC_PRINTF("ERROR: unable to read pki_certs/cloudca.pem\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    OC_PRINTF("ERROR installing root ca\n");
    return;
  }

  unsigned char mfg_crt[4096];
  size_t mfg_crt_len = sizeof(mfg_crt);
  if (read_pem("pki_certs/mfgcrt.pem", (char *)mfg_crt, &mfg_crt_len) < 0) {
    OC_PRINTF("ERROR: unable to read pki_certs/mfgcrt.pem\n");
    return;
  }
  unsigned char mfg_key[4096];
  size_t mfg_key_len = sizeof(mfg_key) - 1;
  if (read_pem("pki_certs/mfgkey.pem", (char *)mfg_key, &mfg_key_len) < 0) {
    OC_PRINTF("ERROR: unable to read pki_certs/mfgkey.pem\n");
    return;
  }
  if (simulate_tpm) {
    // set the manufacturer private key to the internal storage
    memcpy(manufacturer_private_key, mfg_key, mfg_key_len);
    manufacturer_private_key[mfg_key_len] = '\0';
    // set reference private key as mfg_key
    memcpy(mfg_key, manufacturer_reference_private_key,
           strlen(manufacturer_reference_private_key));
    mfg_key[strlen(manufacturer_reference_private_key)] = 0;
    mfg_key_len = strlen(manufacturer_reference_private_key);
  }

  int mfg_credid =
    oc_pki_add_mfg_cert(0, (const unsigned char *)mfg_crt, mfg_crt_len,
                        (const unsigned char *)mfg_key, mfg_key_len);
  if (mfg_credid < 0) {
    OC_PRINTF("ERROR installing manufacturer certificate\n");
    return;
  }
  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, mfg_credid);
#endif /* OC_SECURITY && OC_PKI */
}

static void
display_device_uuid(size_t device)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(device), buffer, sizeof(buffer));

  OC_PRINTF("Started device %d with ID: %s\n", (int)device, buffer);
}

#if defined(OC_SECURITY) && defined(OC_PKI)
static int
disable_time_verify_certificate_cb(struct oc_tls_peer_t *peer,
                                   const mbedtls_x509_crt *crt, int depth,
                                   uint32_t *flags)
{
  (void)peer;
  (void)crt;
  (void)depth;
  *flags &=
    ~((uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE));
  return 0;
}

static bool
get_file(const char *directory, const uint8_t *hash, size_t len, char *buf,
         size_t size)
{
  int j = snprintf(buf, size, "%s", directory);
  if (j < 0) {
    return false;
  }
  for (size_t i = 0; i < len; i++) {
    int v = snprintf(buf + j, size - j, "%02x", hash[i]);
    if (v < 0) {
      return false;
    }
    j += v;
  }
  if ((size_t)j == size) {
    return false;
  }
  buf[j] = '\0';
  return true;
}

static int
simulate_tpm_mbedtls_pk_parse_key(size_t device, mbedtls_pk_context *pk,
                                  const unsigned char *key, size_t keylen,
                                  const unsigned char *pwd, size_t pwdlen,
                                  int (*f_rng)(void *, unsigned char *, size_t),
                                  void *p_rng)
{
  (void)device;
  if (keylen == 32) {
    char buf[256];
    if (!get_file("", key, keylen, buf, sizeof(buf))) {
      return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    FILE *f = fopen(buf, "r");
    if (!f) {
      OC_PRINTF("ERROR: simulate_tpm_mbedtls_pk_parse_key: fopen failed: %s",
                buf);
      return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
    }
    uint8_t identity_private_key[4096];
    size_t ret =
      fread(identity_private_key, 1, sizeof(identity_private_key), f);
    fclose(f);
    return mbedtls_pk_parse_key(pk, identity_private_key, ret, NULL, 0, f_rng,
                                p_rng);
  }
  if (keylen == strlen(manufacturer_reference_private_key)) {
    return mbedtls_pk_parse_key(pk, manufacturer_private_key,
                                strlen((const char *)manufacturer_private_key) +
                                  1,
                                pwd, pwdlen, f_rng, p_rng);
  }
  return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
}

static int
simulate_tpm_mbedtls_pk_write_key_der(size_t device,
                                      const mbedtls_pk_context *pk,
                                      unsigned char *buf, size_t size)
{
  (void)device;
  int ret = mbedtls_pk_write_pubkey_der(pk, buf, size);
  if (ret < 0) {
    return ret;
  }
  uint8_t pub_key_sha256[32];
  mbedtls_sha256(buf + size - ret, ret, pub_key_sha256, 0);
  const uint8_t *key = pub_key_sha256;
  size_t key_size = sizeof(pub_key_sha256);
  char path[256];
  if (!get_file("", pub_key_sha256, sizeof(pub_key_sha256), path,
                sizeof(path))) {
    return MBEDTLS_ERR_PK_KEY_INVALID_FORMAT;
  }
  FILE *f = fopen(path, "r");
  if (!f) {
    key = (const uint8_t *)manufacturer_reference_private_key;
    key_size = strlen(manufacturer_reference_private_key);
  } else {
    fclose(f);
  }
  if (size < key_size) {
    return MBEDTLS_ERR_PK_BUFFER_TOO_SMALL;
  }
  memcpy(buf + size - key_size, key, key_size);
  return (int)key_size;
}

static int
simulate_tpm_mbedtls_pk_ecp_gen_key(
  size_t device, mbedtls_ecp_group_id grp_id, mbedtls_pk_context *pk,
  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
  (void)device;
  int ret = mbedtls_ecp_gen_key(grp_id, (mbedtls_ecp_keypair *)pk->pk_ctx,
                                f_rng, p_rng);
  uint8_t identity_public_key_sha256[32];
  if (ret == 0) {
    uint8_t pub_key[200];
    ret = mbedtls_pk_write_pubkey_der(pk, pub_key, sizeof(pub_key));
    if (ret > 0) {
      mbedtls_sha256(pub_key + sizeof(pub_key) - ret, ret,
                     identity_public_key_sha256, 0);
      ret = 0;
    }
  }
  if (ret == 0) {
    uint8_t identity_private_key[4096];
    ret = mbedtls_pk_write_key_der(pk, identity_private_key,
                                   sizeof(identity_private_key));
    if (ret > 0) {
      char buf[256];
      if (!get_file("", identity_public_key_sha256,
                    sizeof(identity_public_key_sha256), buf, sizeof(buf))) {
        return 0;
      }
      FILE *f = fopen(buf, "w");
      if (f == NULL) {
        OC_PRINTF(
          "ERROR: simulate_tpm_mbedtls_pk_ecp_gen_key: could not open file %s",
          buf);
        return 0;
      }
      ret = (int)fwrite(
        identity_private_key + sizeof(identity_private_key) - ret, 1, ret, f);
      if (ret < 0) {
        OC_PRINTF("ERROR: simulate_tpm_mbedtls_pk_ecp_gen_key: could not write "
                  "to file %s",
                  buf);
      }
      fclose(f);
      ret = 0;
    }
  }
  return ret;
}

static bool
simulate_tpm_pk_free_key(size_t device, const unsigned char *key, size_t keylen)
{
  (void)device;
  char buf[256];
  if (!get_file("", key, keylen, buf, sizeof(buf))) {
    OC_PRINTF("ERROR: simulate_tpm_pk_free_key: could not get file name");
  }
  if (remove(buf) != 0) {
    OC_PRINTF("ERROR: simulate_tpm_pk_free_key: could not remove file %s", buf);
  }
  return true;
}

#endif /* OC_SECURITY && OC_PKI */

#define OPT_DISABLE_TLS_VERIFY_TIME "disable-tls-verify-time"
#define OPT_HELP "help"
#define OPT_NUM_RESOURCES "num-resources"
#define OPT_NUM_DEVICES "num-devices"
#define OPT_DEVICE_NAME "device-name"
#define OPT_CLOUD_AUTH_CODE "cloud-auth-code"
#define OPT_CLOUD_CIS "cloud-endpoint"
#define OPT_CLOUD_APN "cloud-auth-provider-name"
#define OPT_CLOUD_SID "cloud-id"
#define OPT_LOG_LEVEL "log-level"
#define OPT_SIMULATE_TPM "simulate-tpm"
#define OPT_LISTEN_UDP_PORT4 "udp-port4"
#define OPT_LISTEN_TCP_PORT4 "tcp-port4"
#define OPT_LISTEN_UDP_PORT "udp-port"
#define OPT_LISTEN_TCP_PORT "tcp-port"
#ifdef OC_SECURITY
#define OPT_LISTEN_DTLS_PORT4 "dtls-port4"
#define OPT_LISTEN_TLS_PORT4 "tls-port4"
#define OPT_LISTEN_DTLS_PORT "dtls-port"
#define OPT_LISTEN_TLS_PORT "tls-port"
#endif /* OC_SECURITY */

#define OPT_TIME "time"
#define OPT_SET_SYSTEM_TIME "set-system-time"

#ifdef OC_JSON_ENCODER
#define OPT_JSON_ENCODER "json-encoder"
#endif /* OC_JSON_ENCODER */

#define OPT_ARG_DEVICE_NAME OPT_DEVICE_NAME
#define OPT_ARG_CLOUD_AUTH_CODE OPT_CLOUD_AUTH_CODE
#define OPT_ARG_CLOUD_CIS OPT_CLOUD_CIS
#define OPT_ARG_CLOUD_SID OPT_CLOUD_SID
#define OPT_ARG_CLOUD_APN OPT_CLOUD_APN

static void
printhelp(const char *exec_path)
{
  const char *binary_name = strrchr(exec_path, '/');
  binary_name = binary_name != NULL ? binary_name + 1 : exec_path;
  OC_PRINTF("./%s <%s> <%s> <%s> <%s> <%s>\n\n", binary_name,
            OPT_ARG_DEVICE_NAME, OPT_ARG_CLOUD_AUTH_CODE, OPT_ARG_CLOUD_CIS,
            OPT_ARG_CLOUD_SID, OPT_ARG_CLOUD_APN);
  OC_PRINTF("OPTIONS:\n");
  OC_PRINTF("  -h | --%-26s print help\n", OPT_HELP);
  OC_PRINTF("  -n | --%-26s device name\n", OPT_DEVICE_NAME);
  OC_PRINTF("  -a | --%-26s cloud authorization code\n", OPT_CLOUD_AUTH_CODE);
  OC_PRINTF("  -e | --%-26s cloud endpoint\n", OPT_CLOUD_CIS);
  OC_PRINTF("  -i | --%-26s cloud id\n", OPT_CLOUD_SID);
  OC_PRINTF("  -p | --%-26s cloud authorization provider name\n",
            OPT_CLOUD_APN);
  OC_PRINTF("  -r | --%-26s number of resources\n", OPT_NUM_RESOURCES);
  OC_PRINTF("  -c | --%-26s number of devices\n", OPT_NUM_DEVICES);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_PRINTF("  -d | --%-26s disable time verification during TLS handshake\n",
            OPT_DISABLE_TLS_VERIFY_TIME);
  OC_PRINTF("  -m | --%-26s simulate TPM chip\n", OPT_SIMULATE_TPM);
#endif /* OC_SECURITY && OC_PKI */
#ifdef OC_HAS_FEATURE_PLGD_TIME
  OC_PRINTF("  -t | --%-26s set plgd time of device\n",
            OPT_TIME " <rfc3339 time>");
  OC_PRINTF("  -s | --%-26s use plgd time to set system time (root required on "
            "Linux)\n",
            OPT_SET_SYSTEM_TIME);
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  OC_PRINTF("  -l | --%-26s set log level (supported values: disabled, trace, "
            "debug, info, warning, error)\n",
            OPT_LOG_LEVEL " <level>");
#ifdef OC_IPV4
  OC_PRINTF("  -4 | --%-26s IPv4 UDP port (use -1 to disable it)\n",
            OPT_LISTEN_UDP_PORT4 " <port>");
  OC_PRINTF("  -5 | --%-26s IPv4 TCP port (use -1 to disable it)\n",
            OPT_LISTEN_TCP_PORT4 " <port>");
#endif /* OC_IPV4 */
  OC_PRINTF("  -6 | --%-26s IPv6 UDP port (use -1 to disable it)\n",
            OPT_LISTEN_UDP_PORT " <port>");
  OC_PRINTF("  -7 | --%-26s IPv6 TCP port (use -1 to disable it)\n",
            OPT_LISTEN_TCP_PORT " <port>");
#ifdef OC_SECURITY
#ifdef OC_IPV4
  OC_PRINTF("  -u | --%-26s IPv4 DTLS port (use -1 to disable it)\n",
            OPT_LISTEN_DTLS_PORT4 " <port>");
  OC_PRINTF("  -v | --%-26s IPv4 TLS port (use -1 to disable it)\n",
            OPT_LISTEN_TLS_PORT4 " <port>");
#endif /* OC_IPV4 */
  OC_PRINTF("  -w | --%-26s IPv6 DTLS port (use -1 to disable it)\n",
            OPT_LISTEN_DTLS_PORT " <port>");
  OC_PRINTF("  -x | --%-26s IPv6 TLS port (use -1 to disable it)\n",
            OPT_LISTEN_TLS_PORT " <port>");
#endif /* OC_SECURITY */
#ifdef OC_JSON_ENCODER
  OC_PRINTF("  -j | --%-26s use JSON encoder to encode message payloads\n",
            OPT_JSON_ENCODER);
#endif /* OC_JSON_ENCODER */
  OC_PRINTF("ARGUMENTS:\n");
  OC_PRINTF("  %-33s device name (optional, default: cloud_server)\n",
            OPT_ARG_DEVICE_NAME);
  OC_PRINTF("  %-33s cloud authorization code (optional)\n",
            OPT_ARG_CLOUD_AUTH_CODE);
  OC_PRINTF("  %-33s cloud endpoint (optional)\n", OPT_ARG_CLOUD_CIS);
  OC_PRINTF("  %-33s cloud id (optional)\n", OPT_ARG_CLOUD_SID);
  OC_PRINTF("  %-33s cloud authorization provider name (optional)\n",
            OPT_ARG_CLOUD_APN);
}

typedef struct
{
  bool help;
#if defined(OC_SECURITY) && defined(OC_PKI)
  bool disable_tls_verify_time;
  bool simulate_tpm;
#endif /* OC_SECURITY && OC_PKI */
  oc_connectivity_ports_t ports;
} parse_options_result_t;

static bool
parse_log_level(const char *log_level, oc_log_level_t *level)
{
  if (strcmp(log_level, "trace") == 0) {
    *level = OC_LOG_LEVEL_TRACE;
  } else if (strcmp(log_level, "debug") == 0) {
    *level = OC_LOG_LEVEL_DEBUG;
  } else if (strcmp(log_level, "info") == 0) {
    *level = OC_LOG_LEVEL_INFO;
  } else if (strcmp(log_level, "warning") == 0) {
    *level = OC_LOG_LEVEL_WARNING;
  } else if (strcmp(log_level, "error") == 0) {
    *level = OC_LOG_LEVEL_ERROR;
  } else if (strcmp(log_level, "disabled") == 0) {
    *level = OC_LOG_LEVEL_DISABLED;
  } else {
    return false;
  }
  return true;
}

static bool
parse_port(const char *port, uint16_t *p, bool *disabled)
{
  char *eptr = NULL;
  errno = 0;
  long port_num = strtol(port, &eptr, 10); // NOLINT(readability-magic-numbers)
  if (errno != 0 || eptr == port || (*port) == '\0' || port_num > UINT16_MAX) {
    return false;
  }
  if (port_num == -1) {
    *disabled = true;
    return true;
  }
  *p = (uint16_t)port_num;
  return true;
}

static bool
parse_options(int argc, char *argv[], parse_options_result_t *parsed_options)
{
#ifdef _MSC_VER
  // TODO: parse options for MSVC using shellapi.h
  (void)parsed_options;
  (void)printhelp;
  (void)parse_log_level;
  (void)parse_port;
#else /* !_MSC_VER */
  static struct option long_options[] = {
    { OPT_HELP, no_argument, NULL, 'h' },
    { OPT_DEVICE_NAME, required_argument, NULL, 'n' },
    { OPT_CLOUD_AUTH_CODE, required_argument, NULL, 'a' },
    { OPT_CLOUD_CIS, required_argument, NULL, 'e' },
    { OPT_CLOUD_SID, required_argument, NULL, 'i' },
    { OPT_CLOUD_APN, required_argument, NULL, 'p' },
    { OPT_NUM_RESOURCES, required_argument, NULL, 'r' },
    { OPT_LOG_LEVEL, required_argument, NULL, 'l' },
    { OPT_NUM_DEVICES, required_argument, NULL, 'c' },
#if defined(OC_SECURITY) && defined(OC_PKI)
    { OPT_DISABLE_TLS_VERIFY_TIME, no_argument, NULL, 'd' },
    { OPT_SIMULATE_TPM, no_argument, NULL, 'm' },
#endif /* OC_SECURITY && OC_PKI */
#ifdef OC_HAS_FEATURE_PLGD_TIME
    { OPT_TIME, required_argument, NULL, 't' },
    { OPT_SET_SYSTEM_TIME, no_argument, NULL, 's' },
#endif /* OC_HAS_FEATURE_PLGD_TIME */
#ifdef OC_IPV4
    { OPT_LISTEN_UDP_PORT4, required_argument, NULL, '4' },
    { OPT_LISTEN_TCP_PORT4, required_argument, NULL, '5' },
#endif /* OC_IPV4 */
    { OPT_LISTEN_UDP_PORT, required_argument, NULL, '6' },
    { OPT_LISTEN_TCP_PORT, required_argument, NULL, '7' },
#if defined(OC_SECURITY)
#ifdef OC_IPV4
    { OPT_LISTEN_DTLS_PORT4, required_argument, NULL, 'u' },
    { OPT_LISTEN_TLS_PORT4, required_argument, NULL, 'v' },
#endif /* OC_IPV4 */
    { OPT_LISTEN_DTLS_PORT, required_argument, NULL, 'w' },
    { OPT_LISTEN_TLS_PORT, required_argument, NULL, 'x' },
#endif /* OC_SECURITY */
#ifdef OC_JSON_ENCODER
    { OPT_JSON_ENCODER, no_argument, NULL, 'j' },
#endif /* OC_JSON_ENCODER */
    { NULL, 0, NULL, 0 },
  };

  while (true) {
    int option_index = 0;
    int opt = getopt_long(argc, argv,
                          "hdmn:a:e:i:p:r:l:st:4:5:u:v:6:7:w:x:", long_options,
                          &option_index);
    if (opt == -1) {
      break;
    }
    switch (opt) {
    case 0:
      if (long_options[option_index].flag != 0) {
        break;
      }
      OC_PRINTF("invalid option(%s)\n", argv[optind]);
      return false;
    case 'h':
      printhelp(argv[0]);
      parsed_options->help = true;
      return true;
#if defined(OC_SECURITY) && defined(OC_PKI)
    case 'd':
      parsed_options->disable_tls_verify_time = true;
      break;
    case 'm':
      parsed_options->simulate_tpm = true;
      break;
#endif /* OC_SECURITY && OC_PKI */
    case 'n':
      device_name = optarg;
      break;
    case 'a':
      auth_code = optarg;
      break;
    case 'e':
      cis = optarg;
      break;
    case 'i':
      sid = optarg;
      break;
    case 'p':
      apn = optarg;
      break;
    case 'r': {
      char *eptr = NULL;
      errno = 0;
      long val = strtol(optarg, &eptr, 10); // NOLINT(readability-magic-numbers)
      if (errno != 0 || eptr == optarg || (*eptr) != '\0' || val < 0 ||
          val > INT32_MAX) {
        OC_PRINTF("invalid number of resources argument value(%s)\n", optarg);
        return false;
      }
      num_resources = (int)val;
      break;
    }
    case 'c': {
      char *eptr = NULL;
      errno = 0;
      long val = strtol(optarg, &eptr, 10); // NOLINT(readability-magic-numbers)
      if (errno != 0 || eptr == optarg || (*eptr) != '\0' || val < 0 ||
          val > INT32_MAX) {
        OC_PRINTF("invalid number of resources argument value(%s)\n", optarg);
        return false;
      }
      g_num_devices = (size_t)val;
      break;
    }
    case 'l': {
      oc_log_level_t level;
      if (!parse_log_level(optarg, &level)) {
        OC_PRINTF("invalid log level(%s)\n", optarg);
        return false;
      }
      oc_log_set_level(level);
      break;
    }
#ifdef OC_HAS_FEATURE_PLGD_TIME
    case 't': {
      oc_clock_time_t time;
      if (!oc_clock_parse_time_rfc3339_v1(optarg, strlen(optarg), &time)) {
        OC_PRINTF("invalid plgd time value(%s)\n", optarg);
        return false;
      }
      g_time = time;
      break;
    }
    case 's': {
#if defined(__linux__) || defined(__ANDROID_API__)
      if (!is_root()) {
        OC_PRINTF("root required for settimeofday: see man settimeofday\n");
        return false;
      }
      g_set_system_time = true;
#else  /* !__linux__ && !__ANDROID_API__ */
      // TODO: implement for WIN32
      (void)g_set_system_time;
#endif /* __linux__ || __ANDROID_API__ */
      break;
    }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
#ifdef OC_IPV4
    case '4': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.udp.port4, &disabled)) {
        OC_PRINTF("invalid IPv4 UDP port(%s)\n", optarg);
        return false;
      }
      if (parsed_options->ports.udp.port4 == 5683) {
        OC_PRINTF("invalid IPv4 UDP port(%s) - reserved for multicast\n",
                  optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.udp.flags |= OC_CONNECTIVITY_DISABLE_IPV4_PORT;
      }
      break;
    }
    case '5': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.tcp.port4, &disabled)) {
        OC_PRINTF("invalid IPv4 TCP port(%s)\n", optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.tcp.flags |= OC_CONNECTIVITY_DISABLE_IPV4_PORT;
      }
      break;
    }
#endif /* OC_IPV4 */
    case '6': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.udp.port, &disabled)) {
        OC_PRINTF("invalid IPv6 UDP port(%s)\n", optarg);
        return false;
      }
      if (parsed_options->ports.udp.port == 5683) {
        OC_PRINTF("invalid IPv6 UDP port(%s) - reserved for multicast\n",
                  optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.udp.flags |= OC_CONNECTIVITY_DISABLE_IPV6_PORT;
      }
      break;
    }
    case '7': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.tcp.port, &disabled)) {
        OC_PRINTF("invalid IPv6 TCP port(%s)\n", optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.tcp.flags |= OC_CONNECTIVITY_DISABLE_IPV6_PORT;
      }
      break;
    }
#ifdef OC_SECURITY
#ifdef OC_IPV4
    case 'u': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.udp.secure_port4,
                      &disabled)) {
        OC_PRINTF("invalid IPv4 DTLS port(%s)\n", optarg);
        return false;
      }
      if (parsed_options->ports.udp.secure_port4 == 5683) {
        OC_PRINTF("invalid IPv4 DTLS port(%s) - reserved for multicast\n",
                  optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.udp.flags |=
          OC_CONNECTIVITY_DISABLE_SECURE_IPV4_PORT;
      }
      break;
    }
    case 'v': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.tcp.secure_port4,
                      &disabled)) {
        OC_PRINTF("invalid IPv4 TLS port(%s)\n", optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.tcp.flags |=
          OC_CONNECTIVITY_DISABLE_SECURE_IPV4_PORT;
      }
      break;
    }
#endif /* OC_IPV4 */
    case 'w': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.udp.secure_port,
                      &disabled)) {
        OC_PRINTF("invalid IPv6 DTLS port(%s)\n", optarg);
        return false;
      }
      if (parsed_options->ports.udp.secure_port == 5683) {
        OC_PRINTF("invalid IPv6 DTLS port(%s) - reserved for multicast\n",
                  optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.udp.flags |=
          OC_CONNECTIVITY_DISABLE_SECURE_IPV6_PORT;
      }
      break;
    }
    case 'x': {
      bool disabled = false;
      if (!parse_port(optarg, &parsed_options->ports.tcp.secure_port,
                      &disabled)) {
        OC_PRINTF("invalid IPv6 TLS port(%s)\n", optarg);
        return false;
      }
      if (disabled) {
        parsed_options->ports.tcp.flags |=
          OC_CONNECTIVITY_DISABLE_SECURE_IPV6_PORT;
      }
      break;
    }
#endif /* OC_SECURITY */
#ifdef OC_JSON_ENCODER
    case 'j':
      oc_rep_encoder_set_type(OC_REP_JSON_ENCODER);
      break;
#endif /* OC_JSON_ENCODER */
    default:
      OC_PRINTF("invalid option(%s)\n", argv[optind]);
      return false;
    }
  }
  argc -= (optind - 1);
  for (int i = 1; i < argc; ++i, ++optind) {
    argv[i] = argv[optind];
  }
#endif /* _MSC_VER */
  if (argc > 1) {
    device_name = argv[1];
  }
  if (argc > 2) {
    auth_code = argv[2];
  }
  if (argc > 3) {
    cis = argv[3];
  }
  if (argc > 4) {
    sid = argv[4];
  }
  if (argc > 5) {
    apn = argv[5];
  }
  return true;
}

static void
cloud_server_log(oc_log_level_t log_level, oc_log_component_t component,
                 const char *file, int line, const char *func, const char *fmt,
                 ...)
{
  char log_time_buf[64] = { 0 };
  oc_clock_time_rfc3339(log_time_buf, sizeof(log_time_buf));
  printf("[OC %s] ", log_time_buf);
  if (component != OC_LOG_COMPONENT_DEFAULT) {
    printf("(%s) ", oc_log_component_name(component));
  }
  printf("%s: %s:%d <%s>: ", oc_log_level_to_label(log_level), file, line,
         func);
  va_list ap;
  va_start(ap, fmt);
  vprintf(fmt, ap);
  va_end(ap);
  printf("\n");
  fflush(stdout);
}

static void
cloud_server_send_response_cb(oc_request_t *request, oc_status_t response_code)
{
  const char *uri = "???";
  if (request->resource != NULL) {
    uri = oc_string(request->resource->uri);
  }
  char timebuf[64] = { 0 };
  oc_clock_time_rfc3339(timebuf, sizeof(timebuf));
  const char *response_code_str = oc_status_to_str(response_code);
  const char *method_str = oc_method_to_str(request->method);
  OC_PRINTF("[CS %s] <cloud_server_send_response_cb> method(%d): %s, uri: %s, "
            "code(%d): %s",
            timebuf, request->method, method_str, uri, response_code,
            response_code_str);
#ifdef OC_HAS_FEATURE_ETAG
  if (request->etag != NULL) {
    char buf[32];
    size_t buf_size = ARRAY_SIZE(buf);
    oc_conv_byte_array_to_hex_string(request->etag, request->etag_len, buf,
                                     &buf_size);
    OC_PRINTF(", etag [0x%s]", buf);
  }
#endif /* OC_HAS_FEATURE_ETAG */
  OC_PRINTF("\n");
  fflush(stdout);
}

int
main(int argc, char *argv[])
{
  parse_options_result_t parsed_options = {
    .help = false,
#if defined(OC_SECURITY) && defined(OC_PKI)
    .disable_tls_verify_time = false,
    .simulate_tpm = false,
#endif /* OC_SECURITY && OC_PKI */
  };
  memset(&parsed_options.ports, 0, sizeof(parsed_options.ports));
  if (!parse_options(argc, argv, &parsed_options)) {
    return -1;
  }
  if (parsed_options.help) {
    return 0;
  }

  OC_PRINTF("Using parameters: device_name: %s, auth_code: %s, cis: %s, "
            "sid: %s, "
            "apn: %s, "
            "num_resources: %d, "
            "num_devices: %d, ",
            device_name, auth_code, cis, sid, apn, num_resources,
            (int)g_num_devices);
#if defined(OC_SECURITY) && defined(OC_PKI)
  OC_PRINTF("disable_tls_time_verification: %s, ",
            parsed_options.disable_tls_verify_time ? "true" : "false");
  OC_PRINTF("simulate_tpm: %s, ",
            parsed_options.simulate_tpm ? "true" : "false");
#endif /* OC_SECURITY && OC_PKI */
  OC_PRINTF("log_level: %s", oc_log_level_to_label(oc_log_get_level()));
  OC_PRINTF("\n");
  OC_PRINTF("ports:\n");
#ifdef OC_IPV4
  OC_PRINTF("  tcp4: %d\n",
            (parsed_options.ports.tcp.flags & OC_CONNECTIVITY_DISABLE_IPV4_PORT)
              ? -1
              : (int)parsed_options.ports.tcp.port4);
  OC_PRINTF("  udp4: %d\n",
            (parsed_options.ports.udp.flags & OC_CONNECTIVITY_DISABLE_IPV4_PORT)
              ? -1
              : (int)parsed_options.ports.udp.port4);
#endif /* OC_IPV4 */
  OC_PRINTF("  tcp: %d\n",
            (parsed_options.ports.tcp.flags & OC_CONNECTIVITY_DISABLE_IPV6_PORT)
              ? -1
              : (int)parsed_options.ports.tcp.port);
  OC_PRINTF("  udp: %d\n",
            (parsed_options.ports.udp.flags & OC_CONNECTIVITY_DISABLE_IPV6_PORT)
              ? -1
              : (int)parsed_options.ports.udp.port);
#ifdef OC_SECURITY
#ifdef OC_IPV4
  OC_PRINTF("  tls4: %d\n", (parsed_options.ports.tcp.flags &
                             OC_CONNECTIVITY_DISABLE_SECURE_IPV4_PORT)
                              ? -1
                              : (int)parsed_options.ports.tcp.secure_port4);
  OC_PRINTF("  dtls4: %d\n", (parsed_options.ports.udp.flags &
                              OC_CONNECTIVITY_DISABLE_SECURE_IPV4_PORT)
                               ? -1
                               : (int)parsed_options.ports.udp.secure_port4);
#endif /* OC_IPV4 */
  OC_PRINTF("  tls: %d\n", (parsed_options.ports.tcp.flags &
                            OC_CONNECTIVITY_DISABLE_SECURE_IPV6_PORT)
                             ? -1
                             : (int)parsed_options.ports.tcp.secure_port);
  OC_PRINTF("  dtls: %d\n", (parsed_options.ports.udp.flags &
                             OC_CONNECTIVITY_DISABLE_SECURE_IPV6_PORT)
                              ? -1
                              : (int)parsed_options.ports.udp.secure_port);
#endif /* OC_SECURITY */
  g_ports = parsed_options.ports;

#if defined(OC_SECURITY) && defined(OC_PKI)
  if (parsed_options.disable_tls_verify_time) {
    oc_pki_set_verify_certificate_cb(&disable_time_verify_certificate_cb);
  }
  if (parsed_options.simulate_tpm) {
    simulate_tpm = true;
    oc_pki_pk_functions_t pk_functions = {
      .mbedtls_pk_parse_key = simulate_tpm_mbedtls_pk_parse_key,
      .mbedtls_pk_write_key_der = simulate_tpm_mbedtls_pk_write_key_der,
      .mbedtls_pk_ecp_gen_key = simulate_tpm_mbedtls_pk_ecp_gen_key,
      .pk_free_key = simulate_tpm_pk_free_key,
    };
    if (!oc_pki_set_pk_functions(&pk_functions)) {
      OC_PRINTF("ERROR: Failed to set PKI functions\n");
      return -1;
    }
  }
#endif /* OC_SECURITY && OC_PKI */

  if (!init()) {
    return -1;
  }

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };
  oc_log_set_function(cloud_server_log);
  oc_set_send_response_callback(cloud_server_send_response_cb);
#ifdef OC_STORAGE
  oc_storage_config("./cloud_server_creds/");
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb, NULL);
  oc_set_max_app_data_size(8 * 1024 + num_resources * 512);
  oc_set_min_app_data_size(512);
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_sec_certs_md_set_algorithms_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384));
  oc_sec_certs_ecp_set_group_ids_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1));
#endif /* OC_SECURITY && OC_PKI */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    deinit();
    return ret;
  }

  for (size_t i = 0; i < g_num_devices; ++i) {
    oc_cloud_context_t *ctx = oc_cloud_get_context(i);
    if (ctx) {
      oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
      if (cis) {
        oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
      }
    }
    display_device_uuid(i);
  }
#ifdef OC_HAS_FEATURE_PLGD_TIME
  if (g_time != (oc_clock_time_t)-1) {
    plgd_time_set_time(g_time);
  }
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef OC_HAS_FEATURE_ETAG
  oc_etag_load_and_clear();
#endif /* OC_HAS_FEATURE_ETAG */

  run_loop();

  for (size_t i = 0; i < g_num_devices; ++i) {
    oc_cloud_context_t *ctx = oc_cloud_get_context(i);
    if (ctx) {
      oc_cloud_manager_stop(ctx);
    }
  }

#ifdef OC_HAS_FEATURE_ETAG
  oc_etag_dump();
#endif /* OC_HAS_FEATURE_ETAG */

  oc_main_shutdown();
  deinit();
  return 0;
}

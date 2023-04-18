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

#include "oc_api.h"
#include "oc_certs.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_pki.h"
#include "oc_acl.h"
#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "plgd/plgd_time.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>

#ifdef OC_HAS_FEATURE_PLGD_WOT
#include "plgd/plgd_wot.h"
#endif

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
    EnterCriticalSection(&cs);
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
    LeaveCriticalSection(&cs);
  }
}

#elif defined(__linux__) || defined(__ANDROID_API__)
#include <pthread.h>
#include <sys/time.h>
#include <unistd.h>

static pthread_mutex_t mutex;
static pthread_cond_t cv;

static void
signal_event_loop(void)
{
  pthread_cond_signal(&cv);
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
  sigaction(SIGTERM, &sa, NULL);

  if (pthread_mutex_init(&mutex, NULL) != 0) {
    PRINT("ERROR: pthread_mutex_init failed!\n");
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
  now.tv_sec = time / OC_CLOCK_SECOND;
  oc_clock_time_t rem_ticks = time % OC_CLOCK_SECOND;
  now.tv_usec = (__suseconds_t)(((double)rem_ticks * 1.e06) / OC_CLOCK_SECOND);
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
#ifdef OC_HAS_FEATURE_PLGD_TIME
static oc_clock_time_t g_time = (oc_clock_time_t)-1;
static bool g_set_system_time = false;
#endif /* OC_HAS_FEATURE_PLGD_TIME */

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

#ifdef OC_HAS_FEATURE_PLGD_TIME
static int
print_time(oc_clock_time_t time, void *data)
{
  (void)data;
  char ts[64] = { 0 };
  oc_clock_encode_time_rfc3339(time, ts, sizeof(ts));
  PRINT("plgd time: %s\n", ts);
  return 0;
}

static void
plgd_time_init(void)
{
#if defined(__linux__) || defined(__ANDROID_API__)
  if (g_set_system_time) {
    PRINT("using settimeofday to set system time\n");
    plgd_time_configure(/*use_in_mbedtls*/ false, set_system_time, NULL);
    return;
  }
  PRINT("using plgd time in mbedTLS\n");
  plgd_time_configure(/*use_in_mbedtls*/ true, print_time, NULL);
#else  /* !__linux__ && !__ANDROID_API__ */
  PRINT("using plgd time in mbedTLS\n");
  plgd_time_configure(/*use_in_mbedtls*/ true, print_time, NULL);
#endif /* __linux__ || __ANDROID_API__ */
}

#endif /* OC_HAS_FEATURE_PLGD_TIME */

static int
app_init(void)
{
  oc_set_con_res_announced(true);
  if (oc_init_platform(manufacturer, NULL, NULL) != 0) {
    return -1;
  }
#ifdef OC_HAS_FEATURE_PLGD_TIME
  plgd_time_init();
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  if (oc_add_device("/oic/d", device_rt, device_name, spec_version,
                    data_model_version, NULL, NULL) != 0) {
    return -1;
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

#ifdef OC_HAS_FEATURE_PLGD_WOT
static plgd_wot_property_t light_properties[] = {
  {
    .name = "name",
    .type = PLGD_DEV_WOT_PROPERTY_TYPE_STRING,
    .description = "Light name",
    .read_only = true,
  },
  {
    .name = "state",
    .type = PLGD_DEV_WOT_PROPERTY_TYPE_BOOLEAN,
    .observable = true,
    .description = "Turn On/Off",
  },
  {
    .name = "power",
    .type = PLGD_DEV_WOT_PROPERTY_TYPE_INTEGER,
    .observable = true,
    .description = "Power Level",
  },
  {
    /* sentinel */
    .name = NULL,
  },
};
#endif

static void
register_lights(void)
{
  if (num_resources > 0) {
    lights = (struct light_t *)calloc(num_resources, sizeof(struct light_t));
  }
  for (int i = 0; i < num_resources; i++) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf) - 1, "/light/%d", i + 1);
    if (n < 0) {
      continue;
    }
    buf[n] = 0;
    oc_resource_t *res = oc_new_resource(NULL, buf, 1, 0);
    oc_resource_bind_resource_type(res, resource_rt);
    oc_resource_bind_resource_interface(res, OC_IF_RW);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_observable(res, true);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_set_access_in_RFOTM(res, true,
                                    OC_PERM_UPDATE | OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
#ifdef OC_HAS_FEATURE_PLGD_WOT
    plgd_wot_resource_set_thing_description(
      res,
      (plgd_wot_extend_thing_description_cb_t)
        plgd_wot_resource_set_td_properties,
      light_properties);
#endif
    oc_resource_set_request_handler(res, OC_GET, get_handler, &lights[i]);
    oc_resource_set_request_handler(res, OC_POST, post_handler, &lights[i]);
    oc_cloud_add_resource(res);
    oc_add_resource(res);
  }
}

#ifdef OC_COLLECTIONS

/* Setting custom Collection-level properties */
static int64_t g_battery_level = 94;

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
  bool state;
} oc_switch_t;

#ifdef OC_COLLECTIONS_IF_CREATE

OC_MEMB(switch_s, oc_switch_t, 1);
OC_LIST(switches);

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
  PRINT("%s\n", __func__);
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
get_switch_instance(const char *href, oc_string_array_t *types,
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
      oc_resource_set_request_handler(cswitch->resource, OC_DELETE,
                                      delete_cswitch, cswitch);
      oc_resource_set_request_handler(cswitch->resource, OC_POST, post_cswitch,
                                      cswitch);
      oc_resource_set_properties_cbs(cswitch->resource, get_switch_properties,
                                     cswitch, set_switch_properties, cswitch);
      oc_add_resource(cswitch->resource);
      oc_set_delayed_callback(cswitch->resource, register_to_cloud, 0);
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
  PRINT("%s\n", __func__);
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

static void
register_collection(void)
{
  oc_resource_t *col = oc_new_collection(NULL, "/switches", 1, 0);
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
register_con(void)
{
  oc_resource_t *con_res = oc_core_get_resource_by_index(OCF_CON, 0);
  oc_cloud_add_resource(con_res);
}

#ifdef OC_MNT
static void
register_mnt(void)
{
  oc_resource_t *mnt_res = oc_core_get_resource_by_index(OCF_MNT, 0);
  oc_cloud_add_resource(mnt_res);
}
#endif /* OC_MNT */

#ifdef OC_HAS_FEATURE_PLGD_TIME
static void
register_plgd_time(void)
{
  oc_resource_t *ptime_res = oc_core_get_resource_by_index(PLGD_TIME, 0);
  oc_cloud_add_resource(ptime_res);
}
#endif /* OC_HAS_FEATURE_PLGD_TIME */

static void
register_resources(void)
{
  register_lights();
#ifdef OC_COLLECTIONS
  register_collection();
#endif /* OC_COLLECTIONS */
  register_con();
#ifdef OC_MNT
  register_mnt();
#endif /* OC_MNT */
#ifdef OC_HAS_FEATURE_PLGD_TIME
  register_plgd_time();
#endif /* OC_HAS_FEATURE_PLGD_TIME */
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
  // preserve name after factory reset
  oc_device_info_t *dev = oc_core_get_device_info(device);
  oc_free_string(&dev->name);
  oc_new_string(&dev->name, device_name, strlen(device_name));

  unsigned char cloud_ca[4096];
  size_t cert_len = 4096;
  if (read_pem("pki_certs/cloudca.pem", (char *)cloud_ca, &cert_len) < 0) {
    PRINT("ERROR: unable to read pki_certs/cloudca.pem\n");
    return;
  }

  int rootca_credid =
    oc_pki_add_trust_anchor(0, (const unsigned char *)cloud_ca, cert_len);
  if (rootca_credid < 0) {
    PRINT("ERROR installing root ca\n");
    return;
  }

  unsigned char mfg_crt[4096];
  size_t mfg_crt_len = 4096;
  if (read_pem("pki_certs/mfgcrt.pem", (char *)mfg_crt, &mfg_crt_len) < 0) {
    PRINT("ERROR: unable to read pki_certs/mfgcrt.pem\n");
    return;
  }
  unsigned char mfg_key[4096];
  size_t mfg_key_len = 4096;
  if (read_pem("pki_certs/mfgkey.pem", (char *)mfg_key, &mfg_key_len) < 0) {
    PRINT("ERROR: unable to read pki_certs/mfgkey.pem\n");
    return;
  }
  int mfg_credid =
    oc_pki_add_mfg_cert(0, (const unsigned char *)mfg_crt, mfg_crt_len,
                        (const unsigned char *)mfg_key, mfg_key_len);
  if (mfg_credid < 0) {
    PRINT("ERROR installing manufacturer certificate\n");
    return;
  }
  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, mfg_credid);
#endif /* OC_SECURITY && OC_PKI */
}

static void
display_device_uuid(void)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(0), buffer, sizeof(buffer));

  PRINT("Started device with ID: %s\n", buffer);
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
#endif /* OC_SECURITY && OC_PKI */

#define OPT_DISABLE_TLS_VERIFY_TIME "disable-tls-verify-time"
#define OPT_HELP "help"
#define OPT_NUM_RESOURCES "num-resources"
#define OPT_DEVICE_NAME "device-name"
#define OPT_CLOUD_AUTH_CODE "cloud-auth-code"
#define OPT_CLOUD_CIS "cloud-endpoint"
#define OPT_CLOUD_APN "cloud-auth-provider-name"
#define OPT_CLOUD_SID "cloud-id"

#define OPT_TIME "time"
#define OPT_SET_SYSTEM_TIME "set-system-time"

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
  PRINT("./%s <%s> <%s> <%s> <%s> <%s>\n\n", binary_name, OPT_ARG_DEVICE_NAME,
        OPT_ARG_CLOUD_AUTH_CODE, OPT_ARG_CLOUD_CIS, OPT_ARG_CLOUD_SID,
        OPT_ARG_CLOUD_APN);
  PRINT("OPTIONS:\n");
  PRINT("  -h | --%-26s print help\n", OPT_HELP);
  PRINT("  -n | --%-26s device name\n", OPT_DEVICE_NAME);
  PRINT("  -a | --%-26s cloud authorization code\n", OPT_CLOUD_AUTH_CODE);
  PRINT("  -e | --%-26s cloud endpoint\n", OPT_CLOUD_CIS);
  PRINT("  -i | --%-26s cloud id\n", OPT_CLOUD_SID);
  PRINT("  -p | --%-26s cloud authorization provider name\n", OPT_CLOUD_APN);
  PRINT("  -r | --%-26s number of resources\n", OPT_NUM_RESOURCES);
#if defined(OC_SECURITY) && defined(OC_PKI)
  PRINT("  -d | --%-26s disable time verification during TLS handshake\n",
        OPT_DISABLE_TLS_VERIFY_TIME);
#endif /* OC_SECURITY && OC_PKI */
#ifdef OC_HAS_FEATURE_PLGD_TIME
  PRINT("  -t | --%-26s set plgd time of device\n", OPT_TIME " <rfc3339 time>");
  PRINT("  -s | --%-26s use plgd time to set system time (root required on "
        "Linux)\n",
        OPT_SET_SYSTEM_TIME);
#endif /* OC_HAS_FEATURE_PLGD_TIME */
  PRINT("ARGUMENTS:\n");
  PRINT("  %-33s device name (optional, default: cloud_server)\n",
        OPT_ARG_DEVICE_NAME);
  PRINT("  %-33s cloud authorization code (optional)\n",
        OPT_ARG_CLOUD_AUTH_CODE);
  PRINT("  %-33s cloud endpoint (optional)\n", OPT_ARG_CLOUD_CIS);
  PRINT("  %-33s cloud id (optional)\n", OPT_ARG_CLOUD_SID);
  PRINT("  %-33s cloud authorization provider name (optional)\n",
        OPT_ARG_CLOUD_APN);
}

typedef struct
{
  bool help;
#if defined(OC_SECURITY) && defined(OC_PKI)
  bool disable_tls_verify_time;
#endif /* OC_SECURITY && OC_PKI */
} parse_options_result_t;

static bool
parse_options(int argc, char *argv[], parse_options_result_t *parsed_options)
{
  static struct option long_options[] = {
    { OPT_HELP, no_argument, NULL, 'h' },
    { OPT_DEVICE_NAME, required_argument, NULL, 'n' },
    { OPT_CLOUD_AUTH_CODE, required_argument, NULL, 'a' },
    { OPT_CLOUD_CIS, required_argument, NULL, 'e' },
    { OPT_CLOUD_SID, required_argument, NULL, 'i' },
    { OPT_CLOUD_APN, required_argument, NULL, 'p' },
    { OPT_NUM_RESOURCES, required_argument, NULL, 'r' },
#if defined(OC_SECURITY) && defined(OC_PKI)
    { OPT_DISABLE_TLS_VERIFY_TIME, no_argument, NULL, 'd' },
#endif /* OC_SECURITY && OC_PKI */
#ifdef OC_HAS_FEATURE_PLGD_TIME
    { OPT_TIME, required_argument, NULL, 't' },
    { OPT_SET_SYSTEM_TIME, no_argument, NULL, 's' },
#endif /* OC_HAS_FEATURE_PLGD_TIME */
    { NULL, 0, NULL, 0 },
  };

  while (true) {
    int option_index = 0;
    int opt =
      getopt_long(argc, argv, "hdn:a:e:i:p:r:st:", long_options, &option_index);
    if (opt == -1) {
      break;
    }
    switch (opt) {
    case 0:
      if (long_options[option_index].flag != 0) {
        break;
      }
      PRINT("invalid option(%s)\n", argv[optind]);
      return false;
    case 'h':
      printhelp(argv[0]);
      parsed_options->help = true;
      return true;
#if defined(OC_SECURITY) && defined(OC_PKI)
    case 'd':
      parsed_options->disable_tls_verify_time = true;
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
        PRINT("invalid number of resources argument value(%s)\n", optarg);
        return false;
      }
      num_resources = (int)val;
      break;
    }
#ifdef OC_HAS_FEATURE_PLGD_TIME
    case 't': {
      oc_clock_time_t time =
        oc_clock_parse_time_rfc3339(optarg, strlen(optarg));
      if (time == 0) {
        PRINT("invalid plgd time value(%s)\n", optarg);
        return false;
      }
      g_time = time;
      break;
    }
    case 's': {
#if defined(__linux__) || defined(__ANDROID_API__)
      if (!is_root()) {
        PRINT("root required for settimeofday: see man settimeofday\n");
        return false;
      }
      g_set_system_time = true;
#endif /* __linux__ || __ANDROID_API__ */
      break;
    }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
    default:
      PRINT("invalid option(%s)\n", argv[optind]);
      return false;
    }
  }
  argc -= (optind - 1);
  for (int i = 1; i < argc; ++i, ++optind) {
    argv[i] = argv[optind];
  }
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

int
main(int argc, char *argv[])
{
  parse_options_result_t parsed_options = {
    .help = false,
#if defined(OC_SECURITY) && defined(OC_PKI)
    .disable_tls_verify_time = false,
#endif /* OC_SECURITY && OC_PKI */
  };
  if (!parse_options(argc, argv, &parsed_options)) {
    return -1;
  }
  if (parsed_options.help) {
    return 0;
  }

  PRINT("Using parameters: device_name: %s, auth_code: %s, cis: %s, "
        "sid: %s, "
        "apn: %s, "
        "num_resources: %d, ",
        device_name, auth_code, cis, sid, apn, num_resources);
#if defined(OC_SECURITY) && defined(OC_PKI)
  PRINT("disable_tls_time_verification: %s, ",
        parsed_options.disable_tls_verify_time ? "true" : "false");
#endif /* OC_SECURITY && OC_PKI */
  PRINT("\n");

#if defined(OC_SECURITY) && defined(OC_PKI)
  if (parsed_options.disable_tls_verify_time) {
    oc_pki_set_verify_certificate_cb(&disable_time_verify_certificate_cb);
  }
#endif /* OC_SECURITY && OC_PKI */

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
  oc_set_max_app_data_size(8 * 1024 + num_resources * 200);
  oc_set_min_app_data_size(512);
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_sec_certs_md_set_algorithms_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384));
  oc_sec_certs_ecp_set_group_ids_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1));
#endif /* OC_SECURITY && OC_PKI */
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
  display_device_uuid();
#ifdef OC_HAS_FEATURE_PLGD_TIME
  if (g_time != (oc_clock_time_t)-1) {
    plgd_time_set_time(g_time);
  }
#endif /* OC_HAS_FEATURE_PLGD_TIME */

  run();

  oc_cloud_manager_stop(ctx);
  oc_main_shutdown();
  return 0;
}

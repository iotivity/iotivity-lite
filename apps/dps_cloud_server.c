/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

// NOLINTNEXTLINE(bugprone-reserved-identifier)
#define _GNU_SOURCE // required to get strptime from time.h

#include "oc_api.h"
#include "oc_certs.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_log.h"
#include "oc_pki.h"
#include "plgd/plgd_dps.h"
#include "plgd/plgd_time.h"
#include "util/oc_atomic.h"

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifdef PLGD_DPS_CLOUD_SERVER_DBG
#define DPSCS_DBG(...) printf(__VA_ARGS__)
#else /* !PLGD_DPS_CLOUD_SERVER_DBG */
#define DPSCS_DBG(...)
#endif /* PLGD_DPS_CLOUD_SERVER_DBG */

#ifdef __linux__
#include <linux/limits.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/time.h>
#else
#error "Unsupported OS"
#endif

#ifdef PLGD_DPS_FAKETIME
#include <math.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Signal variables */
static OC_ATOMIC_INT8_T g_quit = 0;
static OC_ATOMIC_INT8_T g_reset = 0;

/* Application state */
static bool g_initialized = false;
static const size_t g_device_id = 0;
static int g_create_configuration_resource = 0;
static int g_expiration_limit = -1;
static int16_t g_observer_max_retry = -1;
static int g_skip_ca_verification = 0;
static int g_wait_for_reset = 0;
static bool g_dhcp_enabled = false;
static bool g_set_system_time = false;

#ifdef PLGD_DPS_FAKETIME
static struct
{
  char value[128]; // NOLINT(readability-magic-numbers)
  char format[64]; // NOLINT(readability-magic-numbers)
  bool enabled;
} g_faketime = { 0 };

#endif /* PLGD_DPS_FAKETIME */

/* Application configuration */
static const char *g_dps_device_name = "dps";
static char g_dps_cert_dir[PATH_MAX] = "pki_certs";
#ifdef OC_DYNAMIC_ALLOCATION
static char **g_dps_endpoint = NULL;
#else  /* !OC_DYNAMIC_ALLOCATION */
static char g_dps_endpoint[2][512] = {
  { 0 },
  { 0 }
}; // NOLINT(readability-magic-numbers)
#endif /* OC_DYNAMIC_ALLOCATION */
static int g_dps_endpoint_count = 0;
static const char *g_dhcp_leases_file = "/var/lib/dhcp/dhclient.leases";
static const char *g_dhcp_option_vendor_encapsulated_options =
  "vendor-encapsulated-options";

/* Run-loop synchronization */
static int g_eventfd = -1;

static const char *
strnstr(const char *str1, const char *str2, size_t n)
{
  // simplistic algorithm with O(n2) worst case
  if (str2 == NULL || str1 == NULL || *str2 == '\0') {
    return NULL;
  }
  for (size_t len = strlen(str2); len <= n; n--, str1++) {
    if (memcmp(str1, str2, len) == 0) {
      return str1;
    }
  }
  return NULL;
}

static const char *
find_start_value(const char *value, size_t len)
{
  const char *ignored_characters = " \t\"";
  for (size_t i = 0; i < len; i++) {
    if (strchr(ignored_characters, value[i]) != NULL) {
      continue;
    }
    return value + i;
  }
  return NULL;
}

static const char *
find_end_value(const char *value, size_t len)
{
  const char *end_separator = " \t\"\n,;";
  for (size_t i = 0; i < len; i++) {
    if (strchr(end_separator, value[i]) != NULL) {
      return value + i;
    }
  }
  return NULL;
}

/**
 * @brief Callback function which is called when value of dhcp option has been
 * parsed.
 *
 * @param value value is temporary buffer, so user must copy it to other buffer.
 * @param value_len length of value.
 * @param user_data user data.
 * @return true the parsing will continue.
 * @return false for end parsing.
 */
typedef bool (*plgd_dps_dhcp_get_option_value_cb_t)(const char *value,
                                                    size_t value_len,
                                                    void *user_data);

/**
 * @brief Parse dhcp options from dhcp leases file.
 *
 * @param file_path path to dhcp lease file.
 * @param dhcp_option_name name of dhcp option.
 * @param value_cb callback function to get dps uri.
 * @param user_data user data.
 * @return 0 on success.
 * @return -1 on failure.
 */
static int
plgd_dps_dhcp_get_option_leases_file(
  const char *file_path, const char *dhcp_option_name,
  plgd_dps_dhcp_get_option_value_cb_t value_cb, void *user_data)
{
  if (file_path == NULL || dhcp_option_name == NULL) {
    printf("ERROR: invalid arguments");
    return -1;
  }
  FILE *file = fopen(file_path, "r");
  if (file == NULL) {
    printf("ERROR: cannot open file %s", file_path);
    return -1;
  }

  char *line = NULL;
  size_t len = 0;
  bool found = false;
  while ((getline(&line, &len, file)) != -1) {
    const char *opt = strnstr(line, dhcp_option_name, len);
    if (opt == NULL) {
      continue;
    }
    const char *start_value =
      find_start_value(opt + strlen(dhcp_option_name),
                       len - (opt - line) - strlen(dhcp_option_name));
    if (start_value == NULL) {
      DPSCS_DBG("cannot find start for option %s in line %s", dhcp_option_name,
                line);
      continue;
    }
    const char *end_value =
      find_end_value(start_value, len - (start_value - line));
    if (end_value == NULL) {
      DPSCS_DBG("cannot find end for option %s in line %s", dhcp_option_name,
                line);
      continue;
    }
    size_t value_len = end_value - start_value;
    if (value_len == 0) {
      DPSCS_DBG("value is empty for option %s in line %s", dhcp_option_name,
                line);
      continue;
    }
    found = true;
    if (value_cb != NULL) {
      char buf[value_len + 1];
      memcpy(buf, start_value, value_len);
      buf[value_len] = '\0';
      bool con = value_cb(start_value, value_len, user_data);
      if (!con) {
        break;
      }
    }
  }
  fclose(file);
  if (line) {
    free(line);
  }
  if (!found) {
    printf("ERROR: cannot find option %s in file %s", dhcp_option_name,
           file_path);
  }
  return found ? 0 : -1;
}

static void
signal_event_loop(void)
{
  ssize_t len = 0;
  do {
    len = eventfd_write(g_eventfd, 1);
  } while (len < 0 && errno == EINTR);
#ifdef PLGD_DPS_CLOUD_SERVER_DBG
  if (len < 0) {
    DPSCS_DBG("failed to signal loop event, error (%d)", errno);
  }
#endif /* PLGD_DPS_CLOUD_SERVER_DBG */
}

static void
handle_signal(int signal)
{
  if (signal == SIGPIPE) {
    return;
  }
  signal_event_loop();
  if (signal == SIGHUP) {
    OC_ATOMIC_STORE8(g_reset, 1);
  } else {
    OC_ATOMIC_STORE8(g_quit, 1);
  }
}

static bool
init(void)
{
  struct sigaction sig;
  sigfillset(&sig.sa_mask);
  sig.sa_flags = 0;
  sig.sa_handler = handle_signal;
  sigaction(SIGHUP, &sig, NULL);
  sigaction(SIGINT, &sig, NULL);
  sigaction(SIGPIPE, &sig, NULL);
  sigaction(SIGTERM, &sig, NULL);

  int evtfd =
    eventfd(/*initval*/ 0, EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC);
  if (evtfd < 0) {
    printf("ERROR: failed to create eventfd, error (%d)\n", errno);
    return false;
  }
  g_eventfd = evtfd;
  return true;
}

static void
deinit(void)
{
  close(g_eventfd);
  g_eventfd = -1;
#ifdef OC_DYNAMIC_ALLOCATION
  for (int i = 0; i < g_dps_endpoint_count; i++) {
    free(g_dps_endpoint[i]);
  }
  free(g_dps_endpoint);
  g_dps_endpoint = NULL;
#else  /* !OC_DYNAMIC_ALLOCATION */
  memset(g_dps_endpoint, 0, sizeof(g_dps_endpoint));
#endif /* OC_DYNAMIC_ALLOCATION */
  g_dps_endpoint_count = 0;
}

static void
reset(void)
{
  DPSCS_DBG("reset (device(%zu) %s)\n", g_device_id,
            g_initialized ? "initialized" : "not initialized");
  if (!g_initialized) {
    return;
  }
  const plgd_dps_context_t *ctx = plgd_dps_get_context(g_device_id);
  if (ctx == NULL) {
    printf("ERROR: cannot reset: device(%zu) context not found\n", g_device_id);
    return;
  }
  oc_reset_device(plgd_dps_get_device(ctx));
}

static void
run_loop_read_eventfd(int evtfd)
{
  ssize_t len;
  eventfd_t dummy_value;
  do {
    len = eventfd_read(evtfd, &dummy_value);
  } while (len < 0 && errno == EINTR);
}

static void
run_loop_ppoll(int evtfd, const struct timespec *timeout)
{
  struct pollfd fds = {
    .fd = evtfd,
    .events = POLLIN,
  };
  int ret = ppoll(&fds, 1, timeout, NULL);
  if (ret < 0) {
    printf("ERROR: failed to poll descriptor(%d), error(%d)\n", evtfd, errno);
    return;
  }
  if (ret == 0) {
    return;
  }

  if ((fds.revents & POLLIN) == 0) {
    return;
  }
  run_loop_read_eventfd(evtfd);
}

static void
run(void)
{
  while (OC_ATOMIC_LOAD8(g_quit) != 1) {
    if (OC_ATOMIC_LOAD8(g_reset) != 0) {
      OC_ATOMIC_STORE8(g_reset, 0);
      g_wait_for_reset = 0;
      reset();
    }

    oc_clock_time_t next_event_mt = oc_main_poll_v1();
    if (next_event_mt == 0) {
      run_loop_ppoll(g_eventfd, NULL);
      continue;
    }

    oc_clock_time_t now_mt = oc_clock_time_monotonic();
    if (now_mt >= next_event_mt) {
      continue;
    }
    struct timespec timeout = oc_clock_time_to_timespec(next_event_mt - now_mt);
    run_loop_ppoll(g_eventfd, &timeout);
  }
}

static void
cloud_status_handler(oc_cloud_context_t *cloud_ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  printf("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    printf("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    printf("\t\t-Token Expiry: ");
    if (cloud_ctx != NULL) {
      printf("%d\n", oc_cloud_get_token_expiry(cloud_ctx));
    } else {
      printf("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    printf("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    printf("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    printf("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    printf("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    printf("\t\t-Refreshed Token\n");
  }
}

static void
dps_status_handler(plgd_dps_context_t *ctx, plgd_dps_status_t status,
                   void *data)
{
  (void)data;
  (void)ctx;
  printf("\nDPS Manager Status:\n");
  if (status == 0) {
    printf("\t\t-Uninitialized\n");
  }
  if ((status & PLGD_DPS_INITIALIZED) != 0) {
    printf("\t\t-Initialized\n");
  }
  if ((status & PLGD_DPS_GET_TIME) != 0) {
    printf("\t\t-Get time\n");
  }
  if ((status & PLGD_DPS_HAS_TIME) != 0) {
    printf("\t\t-Has time\n");
  }
  if ((status & PLGD_DPS_GET_OWNER) != 0) {
    printf("\t\t-Get owner\n");
  }
  if ((status & PLGD_DPS_HAS_OWNER) != 0) {
    printf("\t\t-Has owner\n");
  }
  if ((status & PLGD_DPS_GET_CLOUD) != 0) {
    printf("\t\t-Get cloud configuration\n");
  }
  if ((status & PLGD_DPS_HAS_CLOUD) != 0) {
    printf("\t\t-Has cloud configuration\n");
  }
  if ((status & PLGD_DPS_GET_CREDENTIALS) != 0) {
    printf("\t\t-Get credentials\n");
  }
  if ((status & PLGD_DPS_HAS_CREDENTIALS) != 0) {
    printf("\t\t-Has credentials\n");
  }
  if ((status & PLGD_DPS_GET_ACLS) != 0) {
    printf("\t\t-Get acls\n");
  }
  if ((status & PLGD_DPS_HAS_ACLS) != 0) {
    printf("\t\t-Has set acls\n");
  }
  if ((status & PLGD_DPS_CLOUD_STARTED) != 0) {
    printf("\t\t-Started cloud\n");
  }
  if ((status & PLGD_DPS_RENEW_CREDENTIALS) != 0) {
    printf("\t\t-Renew credentials\n");
  }
  if ((status & PLGD_DPS_TRANSIENT_FAILURE) != 0) {
    printf("\t\t-Transient failure\n");
  }
  if ((status & PLGD_DPS_FAILURE) != 0) {
    printf("\t\t-Failure\n");
  }
}

static int
set_system_time(oc_clock_time_t time, void *data)
{
  (void)data;
  struct timeval now;
  now.tv_sec = (long)(time / OC_CLOCK_SECOND);
  oc_clock_time_t rem_ticks = time % OC_CLOCK_SECOND;
#define USECS_IN_SEC 1000000
  now.tv_usec =
    (__suseconds_t)(((double)rem_ticks * USECS_IN_SEC) / OC_CLOCK_SECOND);
  return settimeofday(&now, NULL);
}

static int
print_time(oc_clock_time_t time, void *data)
{
  (void)data;
#define RFC3339_BUFFER_SIZE (64)
  char ts_str[RFC3339_BUFFER_SIZE] = { 0 };
  oc_clock_encode_time_rfc3339(time, ts_str, sizeof(ts_str));
  DPSCS_DBG("plgd time: %s\n", ts_str);
  return 0;
}

/**
 * @brief Configure the plgd-time feature.
 *
 * @param system_time if true then settimeofday is used in by plgd_time_set_time
 * to set time on the whole system otherwise mbedTLS function to get current
 * time is overriden to get time derived from plgd_time
 */
static void
time_configure(bool system_time)
{
  if (system_time) {
    DPSCS_DBG("using settimeofday to set system time\n");
    plgd_time_configure(/*use_in_mbedtls*/ false, set_system_time, NULL);
    return;
  }
  DPSCS_DBG("using plgd time in mbedTLS\n");
  plgd_time_configure(/*use_in_mbedtls*/ true, print_time, NULL);
}

static int
app_init(void)
{
  // define application specific values.
  const char *spec_version = "ocf.2.0.5";
  const char *data_model_version = "ocf.res.1.3.0";
  const char *device_rt = "oic.d.cloudDevice";
  const char *manufacturer = "ocfcloud.com";

  oc_set_con_res_announced(true);
  if (oc_init_platform(manufacturer, NULL, NULL) != 0) {
    printf("ERROR: failed to init platform\n");
    return -1;
  }
  if (oc_add_device("/oic/d", device_rt, g_dps_device_name, spec_version,
                    data_model_version, NULL, NULL) != 0) {
    printf("ERROR: failed to add device resource\n");
    return -1;
  }
  if (plgd_dps_init() != 0) {
    return -1;
  }
  time_configure(g_set_system_time);
  return 0;
}

struct light_t
{
  bool state;
  int64_t power;
};

static struct light_t light1 = { 0 };

static void
get_handler(oc_request_t *request, oc_interface_mask_t iface, void *user_data)
{
  DPSCS_DBG("get_handler:\n");
  const struct light_t *light = (const struct light_t *)user_data;

  oc_rep_start_root_object();
  switch (iface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    __attribute__((fallthrough));
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
  DPSCS_DBG("post_handler:\n");
  struct light_t *light = (struct light_t *)user_data;
  (void)iface_mask;
  for (oc_rep_t *rep = request->request_payload; rep != NULL; rep = rep->next) {
    const char *key = oc_string(rep->name);
    if (key == NULL) {
      continue;
    }
    DPSCS_DBG("key: %s ", key);
    if (strcmp(key, "state") == 0) {
      if (rep->type != OC_REP_BOOL) {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      light->state = rep->value.boolean;
      DPSCS_DBG("value: %d", light->state);
      continue;
    }
    if (strcmp(key, "power") == 0) {
      if (rep->type != OC_REP_INT) {
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
      light->power = rep->value.integer;
      DPSCS_DBG("value: %" PRId64, light->power);
      continue;
    }
  }
  DPSCS_DBG("\n");
  oc_send_response(request, OC_STATUS_CHANGED);
}

static bool
register_lights(size_t device)
{
  oc_resource_t *res = oc_new_resource(NULL, "/light/1", 1, device);
  oc_resource_bind_resource_type(res, "core.light");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, get_handler, &light1);
  oc_resource_set_request_handler(res, OC_POST, post_handler, &light1);
  if (!oc_add_resource(res)) {
    printf("ERROR: Could not add %s resource to device\n", oc_string(res->uri));
    return false;
  }
  if (oc_cloud_add_resource(res) < 0) {
    printf("ERROR: Could not add %s resource to cloud\n", oc_string(res->uri));
    return false;
  }
  return true;
}

#ifdef OC_COLLECTIONS

/* Setting custom Collection-level properties */
static int64_t g_battery_level = 94; // NOLINT(readability-magic-numbers)

static bool
set_switches_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                        void *data)
{
  (void)resource;
  (void)data;
  for (; rep != NULL; rep = rep->next) {
    if (rep->type != OC_REP_INT) {
      continue;
    }
    const char battery_level[] = "bl";
    if (oc_string_len(rep->name) == sizeof(battery_level) - 1 &&
        memcmp(oc_string(rep->name), battery_level,
               sizeof(battery_level) - 1) == 0) {
      g_battery_level = rep->value.integer;
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
  uint16_t id;
  bool state;
} oc_switch_t;

#ifdef OC_COLLECTIONS_IF_CREATE

OC_MEMB(switch_s, oc_switch_t, 1);
OC_LIST(switches); // list of switch instances ordered by id

static bool
set_switch_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                      void *data)
{
  (void)resource;
  oc_switch_t *cswitch = (oc_switch_t *)data;
  for (; rep != NULL; rep = rep->next) {
    if (rep->type != OC_REP_BOOL) {
      continue;
    }
    cswitch->state = rep->value.boolean;
  }
  return true;
}

static void
get_switch_properties(const oc_resource_t *resource,
                      oc_interface_mask_t iface_mask, void *data)
{
  const oc_switch_t *cswitch = (const oc_switch_t *)data;
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(resource);
    __attribute__((fallthrough));
  case OC_IF_A:
    oc_rep_set_boolean(root, value, cswitch->state);
    break;
  default:
    break;
  }
}

static bool
validate_cswitch_payload(oc_rep_t *rep)
{
  for (; rep != NULL; rep = rep->next) {
    if (rep->type == OC_REP_BOOL) {
      const char rep_name[] = "value";
      const size_t rep_name_len = sizeof(rep_name) - 1;
      if (oc_string_len(rep->name) != rep_name_len ||
          memcmp(oc_string(rep->name), rep_name, rep_name_len) != 0) {
        return false;
      }
      continue;
    }

    if ((oc_string_len(rep->name) > 2) &&
        (strncmp(oc_string(rep->name), "x.", 2) == 0)) {
      continue;
    }
    return false;
  }
  return true;
}

static void
post_cswitch(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;

  bool bad_request = !validate_cswitch_payload(request->request_payload);
  if (!bad_request) {
    set_switch_properties(request->resource, request->request_payload, cswitch);
  }

  oc_rep_start_root_object();
  oc_rep_set_boolean(root, value, cswitch->state);
  oc_rep_end_root_object();

  oc_status_t code = OC_STATUS_CHANGED;
  if (bad_request) {
    code = OC_STATUS_BAD_REQUEST;
  }
  oc_send_response(request, code);
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
  DPSCS_DBG("%s\n", __func__);
  (void)request;
  (void)iface_mask;
  oc_switch_t *cswitch = (oc_switch_t *)user_data;

  oc_delayed_delete_resource(cswitch->resource);
  oc_send_response(request, OC_STATUS_DELETED);
}

static oc_event_callback_retval_t
register_to_cloud(void *resource)
{
  oc_resource_t *res = (oc_resource_t *)resource;
  oc_cloud_add_resource(res);
  return OC_EVENT_DONE;
}

static oc_resource_t *
get_switch_instance(
  const char *href, const oc_string_array_t *types,
  oc_resource_properties_t prop, oc_interface_mask_t iface_mask,
  size_t device) // NOLINT(bugprone-easily-swappable-parameters)
{
  oc_switch_t *cswitch = (oc_switch_t *)oc_memb_alloc(&switch_s);
  if (cswitch == NULL) {
    return NULL;
  }
  cswitch->resource = oc_new_resource(
    NULL, href, (uint8_t)oc_string_array_get_allocated_size(*types), device);
  if (cswitch->resource == NULL) {
    oc_memb_free(&switch_s, cswitch);
    return NULL;
  }
  for (size_t i = 0; i < oc_string_array_get_allocated_size(*types); i++) {
    const char *type = oc_string_array_get_item(*types, i);
    oc_resource_bind_resource_type(cswitch->resource, type);
  }
  oc_resource_bind_resource_interface(cswitch->resource, iface_mask);
  cswitch->resource->properties = prop;
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
  DPSCS_DBG("%s\n", __func__);
  oc_switch_t *cswitch = (oc_switch_t *)oc_list_head(switches);
  while (cswitch) {
    if (cswitch->resource == resource) {
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
register_collection(size_t device)
{
  oc_resource_t *col = oc_new_collection(NULL, "/switches", 1, device);
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
  if (!oc_add_collection_v1(col)) {
    printf("ERROR: could not register /switches collection\n");
    return false;
  }
  DPSCS_DBG("\tResources added to collection.\n");

  if (oc_cloud_add_resource(col) < 0) {
    printf("ERROR: could not publish /switches collection\n");
    return false;
  }
  DPSCS_DBG("\tCollection resource published.\n");
  return true;
}
#endif /* OC_COLLECTIONS */

static bool
register_con(size_t device)
{
  oc_resource_t *con_res = oc_core_get_resource_by_index(OCF_CON, device);
  return oc_cloud_add_resource(con_res) == 0;
}

static void
register_resources(void)
{
  if (!register_lights(g_device_id)) {
    oc_abort("ERROR: could not register light\n");
  }
#ifdef OC_COLLECTIONS
  if (!register_collection(g_device_id)) {
    oc_abort("ERROR: could not register collection\n");
  }
#endif /* OC_COLLECTIONS */
  if (!register_con(g_device_id)) {
    oc_abort("ERROR: could not register configuration resource\n");
  }

  plgd_dps_context_t *dps_ctx = plgd_dps_get_context(g_device_id);
  if (dps_ctx == NULL) {
    return;
  }
  plgd_dps_set_configuration_resource(dps_ctx,
                                      g_create_configuration_resource != 0);
}

static void
display_device_uuid(size_t device_id)
{
  char buffer[OC_UUID_LEN];
  oc_uuid_to_str(oc_core_get_device_id(device_id), buffer, sizeof(buffer));
  printf("Started device with ID: %s\n", buffer);
}

/**************************************************************************
 * DPS
 **************************************************************************/

static int
dps_read_pem(const char *file_path, char *buffer, size_t *buffer_size)
{
  FILE *file = fopen(file_path, "r");
  if (file == NULL) {
    printf("ERROR: unable to open %s\n", file_path);
    return -1;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    goto error;
  }
  long pem_len = ftell(file);
  if (pem_len < 0) {
    goto error;
  }
  if ((size_t)pem_len >= *buffer_size) {
    printf("ERROR: buffer provided too small\n");
    goto error;
  }
  if (fseek(file, 0, SEEK_SET) != 0) {
    goto error;
  }
  if (fread(buffer, 1, pem_len, file) < (size_t)pem_len) {
    goto error;
  }
  fclose(file);
  buffer[pem_len] = '\0';
  *buffer_size = (size_t)pem_len;
  return 0;

error:
  printf("ERROR: unable to read PEM\n");
  fclose(file);
  return -1;
}

static void
dps_concat_paths(char *buffer, size_t buffer_size, const char *cert_dir,
                 const char *file)
{
  memset(buffer, 0, buffer_size);
  size_t cert_dir_len = strlen(cert_dir);
  if (cert_dir_len >= buffer_size) {
    abort();
  }
  memcpy(buffer, cert_dir, cert_dir_len);
  buffer[cert_dir_len] = '\0';
  // NOLINTNEXTLINE(clang-analyzer-security.insecureAPI.strcpy)
  strcat(buffer, file);
}

/**
 * @brief Add manufacturer's trusted root certificate authority and
 * manufacturer's certificate to the device.
 *
 * @param dps_ctx device context (cannot be NULL)
 * @param cert_dir path to directory with certificates (cannot be NULL)
 * @return int 0 on success
 * @return int -1 on failure
 */
static int
dps_add_certificates(const plgd_dps_context_t *dps_ctx, const char *cert_dir)
{
  assert(dps_ctx != NULL);
  assert(cert_dir != NULL);
#define CERT_BUFFER_SIZE 4096

  char path[PATH_MAX];
  int dpsca_credid = -1;
  int mfg_credid = -1;
  if (plgd_dps_get_skip_verify(dps_ctx) || g_dhcp_enabled) {
    DPSCS_DBG("adding of manufacturer trusted root ca skipped\n");
  } else {
    unsigned char dps_ca[CERT_BUFFER_SIZE];
    size_t dps_ca_size = sizeof(dps_ca) / sizeof(unsigned char);
    dps_concat_paths(path, sizeof(path), cert_dir, "/dpsca.pem");
    if (dps_read_pem(path, (char *)dps_ca, &dps_ca_size) < 0) {
      printf("ERROR: unable to read %s\n", path);
      goto error;
    }
    dpsca_credid = oc_pki_add_mfg_trust_anchor(plgd_dps_get_device(dps_ctx),
                                               dps_ca, dps_ca_size);
    if (dpsca_credid < 0) {
      printf("ERROR: installing manufacturer trusted root ca\n");
      goto error;
    }
    DPSCS_DBG("manufacturer trusted root ca credid=%d\n", dpsca_credid);
  }

  unsigned char mfg_crt[CERT_BUFFER_SIZE];
  size_t mfg_crt_size = sizeof(mfg_crt) / sizeof(unsigned char);
  dps_concat_paths(path, sizeof(path), cert_dir, "/mfgcrt.pem");
  if (dps_read_pem(path, (char *)mfg_crt, &mfg_crt_size) < 0) {
    printf("ERROR: unable to read %s\n", path);
    goto error;
  }
  unsigned char mfg_key[CERT_BUFFER_SIZE];
  size_t mfg_key_size = sizeof(mfg_key) / sizeof(unsigned char);
  dps_concat_paths(path, sizeof(path), cert_dir, "/mfgkey.pem");
  if (dps_read_pem(path, (char *)mfg_key, &mfg_key_size) < 0) {
    printf("ERROR: unable to read %s\n", path);
    goto error;
  }
  mfg_credid = oc_pki_add_mfg_cert(plgd_dps_get_device(dps_ctx), mfg_crt,
                                   mfg_crt_size, mfg_key, mfg_key_size);
  if (mfg_credid < 0) {
    printf("ERROR: installing manufacturer certificate\n");
    goto error;
  }
  DPSCS_DBG("manufacturer certificate credid=%d\n", mfg_credid);
  oc_pki_set_security_profile(plgd_dps_get_device(dps_ctx), OC_SP_BLACK,
                              OC_SP_BLACK, mfg_credid);
  return 0;

error:
  if (dpsca_credid != -1) {
    if (oc_sec_remove_cred_by_credid(dpsca_credid,
                                     plgd_dps_get_device(dps_ctx))) {
      DPSCS_DBG("certificate(%d) removed\n", dpsca_credid);
    } else {
      printf("WARNING: failed to remove manufacturer trusted root ca(%d)\n",
             dpsca_credid);
    }
  }
  if (mfg_credid != -1) {
    if (oc_sec_remove_cred_by_credid(mfg_credid,
                                     plgd_dps_get_device(dps_ctx))) {
      DPSCS_DBG("certificate(%d) removed\n", mfg_credid);
    } else {
      printf("WARNING: failed to remove manufacturer certificate(%d)\n",
             mfg_credid);
    }
  }
  return -1;
}

/**
 * @brief Setup the device to manufacturer's configuration.
 *
 * @param dps_ctx device context
 * @return int 0 on success
 * @return int -1 on failure
 */
static int
manufacturer_setup(plgd_dps_context_t *dps_ctx)
{
  // preserve name after factory reset
  oc_device_info_t *dev = oc_core_get_device_info(plgd_dps_get_device(dps_ctx));
  if (dev != NULL) {
    oc_free_string(&dev->name);
    oc_new_string(&dev->name, g_dps_device_name, strlen(g_dps_device_name));
  }
  plgd_dps_manager_callbacks_t callbacks = {
    .on_status_change = dps_status_handler,
    .on_status_change_data = NULL,
    .on_cloud_status_change = cloud_status_handler,
    .on_cloud_status_change_data = NULL,
  };
  plgd_dps_set_manager_callbacks(dps_ctx, callbacks);
  if (g_expiration_limit != -1) {
    plgd_dps_pki_set_expiring_limit(dps_ctx, (uint16_t)g_expiration_limit);
  }
  if (g_observer_max_retry != -1) {
    plgd_dps_set_cloud_observer_configuration(dps_ctx,
                                              (uint8_t)g_observer_max_retry, 1);
  }
  plgd_dps_set_skip_verify(dps_ctx, g_skip_ca_verification != 0);
  for (int i = 0; i < g_dps_endpoint_count; i++) {
    size_t dps_endpoint_len = strlen(g_dps_endpoint[i]);
    if (dps_endpoint_len > 0 &&
        !plgd_dps_add_endpoint_address(dps_ctx, g_dps_endpoint[i],
                                       dps_endpoint_len, NULL, 0)) {
      printf("ERROR: failed to add endpoint address\n");
      return -1;
    }
  }
  if (dps_add_certificates(dps_ctx, g_dps_cert_dir) != 0) {
    printf("ERROR: failed to add initial certificates on factory reset\n");
    return -1;
  }
  plgd_dps_force_reprovision(dps_ctx);
  return 0;
}

static int
try_start_dps(plgd_dps_context_t *ctx, plgd_dps_manager_callbacks_t callbacks)
{
  if (g_expiration_limit != -1) {
    plgd_dps_pki_set_expiring_limit(ctx, (uint16_t)g_expiration_limit);
  }
  if (g_observer_max_retry != -1) {
    plgd_dps_set_cloud_observer_configuration(ctx,
                                              (uint8_t)g_observer_max_retry, 1);
  }
  plgd_dps_set_skip_verify(ctx, g_skip_ca_verification != 0);
  plgd_dps_set_manager_callbacks(ctx, callbacks);
  return plgd_dps_manager_start(ctx);
}

static bool
dps_string_property_is_not_null(const oc_string_t *prop)
{
  return prop != NULL && oc_string(*prop) != NULL;
}

static void
try_start_cloud(const plgd_dps_context_t *ctx)
{
  const oc_cloud_context_t *cloud_ctx =
    oc_cloud_get_context(plgd_dps_get_device(ctx));
  if (cloud_ctx == NULL) {
    return;
  }

  if (oc_cloud_manager_is_started(cloud_ctx)) {
    // already running
    return;
  }

  // check if cloud is configured to start
  bool has_server = oc_cloud_get_server_uri(cloud_ctx) != NULL;
  bool has_auth = dps_string_property_is_not_null(
    oc_cloud_get_authorization_provider_name(cloud_ctx));
  bool has_access_token =
    dps_string_property_is_not_null(oc_cloud_get_access_token(cloud_ctx));
  bool has_refresh_token =
    dps_string_property_is_not_null(oc_cloud_get_refresh_token(cloud_ctx));
  bool has_token = has_access_token && has_refresh_token;
  if (!has_server || (!has_auth && !has_token)) {
    return;
  }
  if (!plgd_cloud_manager_start(ctx)) {
    printf("ERROR: Failed to start cloud manager\n");
    return;
  }
}

#ifdef PLGD_DPS_FAKETIME

static void
init_faketime(void)
{
  const char *faketime = getenv("FAKETIME");
  if (faketime == NULL) {
    DPSCS_DBG("faketime disabled\n");
    g_faketime.enabled = false;
    g_faketime.value[0] = '\0';
    g_faketime.format[0] = '\0';
    return;
  }
  g_faketime.enabled = true;
  strncpy(g_faketime.value, faketime, sizeof(g_faketime.value) - 1);
  DPSCS_DBG("faketime enabled time=%s\n", g_faketime.value);

  const char *fmt_env = getenv("FAKETIME_FMT");
  if (fmt_env == NULL) {
    fmt_env = "%Y-%m-%d %T";
  }
  strncpy(g_faketime.format, fmt_env, sizeof(g_faketime.format) - 1);

  const char *fake_monotonic_env = getenv("FAKETIME_DONT_FAKE_MONOTONIC");
  if (fake_monotonic_env == NULL || 0 != strcmp(fake_monotonic_env, "1")) {
    printf(
      "WARNING: monotonic time calculation calculated by faketime library\n");
  }
}

/** @brief Parsing of env("FAKETIME") string understandable to libfaketime */
static bool
parse_faketime(const char *faketime, const char *faketime_fmt,
               struct timeval *tval)
{
  const char *start = faketime;
  switch (faketime[0]) {
  case '%':
  case 'i':
  case 'x':
    // ignored options
    DPSCS_DBG("ignoring faketime=%s\n", faketime);
    return false;
  case '@':
    start = &faketime[1];
    break;
  default:
    break;
  }
  struct tm faketime_tm = { 0 };
  char *nstime_str = strptime(start, faketime_fmt, &faketime_tm);
  if (nstime_str == NULL) {
    return false;
  }

  time_t tv_sec = mktime(&faketime_tm);
  if (tv_sec == (time_t)-1) {
    printf("ERROR: failed to parse faketime: %s\n", strerror(errno));
    return false;
  }
  tval->tv_sec = tv_sec;
  tval->tv_usec = 0;

  if (nstime_str[0] == '.') {
    double nstime = atof(--nstime_str);
#define USECS_IN_SEC 1000000
    tval->tv_usec = (long)((nstime - floor(nstime)) * USECS_IN_SEC);
  }
  return true;
}

#ifdef PLGD_DPS_FAKETIME_SET_SYSTEM_TIME_ON_RESET
static void
set_faketime(void)
{
  if (!g_faketime.enabled) {
    return;
  }

  DPSCS_DBG("using faketime(%s) to set system time\n", g_faketime.value);
  struct timeval tval = { 0 };
  if (!parse_faketime(g_faketime.value, g_faketime.format, &tval)) {
    DPSCS_DBG("failed to parse faketime\n");
    return;
  }

  DPSCS_DBG("set_faketime: sec=%ld usec=%ld\n", (long)tval.tv_sec,
            (long)tval.tv_usec);
  if (settimeofday(&tval, NULL) != 0) {
    DPSCS_DBG("failed to set faketime\n");
  }
}
#endif /* PLGD_DPS_FAKETIME_SET_SYSTEM_TIME_ON_RESET */

#else /* !PLGD_DPS_FAKETIME */

static bool
is_root(void)
{
  return geteuid() == 0;
}

#endif /* PLGD_DPS_FAKETIME */

static void
factory_presets_cb(size_t device_id, void *data)
{
  (void)data;
  if (g_wait_for_reset != 0) {
    DPSCS_DBG("skip factory reset handling: waiting for reset signal\n");
    return;
  }

#if defined(PLGD_DPS_FAKETIME) &&                                              \
  defined(PLGD_DPS_FAKETIME_SET_SYSTEM_TIME_ON_RESET)
  set_faketime();
#endif /* PLGD_DPS_FAKETIME && PLGD_DPS_FAKETIME_SET_SYSTEM_TIME_ON_RESET */

  plgd_dps_context_t *dps_ctx = plgd_dps_get_context(device_id);
  if (dps_ctx == NULL) {
    DPSCS_DBG("skip factory reset handling: empty context\n");
    return;
  }

  if (plgd_dps_on_factory_reset(dps_ctx) != 0) {
    printf("ERROR: cannot handle factory reset\n");
    return;
  }
  if (manufacturer_setup(dps_ctx) != 0) {
    printf("ERROR: failed to configure device\n");
    return;
  }
  if (plgd_dps_manager_start(dps_ctx) != 0) {
    printf("ERROR: failed to start dps manager\n");
    return;
  }
}

static char *
dirname(const char *exec_path)
{
  char *path = realpath(exec_path, NULL);
  if (path == NULL) {
    return NULL;
  }
  char *dir = strrchr(path, '/');
  if (dir == NULL) {
    return NULL;
  }
  dir[0] = '\0';
  return path;
}

static bool
is_directory(const char *path)
{
  struct stat statbuf;
  if (stat(path, &statbuf) != 0) {
    return false;
  }
  return S_ISDIR(statbuf.st_mode) != 0;
}

typedef struct
{
  bool help;
  uint8_t retry_configuration[PLGD_DPS_MAX_RETRY_VALUES_SIZE];
  size_t retry_configuration_size;
  oc_log_level_t log_level;
  oc_log_level_t oc_log_level;
} parse_options_result_t;

static int
parse_string_to_int_array(char *str, uint8_t data[], size_t data_size)
{
  const char *token;
  const char *delim = ",";
  int size = 0;
  while ((token = strtok_r(str, delim, &str)) != NULL) {
    if ((size_t)size >= data_size || size > UINT8_MAX) {
      return -1;
    }

    char *eptr = NULL;
    errno = 0;
    long val = strtol(token, &eptr, 10); // NOLINT(readability-magic-numbers)
    if (errno != 0 || eptr == token || (val <= 0 || val > UINT8_MAX)) {
      return -1;
    }

    data[size] = (uint8_t)val;
    ++size;
  }
  return size;
}

static int
parse_retry_configuration(const char *cfg,
                          parse_options_result_t *parsed_options)
{
  if (cfg == NULL || parsed_options == NULL) {
    return -1;
  }

#ifdef OC_DYNAMIC_ALLOCATION
  char *str = strdup(cfg);
  if (str == NULL) {
    return -1;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  char str[64] = { 0 }; // NOLINT(readability-magic-numbers)
  size_t cfg_len = strlen(cfg);
  if (cfg_len >= sizeof(str)) {
    return -1;
  }
  memcpy(str, cfg, cfg_len);
  str[cfg_len] = 0;
#endif /* OC_DYNAMIC_ALLOCATION */

  uint8_t data[sizeof(parsed_options->retry_configuration) /
               sizeof(parsed_options->retry_configuration[0])] = { 0 };
  int size =
    parse_string_to_int_array(str, data, sizeof(data) / sizeof(data[0]));
  if (size == -1) {
#ifdef OC_DYNAMIC_ALLOCATION
    free(str);
#endif /* OC_DYNAMIC_ALLOCATION */
    return -1;
  }

  if (size > 0) {
    memcpy(parsed_options->retry_configuration, data, size * sizeof(data[0]));
  }
#ifdef OC_DYNAMIC_ALLOCATION
  free(str);
#endif /* OC_DYNAMIC_ALLOCATION */
  return size;
}

#define OPT_CREATE_CONF_RESOURCE "create-conf-resource"
#define OPT_EXPIRATION_LIMIT "expiration-limit"
#define OPT_HELP "help"
#define OPT_NO_VERIFY_CA "no-verify-ca"
#define OPT_CLOUD_OBSERVER_MAX_RETRY "cloud-observer-max-retry"
#define OPT_RETRY_CFG "retry-configuration"
#define OPT_WAIT_FOR_RESET "wait-for-reset"
#define OPT_DHCP_LEASE_FILE "dhcp-leases-file"
#define OPT_DHCP_ENABLED "dhcp-enabled"
#define OPT_SET_SYSTEM_TIME "set-system-time"
#define OPT_LOG_LEVEL "log-level"
#define OPT_OC_LOG_LEVEL "oc-log-level"
#define OPT_ENDPOINT "endpoint"

#define OPT_ARG_DEVICE_NAME "device-name"
#define OPT_ARG_ENDPOINT "endpoint"

#define OPT_OC_LOG_LEVEL_FLAG (256)

static void
printhelp(const char *exec_path)
{
  const char *binary_name = strrchr(exec_path, '/');
  binary_name = binary_name != NULL ? binary_name + 1 : exec_path;
  printf("./%s [%s] [%s]\n\n", binary_name, OPT_ARG_DEVICE_NAME,
         OPT_ARG_ENDPOINT);
  printf("OPTIONS:\n");
  printf("  -h | --%-26s print help\n", OPT_HELP);
  printf("  -c | --%-26s create DPS configuration resource\n",
         OPT_CREATE_CONF_RESOURCE);
  printf("  -e | --%-26s set certificate expiration limit (in seconds)\n",
         OPT_EXPIRATION_LIMIT);
  printf("  -l | --%-26s set runtime log-level of the DPS library (supported "
         "values: disabled, trace, debug, info, "
         "notice, warning, error)\n",
         OPT_LOG_LEVEL);
  printf("       --%-26s set runtime log-level of the IoTivity library "
         "(supported values: disabled, trace, debug, info, "
         "notice, warning, error)\n",
         OPT_OC_LOG_LEVEL);
  printf("  -n | --%-26s skip loading of the DPS certificate authority\n",
         OPT_NO_VERIFY_CA);
  printf("  -f | --%-26s path to the dhcp leases file (default: "
         "/var/lib/dhcp/dhclient.leases)\n",
         OPT_DHCP_LEASE_FILE);
  printf("  -x | --%-26s pull dhcp leases file every 5sec\n", OPT_DHCP_ENABLED);
  printf("  -o | --%-26s maximal number of retries by cloud observer before "
         "forcing reprovisioning\n",
         OPT_CLOUD_OBSERVER_MAX_RETRY);
  printf("  -r | --%-26s retry timeout configuration (array of non-zero values "
         "delimited by ',', "
         "maximum of %d values is accepted; example: 1,2,4,8,16)\n",
         OPT_RETRY_CFG " [cfg]", PLGD_DPS_MAX_RETRY_VALUES_SIZE);
  printf("  -s | --%-26s use plgd time to set system time (root required)\n",
         OPT_SET_SYSTEM_TIME);
  printf(
    "  -w | --%-26s don't start right away, but wait for SIGHUP signal\n\n",
    OPT_WAIT_FOR_RESET);
  printf("  -t | --%-26s additional endpoints for DPD (add multiple times for "
         "multiple endpoints)\n",
         OPT_ENDPOINT);
  printf("ARGUMENTS:\n");
  printf("  %-33s name of the device (optional, default: dps)\n",
         OPT_ARG_DEVICE_NAME);
  printf("  %-33s address of the endpoint (optional, default: "
         "coaps+tcp://127.0.0.1:20030)\n",
         OPT_ARG_ENDPOINT);
}

static int
make_storage(const char *storage_dir)
{
  if (oc_storage_config(storage_dir) != 0) {
    return false;
  }
  errno = 0;
  int ret = mkdir(storage_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
  if (ret != 0 && ((EEXIST != errno) || !is_directory(storage_dir))) {
    return false;
  }
  return true;
}

static void
shutdown(size_t device_id)
{
  plgd_dps_shutdown();
  oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(device_id);
  if (cloud_ctx != NULL && (oc_cloud_manager_stop(cloud_ctx) != 0)) {
    printf("ERROR: failed to stop cloud manager\n");
  }
  oc_main_shutdown();
}

#define PLGD_VENDOR_ENCAPSULATED_OPTION_MAX_SIZE (512)

typedef struct
{
  uint8_t value[PLGD_VENDOR_ENCAPSULATED_OPTION_MAX_SIZE];
  size_t size;
} dps_vendor_encapsulated_options_t;

static bool
dps_dhcp_parse_vendor_encapsulated_options(const char *value, size_t size,
                                           void *user_data)
{
  dps_vendor_encapsulated_options_t *veo =
    (dps_vendor_encapsulated_options_t *)user_data;
  ssize_t len = plgd_dps_hex_string_to_bytes(value, size, NULL, 0);
  if (len < 0) {
    printf("ERROR: invalid character in vendor encapsulated options\n");
    return true;
  }
  if (len > (ssize_t)(sizeof(veo->value))) {
    printf("ERROR: vendor encapsulated options too long\n");
    return true;
  }
  len =
    plgd_dps_hex_string_to_bytes(value, size, veo->value, sizeof(veo->value));
  if (len < (ssize_t)(sizeof(veo->value))) {
    veo->value[len] = '\0';
  }
  veo->size = (size_t)len;
  return true;
}

static oc_event_callback_retval_t
pull_vendor_encapsulated_options(void *data)
{
  DPSCS_DBG("pull vendor_encapsulated_options from dhcp leases file %s\n",
            g_dhcp_leases_file);
  if (g_dhcp_option_vendor_encapsulated_options == NULL) {
    return OC_EVENT_DONE;
  }
  if (g_dhcp_leases_file == NULL) {
    return OC_EVENT_DONE;
  }
  plgd_dps_context_t *dps_ctx = (plgd_dps_context_t *)data;
  dps_vendor_encapsulated_options_t veo = { 0 };
  if (plgd_dps_dhcp_get_option_leases_file(
        g_dhcp_leases_file, g_dhcp_option_vendor_encapsulated_options,
        dps_dhcp_parse_vendor_encapsulated_options, &veo)) {
    printf("ERROR: pull vendor_encapsulated_options: error during parsing\n");
    return OC_EVENT_CONTINUE;
  }
  plgd_dps_dhcp_set_values_t ret =
    plgd_dps_dhcp_set_values_from_vendor_encapsulated_options(
      dps_ctx, veo.value, veo.size);
  switch (ret) {
  case PLGD_DPS_DHCP_SET_VALUES_ERROR:
    printf("ERROR: pull vendor_encapsulated_options: error during update\n");
    break;
  case PLGD_DPS_DHCP_SET_VALUES_UPDATED:
    DPSCS_DBG("pull vendor_encapsulated_options: updated but force "
              "re-provision is not needed\n");
    break;
  case PLGD_DPS_DHCP_SET_VALUES_NEED_REPROVISION: {
    DPSCS_DBG("pull vendor_encapsulated_options: updated but needed force "
              "re-provision and restart dps manager\n");
    plgd_dps_force_reprovision(dps_ctx);
    if (plgd_dps_manager_restart(dps_ctx)) {
      printf("ERROR: pull vendor_encapsulated_options: failed to restart dps "
             "manager\n");
    }
  } break;
  case PLGD_DPS_DHCP_SET_VALUES_NOT_CHANGED:
    DPSCS_DBG("pull vendor_encapsulated_options: no change\n");
    break;
  default:
    printf("ERROR: pull vendor_encapsulated_options: unknown return value %d\n",
           ret);
    break;
  }
  return OC_EVENT_CONTINUE;
}

#define PLGD_VENDOR_ENCAPSULATED_OPTIONS_PULLING_INTERVAL (5)

static oc_event_callback_retval_t
init_pull_vendor_encapsulated_options(void *data)
{
  pull_vendor_encapsulated_options(data);
  plgd_dps_context_t *dps_ctx = (plgd_dps_context_t *)data;
  oc_set_delayed_callback(dps_ctx, pull_vendor_encapsulated_options,
                          PLGD_VENDOR_ENCAPSULATED_OPTIONS_PULLING_INTERVAL);
  return OC_EVENT_DONE;
}

static bool
parse_positive_integer_value(const char *str, long *value)
{
  char *eptr = NULL;
  errno = 0;
  long val = strtol(str, &eptr, 10); // NOLINT(readability-magic-numbers)
  if (errno != 0 || eptr == str || (*eptr) != '\0' || val < 0) {
    return false;
  }
  *value = val;
  return true;
}

static bool
parse_oc_log_level(const char *log_level, oc_log_level_t *level)
{
  const char *levels_str[] = {
    "trace", "debug", "info", "notice", "warning", "error", "disabled",
  };
  oc_log_level_t levels[] = {
    OC_LOG_LEVEL_TRACE,    OC_LOG_LEVEL_DEBUG,   OC_LOG_LEVEL_INFO,
    OC_LOG_LEVEL_NOTICE,   OC_LOG_LEVEL_WARNING, OC_LOG_LEVEL_ERROR,
    OC_LOG_LEVEL_DISABLED,
  };

  for (size_t i = 0; i < sizeof(levels_str) / sizeof(levels_str[0]); ++i) {
    if (strcmp(log_level, levels_str[i]) == 0) {
      *level = levels[i];
      return true;
    }
  }
  return false;
}

static bool
add_endpoint(const char *endpoint)
{
#if OC_DYNAMIC_ALLOCATION
  char **new_dps_endpoint_buffer = (char **)realloc(
    g_dps_endpoint, (g_dps_endpoint_count + 1) * sizeof(char *));
  if (new_dps_endpoint_buffer == NULL) {
    printf("ERROR: failed to allocate memory for list of endpoints\n");
    return false;
  }
  g_dps_endpoint = new_dps_endpoint_buffer;
  g_dps_endpoint[g_dps_endpoint_count] = strdup(endpoint);
  if (g_dps_endpoint[g_dps_endpoint_count] == NULL) {
    printf("ERROR: failed to allocate memory for endpoint\n");
    return false;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  if (g_dps_endpoint_count == 2) {
    printf("ERROR: cannot add more than 2 endpoints static allocation\n");
    return false;
  }
  size_t endpoint_len = strlen(endpoint);
  if (sizeof(g_dps_endpoint[0]) <= endpoint_len) {
    printf("ERROR: endpoint address too long\n");
    return false;
  }
  memcpy(g_dps_endpoint, endpoint, endpoint_len);
  g_dps_endpoint[g_dps_endpoint_count][endpoint_len] = '\0';
#endif /* OC_DYNAMIC_ALLOCATION */
  ++g_dps_endpoint_count;
  return true;
}

static bool
parse_option(int opt, char *argv[], parse_options_result_t *parsed_options)
{
  switch (opt) {
  case 'c':
    g_create_configuration_resource = 1;
    return true;
  case 'e': {
    long expiration_limit = 0;
    if (!parse_positive_integer_value(optarg, &expiration_limit) ||
        expiration_limit > UINT16_MAX) {
      printf("invalid expiration limit argument value(%s)\n", optarg);
      return false;
    }
    g_expiration_limit = (int)expiration_limit;
    return true;
  }
  case 'l':
    if (!parse_oc_log_level(optarg, &parsed_options->log_level)) {
      printf("invalid log-level (%s)\n", optarg);
      return false;
    }
    return true;
  case 'n':
    g_skip_ca_verification = 1;
    return true;
  case 'o': {
    long observer_max_retry = 0;
    if (!parse_positive_integer_value(optarg, &observer_max_retry) ||
        observer_max_retry > UINT8_MAX) {
      printf("invalid observer max retry count argument value(%s)\n", optarg);
      return false;
    }
    g_observer_max_retry = (int16_t)observer_max_retry;
    return true;
  }
  case 'r': {
    int size = parse_retry_configuration(optarg, parsed_options);
    if (size < 1) {
      printf("invalid retry configuration(%s)\n", optarg);
      return false;
    }
    parsed_options->retry_configuration_size = (size_t)size;
    return true;
  }
  case 's':
#ifndef PLGD_DPS_FAKETIME // intercepted settimeofday by faketime doesn't need
                          // root
    if (!is_root()) {
      printf("root required for settimeofday: see man settimeofday\n");
      return false;
    }
#endif /* !PLGD_DPS_FAKETIME */
    g_set_system_time = true;
    return true;
  case 'w':
    g_wait_for_reset = 1;
    return true;
  case 'f':
    g_dhcp_leases_file = optarg;
    return true;
  case 'x':
    g_dhcp_enabled = true;
    return true;
  case OPT_OC_LOG_LEVEL_FLAG:
    if (!parse_oc_log_level(optarg, &parsed_options->oc_log_level)) {
      printf("invalid oc-log-level (%s)\n", optarg);
      return false;
    }
    return true;
  case 't':
    return add_endpoint(optarg);
  default:
    break;
  }

  printf("invalid option(%s)\n", argv[optind]);
  return false;
}

static bool
parse_options(int argc, char *argv[], parse_options_result_t *parsed_options)
{
  static struct option long_options[] = {
    { OPT_CREATE_CONF_RESOURCE, no_argument, &g_create_configuration_resource,
      'c' },
    { OPT_EXPIRATION_LIMIT, required_argument, NULL, 'e' },
    { OPT_HELP, no_argument, NULL, 'h' },
    { OPT_LOG_LEVEL, required_argument, NULL, 'l' },
    { OPT_OC_LOG_LEVEL, required_argument, NULL, OPT_OC_LOG_LEVEL_FLAG },
    { OPT_NO_VERIFY_CA, no_argument, &g_skip_ca_verification, 'n' },
    { OPT_CLOUD_OBSERVER_MAX_RETRY, required_argument, NULL, 'o' },
    { OPT_RETRY_CFG, required_argument, NULL, 'r' },
    { OPT_SET_SYSTEM_TIME, no_argument, NULL, 's' },
    { OPT_WAIT_FOR_RESET, no_argument, &g_wait_for_reset, 'w' },
    { OPT_DHCP_LEASE_FILE, required_argument, NULL, 'f' },
    { OPT_DHCP_ENABLED, no_argument, NULL, 'x' },
    { OPT_ENDPOINT, required_argument, NULL, 't' },
    { NULL, 0, NULL, 0 },
  };
  while (true) {
    int option_index = 0;
    int opt = getopt_long(argc, argv, "ce:f:hl:nr:o:sxwt:", long_options,
                          &option_index);
    if (opt == -1) {
      break;
    }
    switch (opt) {
    case 0:
      if (long_options[option_index].flag != 0) {
        break;
      }
      printf("invalid option(%s)\n", argv[optind]);
      return false;
    case 'h':
      printhelp(argv[0]);
      parsed_options->help = true;
      return true;
    default:
      if (!parse_option(opt, argv, parsed_options)) {
        return false;
      }
      break;
    }
  }
  argc -= (optind - 1);
  for (int i = 1; i < argc; ++i, ++optind) {
    argv[i] = argv[optind];
  }

  if (argc == 1) {
    printf("./dps_cloud_server <device-name-without-spaces> <endpoint>\n");
    printf("Default parameters:\n"
           "\tdevice_name: %s\n",
           g_dps_device_name);
  }
  if (argc > 1) {
    g_dps_device_name = argv[1];
    printf("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
#ifdef OC_DYNAMIC_ALLOCATION
    free(g_dps_endpoint[0]);
    g_dps_endpoint[0] = strdup(argv[2]);
    if (g_dps_endpoint[0] == NULL) {
      printf("ERROR: failed to allocate memory for endpoint\n");
      return false;
    }
#else  /* !OC_DYNAMIC_ALLOCATION */
    size_t endpoint_len = strlen(argv[2]);
    if (sizeof(g_dps_endpoint[0]) <= endpoint_len) {
      printf("ERROR: endpoint address too long\n");
      return false;
    }
    memcpy(g_dps_endpoint[0], argv[2], endpoint_len);
    g_dps_endpoint[0][endpoint_len] = '\0';
#endif /* OC_DYNAMIC_ALLOCATION  */
  }
  printf("Endpoints:\n");
  for (int i = 0; i < g_dps_endpoint_count; ++i) {
    printf("\t%s\n", g_dps_endpoint[i]);
  }

  char *dir = dirname(argv[0]);
  if (dir == NULL) {
    printf("ERROR: failed to resolve parent directory\n");
    return false;
  }
  dps_concat_paths(g_dps_cert_dir, sizeof(g_dps_cert_dir), dir, "/pki_certs");
  free(dir);

#ifdef PLGD_DPS_FAKETIME
  init_faketime();
#endif /* PLGD_DPS_FAKETIME */

  return true;
}

int
main(int argc, char *argv[])
{
  parse_options_result_t parsed_options = {
    .help = false,
    .retry_configuration = { 0 },
    .retry_configuration_size = 0,
    .log_level = OC_LOG_LEVEL_INFO,
    .oc_log_level = OC_LOG_LEVEL_INFO,
  };
  if (!add_endpoint(
        "coaps+tcp://127.0.0.1:20030")) { // NOLINT(readability-magic-numbers)
    return -1;
  }
  if (!parse_options(argc, argv, &parsed_options)) {
    return -1;
  }
  if (parsed_options.help) {
    return 0;
  }

  oc_log_set_level(parsed_options.oc_log_level);
  plgd_dps_log_set_level(parsed_options.log_level);

  if (!init()) {
    return -1;
  }

#define DPS_STORAGE "./dps_cloud_server_creds/"
  if (!make_storage(DPS_STORAGE)) {
    printf("ERROR: failed to create storage at path %s", DPS_STORAGE);
    deinit();
    return -1;
  }
  oc_set_factory_presets_cb(factory_presets_cb, NULL);

#ifdef OC_DYNAMIC_ALLOCATION
  const size_t max_app_data_size = (size_t)(8 * 1024);
  oc_set_max_app_data_size(max_app_data_size);
  const size_t min_app_data_size = 512;
  oc_set_min_app_data_size(min_app_data_size);
#endif /* OC_DYNAMIC_ALLOCATION */
#if defined(OC_SECURITY) && defined(OC_PKI)
  oc_sec_certs_md_set_algorithms_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA384));
  oc_sec_certs_ecp_set_group_ids_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1) |
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP384R1));
#endif /* OC_SECURITY && OC_PKI */
  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .register_resources = register_resources,
  };
  if (oc_main_init(&handler) < 0) {
    deinit();
    return -1;
  }
  g_initialized = true;
  display_device_uuid(g_device_id);
  plgd_dps_context_t *dps_ctx = plgd_dps_get_context(g_device_id);
  if (dps_ctx == NULL) {
    printf("ERROR: cannot start dps manager: empty context\n");
    shutdown(g_device_id);
    deinit();
    return -1;
  }

  if (g_dhcp_enabled) {
    oc_set_delayed_callback(dps_ctx, init_pull_vendor_encapsulated_options, 0);
  }

  if (parsed_options.retry_configuration_size > 0 &&
      !plgd_dps_set_retry_configuration(
        dps_ctx, parsed_options.retry_configuration,
        parsed_options.retry_configuration_size)) {
    printf("ERROR: cannot start dps manager: invalid retry configuration\n");
    shutdown(g_device_id);
    deinit();
    return -1;
  }

  if (g_wait_for_reset != 0) {
    run();
    shutdown(g_device_id);
    deinit();
    return 0;
  }

  if (!plgd_dps_manager_is_started(dps_ctx)) {
    plgd_dps_manager_callbacks_t callbacks = {
      .on_status_change = dps_status_handler,
      .on_status_change_data = NULL,
      .on_cloud_status_change = cloud_status_handler,
      .on_cloud_status_change_data = NULL,
    };
    if (try_start_dps(dps_ctx, callbacks) != 0) {
      printf("ERROR: failed to start dps manager\n");
      shutdown(g_device_id);
      deinit();
      return -1;
    }

    oc_cloud_context_t *cloud_ctx = oc_cloud_get_context(g_device_id);
    if (cloud_ctx != NULL) {
      // setup callbacks in case cloud gets configured later
      oc_cloud_set_on_status_change(cloud_ctx,
                                    (oc_cloud_on_status_change_t){
                                      callbacks.on_cloud_status_change,
                                      callbacks.on_cloud_status_change_data,
                                    });
    }
    if (!plgd_dps_manager_is_started(dps_ctx) &&
        plgd_dps_endpoint_is_empty(dps_ctx)) {
      try_start_cloud(dps_ctx);
    }
  }

  run();
  shutdown(g_device_id);
  deinit();
  return 0;
}

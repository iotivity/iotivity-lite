/****************************************************************************
 *
 * Copyright 2021 ETRI All Rights Reserved.
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
 * Created on: Aug 2, 2022,
 *        Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

#include "oc_api.h"
#include "oc_log.h"
#include "oc_push.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"

#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";
static const char *resource_rt = "oic.r.custom.light";
static const char *device_rt = "oic.d.push";
static const char *device_name = "push-configurator";
static const char *manufacturer = "ETRI";
static const char *recv_path = "/pushed-resource/from-complex-light";

static pthread_mutex_t app_mutex;
static pthread_mutex_t mutex;
static pthread_cond_t cv;

static OC_ATOMIC_INT8_T quit = 0;

#define MAX_URI_LENGTH (30)
static char rsc_uri[MAX_URI_LENGTH];
static char push_rsc_uri[MAX_URI_LENGTH];
static bool resource_found = false;

#define OC_IPV6_ADDRSTRLEN (59)
static char address[OC_IPV6_ADDRSTRLEN + 1];
static oc_endpoint_t originserver_ep;
static oc_endpoint_t targetserver_ep;

#define PING_RETRY_COUNT (4)

typedef void (*custom_func_t)(const oc_endpoint_t *, const char *,
                              oc_resource_properties_t);

typedef struct
{
  custom_func_t func;
} custom_func_s;

static void
push_arrived(oc_pushd_resource_rep_t *push_payload)
{
  OC_PRINTF("new push arrives (path: %s, rt: ",
            oc_string(push_payload->resource->uri));
  for (size_t i = 0;
       i < oc_string_array_get_allocated_size(push_payload->resource->types);
       i++) {
    OC_PRINTF("%s ",
              oc_string_array_get_item(push_payload->resource->types, i));
  }
  OC_PRINTF(")\n");

  oc_print_pushd_resource(push_payload->rep);
}

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);

  /* set push callback function which will be called when new PUSH arrives */
  oc_set_on_push_arrived(push_arrived);

  return ret;
}

static bool
is_resource_found(void)
{
  if (!resource_found) {
    OC_PRINTF("Please discovery resource first!\n");
    return false;
  }

  return true;
}

static void
cb_create_notification_selector_response(oc_client_response_t *data)
{
  oc_rep_t *rep = data->payload;

  if (!rep) {
    OC_PRINTF("\n   => return status: [ %s ] \n\n",
              oc_status_to_str(data->code));
    return;
  }

  OC_PRINTF("\n   => return status: [ %s ] \n\n", oc_status_to_str(data->code));
  oc_print_pushd_resource(data->payload);

  return;
}

static void
create_notification_selector(void)
{
  if (!is_resource_found())
    return;

  if (!oc_init_post(PUSHCONFIG_RESOURCE_PATH, &originserver_ep,
                    "if=oic.if.create",
                    &cb_create_notification_selector_response, LOW_QOS, NULL)) {
    OC_PRINTF("could not initiate oc_init_post()\n");
    return;
  }
  oc_rep_begin_root_object();

  oc_rep_open_array(root, rt);
  oc_rep_add_text_string(rt, "oic.r.notificationselector");
  oc_rep_add_text_string(rt, "oic.r.pushproxy");
  oc_rep_close_array(root, rt);

  oc_rep_open_array(root, if);
  oc_rep_add_text_string(if, "oic.if.rw");
  oc_rep_add_text_string(if, "oic.if.baseline");
  oc_rep_close_array(root, if);

  oc_rep_open_object(root, p);
  oc_rep_set_uint(p, bm, 3);
  oc_rep_close_object(root, p);

  /* ----- begin of "rep" ----- */
  oc_rep_open_object(root, rep);

  /* phref (optinal) */
  oc_rep_set_text_string(rep, phref, push_rsc_uri);

  /* prt (optinal) */
  oc_rep_open_array(rep, prt);
  oc_rep_add_text_string(prt, resource_rt);
  oc_rep_close_array(rep, prt);

  /* pushtarget */
  oc_string_t pushtarget_ep_str;
  if (oc_endpoint_to_string(&targetserver_ep, &pushtarget_ep_str) != 0) {
    OC_PRINTF("error converting target server endpoint to string\n");
    return;
  }
  OC_PRINTF("target server's ep: %s \n", oc_string(pushtarget_ep_str));
  oc_string_t pushtarget_str;
  oc_concat_strings(&pushtarget_str, oc_string(pushtarget_ep_str), recv_path);
  OC_PRINTF("targetpath: %s \n", oc_string(pushtarget_str));
  oc_rep_set_text_string(rep, pushtarget, oc_string(pushtarget_str));
  oc_free_string(&pushtarget_str);
  oc_free_string(&pushtarget_ep_str);

  /* pushqif */
  oc_rep_set_text_string(rep, pushqif, "oic.if.rw");

  /* sourcert */
  oc_rep_open_array(rep, sourcert);
  oc_rep_add_text_string(sourcert, "oic.r.pushpayload");
  oc_rep_close_array(rep, sourcert);

  /* state */
  /* ----- end of "rep" ----- */
  oc_rep_close_object(root, rep);

  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_PRINTF("oc_do_post() failed\n");
  }
}

static void
cb_update_push_receiver_response(oc_client_response_t *data)
{
  (void)data;

  oc_rep_t *rep = data->payload;

  if (!rep) {
    OC_PRINTF("\n   => return status: [ %s ] \n\n",
              oc_status_to_str(data->code));
    return;
  }

  OC_PRINTF("\n   => return status: [ %s ] \n\n", oc_status_to_str(data->code));
  oc_print_pushd_resource(data->payload);

  return;
}

static void
update_push_receiver(void)
{
  if (!is_resource_found())
    return;

  char query[2048];
  sprintf(query, "receiveruri=%s&if=oic.if.rw", recv_path);

  if (oc_init_post(PUSHRECEIVERS_RESOURCE_PATH, &targetserver_ep, query,
                   &cb_update_push_receiver_response, LOW_QOS, NULL)) {
    /* create a "receiver" object in pushreceiver Resource */
    oc_rep_begin_root_object();
    oc_rep_set_text_string(root, receiveruri, recv_path);
    oc_rep_open_array(root, rts);
    oc_rep_add_text_string(rts, resource_rt);
    oc_rep_close_array(root, rts);
    oc_rep_end_root_object();
  } else {
    OC_PRINTF("could not initiate oc_init_post()\n");
    return;
  }

  if (!oc_do_post()) {
    OC_PRINTF("oc_do_post() failed\n");
  }
}

static void
cb_retrieve_push_origin_rsc_response(oc_client_response_t *data)
{
  OC_PRINTF("RETRIEVE \"%s\":\n", resource_rt);
  oc_print_pushd_resource(data->payload);
}

static void
retrieve_push_origin_rsc(void)
{
  if (!is_resource_found())
    return;

  oc_do_get(push_rsc_uri, &originserver_ep, NULL,
            cb_retrieve_push_origin_rsc_response, LOW_QOS, NULL);
}

static oc_discovery_flags_t
cb_discovery(const char *anchor, const char *uri, oc_string_array_t types,
             oc_interface_mask_t iface_mask, const oc_endpoint_t *endpoint,
             oc_resource_properties_t bm, void *user_data)
{
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;

  (void)anchor;
  (void)iface_mask;
  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == strlen(resource_rt) &&
        strncmp(t, resource_rt, strlen(t)) == 0) {
      strncpy(rsc_uri, uri, uri_len);
      rsc_uri[uri_len] = '\0';

      OC_PRINTF("\nResource %s hosted at endpoints:\n", rsc_uri);

      if (user_data) {
        custom_func_s *custom = (custom_func_s *)user_data;
        custom->func(endpoint, rsc_uri, bm);
      } else {
        OC_PRINTF("custom function is not set!");
        goto exit;
      }
    }
  }

exit:
  return ret;
}

static void
cb_retrieve_pushconf_rsc_response(oc_client_response_t *data)
{
  OC_PRINTF("RETRIEVE \"%s\":\n", PUSHCONFIG_RESOURCE_TYPE);
  oc_print_pushd_resource(data->payload);
}

static void
retrieve_pushconf_rsc(void)
{
  if (!is_resource_found())
    return;
  oc_do_get(PUSHCONFIG_RESOURCE_PATH, &originserver_ep, "if=oic.if.b",
            cb_retrieve_pushconf_rsc_response, LOW_QOS, NULL);
}

static void
cb_retrieve_pushreceiver_rsc_response(oc_client_response_t *data)
{
  OC_PRINTF("RETRIEVE \"%s\":\n", PUSHRECEIVERS_RESOURCE_TYPE);
  oc_print_pushd_resource(data->payload);
}

static void
retrieve_pushreceiver_rsc(void)
{
  oc_do_get(PUSHRECEIVERS_RESOURCE_PATH, &targetserver_ep, "if=oic.if.rw",
            cb_retrieve_pushreceiver_rsc_response, LOW_QOS, NULL);
}

static void
find_same_endpoint(const oc_endpoint_t *endpoint, const char *uri,
                   oc_resource_properties_t bm)
{
  const oc_endpoint_t *ep = endpoint;
  while (ep != NULL) {
    OC_PRINTF(" |__");
    OC_PRINTipaddr(*ep);
    OC_PRINTF("\n");

    if (oc_endpoint_compare(&originserver_ep, ep) == 0) {
      OC_PRINTF("     ===> matched originserver ep is found!\n");
      if (bm & OC_PUSHABLE) {
        OC_PRINTF("     ===> Resource %s is PUSHABLE Resource!\n", uri);
        strcpy(push_rsc_uri, uri);
        resource_found = true;
      }
    }

    ep = ep->next;
  }
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

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event_mt;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event_mt = oc_main_poll_v1();
    pthread_mutex_unlock(&app_mutex);
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

  pthread_exit(0);
}

static void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  OC_PRINTF("=====================================\n");
  OC_PRINTF("1. Discovery\n");
  OC_PRINTF(
    "2. Create new PUSH notification selector on origin server, and add "
    "new Receiver configuration object to target server\n");
  OC_PRINTF("3. Retrieve PUSH origin Resource of origin-server\n");
  OC_PRINTF("4. Retrieve PUSH configuration Resource of origin server\n");
  OC_PRINTF("5. Retrieve PUSH receivers Resource of target server\n");
  OC_PRINTF("0. Quit\n");
  OC_PRINTF("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

static bool
init(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  int err = pthread_mutex_init(&app_mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    return false;
  }
  err = pthread_mutex_init(&mutex, NULL);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_mutex_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  pthread_condattr_t attr;
  err = pthread_condattr_init(&attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_init failed (error=%d)!\n", err);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  err = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_condattr_setclock failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
    return false;
  }
  err = pthread_cond_init(&cv, &attr);
  if (err != 0) {
    OC_PRINTF("ERROR: pthread_cond_init failed (error=%d)!\n", err);
    pthread_condattr_destroy(&attr);
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);
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
  pthread_mutex_destroy(&app_mutex);
}

int
main(void)
{
  if (!init()) {
    return -1;
  }

  /* get originserver ep */
  OC_PRINTF("set originserver address(ex. coap+tcp://xxx.xxx.xxx.xxx:yyyy): ");
  if (scanf("%59s", address) > 0) {
    OC_PRINTF("address: %s\n", address);
  } else {
    OC_PRINTF("error reading remote address\n");
    deinit();
    return -1;
  }

  oc_string_t address_str;
  oc_new_string(&address_str, address, strlen(address));

  if (oc_string_to_endpoint(&address_str, &originserver_ep, NULL) < 0) {
    OC_PRINTF("error parsing originserver endpoint address\n");
    deinit();
    return -1;
  }
  originserver_ep.version = OCF_VER_1_0_0;
  oc_free_string(&address_str);

  /* get targetserver ep */
  OC_PRINTF("set targetserver address(ex. coap+tcp://xxx.xxx.xxx.xxx:yyyy): ");
  if (scanf("%59s", address) > 0) {
    OC_PRINTF("address: %s\n", address);
  } else {
    OC_PRINTF("error reading remote address\n");
    deinit();
    return -1;
  }

  oc_new_string(&address_str, address, strlen(address));

  if (oc_string_to_endpoint(&address_str, &targetserver_ep, NULL) < 0) {
    OC_PRINTF("error parsing originserver endpoint address\n");
    deinit();
    return -1;
  }
  originserver_ep.version = OCF_VER_1_0_0;
  oc_free_string(&address_str);

  static const oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
  };

#ifdef OC_STORAGE
  oc_storage_config("./push_targetserver_multithread_linux_creds");
#endif /* OC_STORAGE */

  int ret = oc_main_init(&handler);
  if (ret < 0) {
    OC_PRINTF("oc_main_init failed!(%d)\n", ret);
    deinit();
    return ret;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    OC_PRINTF("Failed to create main thread\n");
    ret = -1;
    goto exit;
  }

  custom_func_s same_func = { .func = find_same_endpoint };

  int key;
  while (OC_ATOMIC_LOAD8(quit) != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      OC_PRINTF("scanf failed!!!!\n");
      handle_signal(0);
      break;
    }

    pthread_mutex_lock(&app_mutex);
    switch (key) {
    case 1:
      /* discover all Resources whose rt is `resource_rt`, and save uri of
       * pushable one */
      resource_found = false;
      oc_do_ip_discovery(resource_rt, cb_discovery, &same_func);
      break;

    case 2:
      /* create PUSH notification selector for PUSH origin Resource */
      create_notification_selector();
      /* update PUSH receiver Resource for PUSH origin Resource */
      update_push_receiver();
      break;
    case 3:
      /* retrieve PUSH origin Resource */
      retrieve_push_origin_rsc();
      break;
    case 4:
      /* retrieve PUSH configuration Resource */
      retrieve_pushconf_rsc();
      break;
    case 5:
      /* retrieve PUSH receiver Resource */
      retrieve_pushreceiver_rsc();
      break;
    case 0:
      handle_signal(0);
      break;
    default:
      OC_PRINTF("unsupported command.\n");
      break;
    }
    pthread_mutex_unlock(&app_mutex);
  }

  pthread_join(thread, NULL);
  OC_PRINTF("pthread_join finish!\n");

exit:
  oc_main_shutdown();
  deinit();
  return ret;
}

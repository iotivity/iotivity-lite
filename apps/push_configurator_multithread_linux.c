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
#include "port/oc_clock.h"
#include "port/oc_log_internal.h" // TODO: need to be removed
#include "oc_push.h"
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

pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

pthread_mutex_t app_mutex;
int quit = 0;

#define MAX_URI_LENGTH (30)
static char rsc_uri[MAX_URI_LENGTH];
static char push_rsc_uri[MAX_URI_LENGTH];
static bool resource_found = false;

#define OC_IPV6_ADDRSTRLEN (59)
static char address[OC_IPV6_ADDRSTRLEN + 1];
static oc_endpoint_t originserver_ep;
static oc_endpoint_t targetserver_ep;

#define PING_RETRY_COUNT (4)

typedef void (*custom_func_t)(oc_endpoint_t *, char *,
                              oc_resource_properties_t);

typedef struct
{
  custom_func_t func;
} custom_func_s;

static void
push_arrived(oc_pushd_resource_rep_t *push_payload)
{
  PRINT("new push arrives (path: %s, rt: ",
        oc_string(push_payload->resource->uri));
  for (size_t i = 0;
       i < oc_string_array_get_allocated_size(push_payload->resource->types);
       i++) {
    PRINT("%s ", oc_string_array_get_item(push_payload->resource->types, i));
  }
  PRINT(")\n");

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
    printf("Please discovery resource first!\n");
    return false;
  }

  return true;
}

static void
cb_create_notification_selector_response(oc_client_response_t *data)
{
  oc_rep_t *rep = data->payload;

  if (!rep) {
    printf("\n   => return status: [ %s ] \n\n", oc_status_to_str(data->code));
    return;
  }

  printf("\n   => return status: [ %s ] \n\n", oc_status_to_str(data->code));
  oc_print_pushd_resource(data->payload);

  return;
}

static void
create_notification_selector(void)
{
  if (!is_resource_found())
    return;

  if (oc_init_post(PUSHCONFIG_RESOURCE_PATH, &originserver_ep,
                   "if=oic.if.create",
                   &cb_create_notification_selector_response, LOW_QOS, NULL)) {
    oc_string_t pushtarget_ep_str;
    oc_string_t pushtarget_str;

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
    oc_endpoint_to_string(&targetserver_ep, &pushtarget_ep_str);
    printf("target server's ep: %s \n", oc_string(pushtarget_ep_str));
    oc_concat_strings(&pushtarget_str, oc_string(pushtarget_ep_str), recv_path);
    printf("targetpath: %s \n", oc_string(pushtarget_str));
    oc_rep_set_text_string(rep, pushtarget, oc_string(pushtarget_str));

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

    oc_free_string(&pushtarget_ep_str);
    oc_free_string(&pushtarget_str);
  } else {
    printf("could not initiate oc_init_post()\n");
    return;
  }

  if (!oc_do_post()) {
    printf("oc_do_post() failed\n");
  }
}

static void
cb_update_push_receiver_response(oc_client_response_t *data)
{
  (void)data;

  oc_rep_t *rep = data->payload;

  if (!rep) {
    printf("\n   => return status: [ %s ] \n\n", oc_status_to_str(data->code));
    return;
  }

  printf("\n   => return status: [ %s ] \n\n", oc_status_to_str(data->code));
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
    printf("could not initiate oc_init_post()\n");
    return;
  }

  if (!oc_do_post()) {
    printf("oc_do_post() failed\n");
  }
}

static void
cb_retrieve_push_origin_rsc_response(oc_client_response_t *data)
{
  printf("RETRIEVE \"%s\":\n", resource_rt);
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
             oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
             oc_resource_properties_t bm, void *user_data)
{
  oc_discovery_flags_t ret = OC_CONTINUE_DISCOVERY;

  (void)anchor;
  (void)iface_mask;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == strlen(resource_rt) &&
        strncmp(t, resource_rt, strlen(t)) == 0) {
      strncpy(rsc_uri, uri, uri_len);
      rsc_uri[uri_len] = '\0';

      printf("\nResource %s hosted at endpoints:\n", rsc_uri);

      if (user_data) {
        custom_func_s *custom = (custom_func_s *)user_data;
        custom->func(endpoint, rsc_uri, bm);
      } else {
        printf("custom function is not set!");
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
  printf("RETRIEVE \"%s\":\n", PUSHCONFIG_RESOURCE_TYPE);
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
  printf("RETRIEVE \"%s\":\n", PUSHRECEIVERS_RESOURCE_TYPE);
  oc_print_pushd_resource(data->payload);
}

static void
retrieve_pushreceiver_rsc(void)
{
  oc_do_get(PUSHRECEIVERS_RESOURCE_PATH, &targetserver_ep, "if=oic.if.rw",
            cb_retrieve_pushreceiver_rsc_response, LOW_QOS, NULL);
}

static void
find_same_endpoint(oc_endpoint_t *endpoint, char *uri,
                   oc_resource_properties_t bm)
{
  oc_endpoint_t *ep = endpoint;
  while (ep != NULL) {
    printf(" |__");
    PRINTipaddr(*ep);
    printf("\n");

    if (oc_endpoint_compare(&originserver_ep, ep) == 0) {
      printf("     ===> matched originserver ep is found!\n");
      if (bm & OC_PUSHABLE) {
        printf("     ===> Resource %s is PUSHABLE Resource!\n", uri);
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
  signal_event_loop();
  quit = 1;
}

static void *
process_func(void *data)
{
  (void)data;
  oc_clock_time_t next_event;

  while (quit != 1) {
    pthread_mutex_lock(&app_mutex);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_mutex);
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  pthread_exit(0);
}

static void
print_menu(void)
{
  pthread_mutex_lock(&app_mutex);
  printf("=====================================\n");
  printf("1. Discovery\n");
  printf("2. Create new PUSH notification selector on origin server, and add "
         "new Receiver configuration object to target server\n");
  printf("3. Retrieve PUSH origin Resource of origin-server\n");
  printf("4. Retrieve PUSH configuration Resource of origin server\n");
  printf("5. Retrieve PUSH receivers Resource of target server\n");
  printf("0. Quit\n");
  printf("=====================================\n");
  pthread_mutex_unlock(&app_mutex);
}

int
main(void)
{
  int init = 0;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  oc_string_t address_str;

  /* get originserver ep */
  printf("set originserver address(ex. coap+tcp://xxx.xxx.xxx.xxx:yyyy): ");
  if (scanf("%59s", address) > 0) {
    printf("address: %s\n", address);
  } else {
    printf("error reading remote address\n");
    return -1;
  }

  oc_new_string(&address_str, address, strlen(address));

  if (oc_string_to_endpoint(&address_str, &originserver_ep, NULL) < 0) {
    printf("error parsing originserver endpoint address\n");
    return -1;
  }
  originserver_ep.version = OCF_VER_1_0_0;
  oc_free_string(&address_str);

  /* get targetserver ep */
  printf("set targetserver address(ex. coap+tcp://xxx.xxx.xxx.xxx:yyyy): ");
  if (scanf("%59s", address) > 0) {
    printf("address: %s\n", address);
  } else {
    printf("error reading remote address\n");
    return -1;
  }

  oc_new_string(&address_str, address, strlen(address));

  if (oc_string_to_endpoint(&address_str, &targetserver_ep, NULL) < 0) {
    printf("error parsing originserver endpoint address\n");
    return -1;
  }
  originserver_ep.version = OCF_VER_1_0_0;
  oc_free_string(&address_str);

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop =
                                          signal_event_loop };

#ifdef OC_STORAGE
  oc_storage_config("./push_targetserver_multithread_linux_creds");
#endif /* OC_STORAGE */

  if (pthread_mutex_init(&mutex, NULL)) {
    printf("pthread_mutex_init failed!\n");
    return -1;
  }

  if (pthread_mutex_init(&app_mutex, NULL)) {
    printf("pthread_mutex_init failed!\n");
    pthread_mutex_destroy(&mutex);
    return -1;
  }

  init = oc_main_init(&handler);
  if (init < 0) {
    printf("oc_main_init failed!(%d)\n", init);
    goto exit;
  }

  pthread_t thread;
  if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
    printf("Failed to create main thread\n");
    init = -1;
    goto exit;
  }

  custom_func_s same_func = { .func = find_same_endpoint };

  int key;
  while (quit != 1) {
    print_menu();
    fflush(stdin);
    if (!scanf("%d", &key)) {
      printf("scanf failed!!!!\n");
      quit = 1;
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
      quit = 1;
      handle_signal(0);
      break;
    default:
      printf("unsupported command.\n");
      break;
    }
    pthread_mutex_unlock(&app_mutex);
  }

  pthread_join(thread, NULL);
  printf("pthread_join finish!\n");

exit:
  oc_main_shutdown();

  pthread_mutex_destroy(&mutex);
  pthread_mutex_destroy(&app_mutex);
  return 0;
}

/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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
#include "port/oc_clock.h"
#include "rd_client.h"
#include <pthread.h>
#include <signal.h>
#include <stdio.h>

// define application specific values.
static const char *spec_version = "ocf.1.0.0";
static const char *data_model_version = "ocf.res.1.0.0";

static const char *resource_rt = "core.light";
static const char *device_rt = "oic.d.cloudDevice";
static const char *device_name = "Cloud Device";

static const char *manufacturer = "ocfcloud.com";

pthread_mutex_t mutex;
pthread_cond_t cv;
static pthread_t event_thread;
static pthread_mutex_t app_sync_lock;

oc_resource_t *res1;
oc_resource_t *res2;

static struct timespec ts;
static int quit;

#define ACCESS_TOKEN_KEY "accesstoken"
#define REFRESH_TOKEN_KEY "refreshtoken"
#define REDIRECTURI_KEY "redirecturi"
#define USER_ID_KEY "uid"
#define EXPIRESIN_KEY "expiresin"

static void
display_menu(void)
{
  PRINT("\n\n################################################\nOCF "
        "Cloud-connected Device Certification Test "
        "Tool\n################################################\n");
  PRINT("[0] Display this menu\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[1] Cloud Register\n");
  PRINT("[2] Cloud Login\n");
  PRINT("[3] Cloud Logout\n");
  PRINT("[4] Cloud DeRegister\n");
  PRINT("[5] Cloud Refresh Token\n");
  PRINT("[6] Publish Resources\n");
  PRINT("-----------------------------------------------\n");
  PRINT("-----------------------------------------------\n");
  PRINT("[7] Exit\n");
  PRINT("################################################\n");
  PRINT("\nSelect option: \n");
}

#define SCANF(...)                                                             \
  do {                                                                         \
    if (scanf(__VA_ARGS__) != 1) {                                             \
      PRINT("ERROR Invalid input\n");                                          \
    }                                                                          \
  } while (0)

static int
app_init(void)
{
  int ret = oc_init_platform(manufacturer, NULL, NULL);
  ret |= oc_add_device("/oic/d", device_rt, device_name, spec_version,
                       data_model_version, NULL, NULL);
  return ret;
}

static void
cloud_refresh_token_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                       void *data)
{
  (void)data;
  PRINT("\nCloud Refresh Token status flags:\n");
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

static void
cloud_refresh_token(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_cloud_refresh_token(ctx, cloud_refresh_token_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Refresh Token request\n");
  } else {
    PRINT("\nIssued Refresh Token request\n");
  }
}

static void
cloud_deregister_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                    void *data)
{
  (void)data;
  PRINT("\nCloud DeRegister status flags:\n");
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
}

static void
cloud_deregister(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_cloud_deregister(ctx, cloud_deregister_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud DeRegister request\n");
  } else {
    PRINT("\nIssued Cloud DeRegister request\n");
  }
}

static void
cloud_logout_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  PRINT("\nCloud Logout status flags:\n");
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
}

static void
cloud_logout(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_cloud_logout(ctx, cloud_logout_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud Logout request\n");
  } else {
    PRINT("\nIssued Cloud Logout request\n");
  }
}

static void
cloud_login_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  PRINT("\nCloud Login status flags:\n");
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
}

static void
cloud_login(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_cloud_login(ctx, cloud_login_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud Login request\n");
  } else {
    PRINT("\nIssued Cloud Login request\n");
  }
}

static void
cloud_register_cb(oc_cloud_context_t *ctx, oc_cloud_status_t status, void *data)
{
  (void)data;
  PRINT("\nCloud Register status flags:\n");
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
}

static void
cloud_register(void)
{
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (!ctx) {
    return;
  }
  pthread_mutex_lock(&app_sync_lock);
  int ret = oc_cloud_register(ctx, cloud_register_cb, NULL);
  pthread_mutex_unlock(&app_sync_lock);
  if (ret < 0) {
    PRINT("\nCould not issue Cloud Register request\n");
  } else {
    PRINT("\nIssued Cloud Register request\n");
  }
}

struct light_t
{
  bool state;
  int power;
};

struct light_t light1 = { 0 };
struct light_t light2 = { 0 };

static void
get_handler(oc_request_t *request, oc_interface_mask_t interface,
            void *user_data)
{
  struct light_t *light = (struct light_t *)user_data;

  printf("get_handler:\n");

  oc_rep_start_root_object();
  switch (interface) {
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
        printf("value: %d\n", light->state);
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    } else if (key && !strcmp(key, "power")) {
      switch (rep->type) {
      case OC_REP_INT:
        light->power = rep->value.integer;
        printf("value: %d\n", light->power);
        break;
      default:
        oc_send_response(request, OC_STATUS_BAD_REQUEST);
        return;
      }
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  oc_notify_observers(request->resource);
}

static void
register_resources(void)
{
  res1 = oc_new_resource(NULL, "/light/1", 1, 0);
  oc_resource_bind_resource_type(res1, resource_rt);
  oc_resource_bind_resource_interface(res1, OC_IF_RW);
  oc_resource_set_default_interface(res1, OC_IF_RW);
  oc_resource_set_discoverable(res1, true);
  oc_resource_set_observable(res1, true);
  oc_resource_set_request_handler(res1, OC_GET, get_handler, &light1);
  oc_resource_set_request_handler(res1, OC_POST, post_handler, &light1);
  oc_cloud_add_resource(res1); /* Publish resource to the Cloud RD */
  oc_add_resource(res1);

  res2 = oc_new_resource(NULL, "/light/2", 1, 0);
  oc_resource_bind_resource_type(res2, resource_rt);
  oc_resource_bind_resource_interface(res2, OC_IF_RW);
  oc_resource_set_default_interface(res2, OC_IF_RW);
  oc_resource_set_discoverable(res2, true);
  oc_resource_set_observable(res2, true);
  oc_resource_set_request_handler(res2, OC_GET, get_handler, &light2);
  oc_resource_set_request_handler(res2, OC_POST, post_handler, &light2);
  oc_cloud_add_resource(res2); /* Publish resource to the Cloud RD */
  oc_add_resource(res2);
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

static void *
ocf_event_thread(void *data)
{
  (void)data;
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

  oc_storage_config("./cloud_tests_creds");

  if (pthread_mutex_init(&mutex, NULL) < 0) {
    printf("pthread_mutex_init failed!\n");
    return NULL;
  }
  oc_set_con_res_announced(false);
  oc_set_max_app_data_size(6000);
  int init = oc_main_init(&handler);
  if (init < 0)
    return NULL;

  oc_clock_time_t next_event;
  while (quit != 1) {
    pthread_mutex_lock(&app_sync_lock);
    next_event = oc_main_poll();
    pthread_mutex_unlock(&app_sync_lock);

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
  oc_main_shutdown();
  return NULL;
}

int
main(void)
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  if (pthread_create(&event_thread, NULL, &ocf_event_thread, NULL) != 0) {
    return -1;
  }

  int c;
  while (quit != 1) {
    display_menu();
    SCANF("%d", &c);
    switch (c) {
    case 0:
      continue;
    case 1:
      cloud_register();
      break;
    case 2:
      cloud_login();
      break;
    case 3:
      cloud_logout();
      break;
    case 4:
      cloud_deregister();
      break;
    case 5:
      cloud_refresh_token();
      break;
    case 6:
      oc_cloud_publish_resources(0);
      break;
    case 7:
      handle_signal(0);
    default:
      break;
    }
  }

  pthread_join(event_thread, NULL);

  return 0;
}

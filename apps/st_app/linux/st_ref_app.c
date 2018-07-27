/****************************************************************************
 *
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

#define USER_INPUT 1

#ifdef USER_INPUT
#include <pthread.h>
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>
#endif /* USER_INPUT */

#include "st_device_def.h"
#include "st_fota_manager.h"
#include "st_manager.h"
#include "st_resource_manager.h"

static const char *switch_rsc_uri = "/capability/switch/main/0";
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";

static const char *power_prop_key = "power";
static const char *dimming_prop_key = "dimmingSetting";
static const char *ct_prop_key = "ct";

static char power[10] = "on";

static int dimmingSetting = 50;
static int dimming_range[2] = { 0, 100 };
static int dimming_step = 5;

static int ct = 50;
static int ct_range[2] = { 0, 100 };

#ifdef USER_INPUT
#ifndef STATE_MODEL
static pthread_t g_user_input_thread;
#endif
static int g_user_input_shutdown_pipe[2];
#endif /* USER_INPUT */

#ifdef STATE_MODEL
static bool gstop_flag = false;
#endif

#define FLUSH_INPUT(var)                                                       \
  do {                                                                         \
    char fin = var;                                                            \
    while (fin != '\n' && fin != EOF)                                          \
      fin = getchar();                                                         \
  } while (0)

static void
switch_resource_construct(void)
{
  oc_rep_set_text_string(root, power, power);
}

static void
switchlevel_resource_construct(void)
{
  oc_rep_set_int(root, dimmingSetting, dimmingSetting);
  oc_rep_set_int_array(root, range, dimming_range, 2);
  oc_rep_set_int(root, step, dimming_step);
}

static void
color_temp_resource_construct(void)
{
  oc_rep_set_int(root, ct, ct);
  oc_rep_set_int_array(root, range, ct_range, 2);
}

static bool
get_resource_handler(st_request_t *request)
{
  if (strncmp(request->uri, switch_rsc_uri, strlen(switch_rsc_uri)) == 0) {
    switch_resource_construct();
  } else if (strncmp(request->uri, switchlevel_rsc_uri,
                     strlen(switchlevel_rsc_uri)) == 0) {
    switchlevel_resource_construct();
  } else if (strncmp(request->uri, color_temp_rsc_uri,
                     strlen(color_temp_rsc_uri)) == 0) {
    color_temp_resource_construct();
  } else {
    printf("[ST_APP] invalid uri %s\n", request->uri);
    return false;
  }

  return true;
}
static void
switch_resource_change(oc_rep_t *rep)
{
  int len = 0;
  char *m_power = NULL;
  if (oc_rep_get_string(rep, power_prop_key, &m_power, &len)) {
    strncpy(power, m_power, len);
    power[len] = '\0';
    printf("[ST_APP]  %s : %s\n", power_prop_key, power);

    // TODO: device specific behavior.
  }
}

static void
switchlevel_resource_change(oc_rep_t *rep)
{
  if (oc_rep_get_int(rep, dimming_prop_key, &dimmingSetting)) {
    printf("[ST_APP]  %s : %d\n", dimming_prop_key, dimmingSetting);

    // TODO: device specific behavior.
  }
}

static void
color_temp_resource_change(oc_rep_t *rep)
{
  if (oc_rep_get_int(rep, ct_prop_key, &ct)) {
    printf("[ST_APP]  %s : %d\n", ct_prop_key, ct);

    // TODO: device specific behavior.
  }
}

static bool
set_resource_handler(st_request_t *request)
{
  if (strncmp(request->uri, switch_rsc_uri, strlen(switch_rsc_uri)) == 0) {
    switch_resource_change(request->request_payload);
    switch_resource_construct();
  } else if (strncmp(request->uri, switchlevel_rsc_uri,
                     strlen(switchlevel_rsc_uri)) == 0) {
    switchlevel_resource_change(request->request_payload);
    switchlevel_resource_construct();
  } else if (strncmp(request->uri, color_temp_rsc_uri,
                     strlen(color_temp_rsc_uri)) == 0) {
    color_temp_resource_change(request->request_payload);
    color_temp_resource_construct();
  } else {
    printf("[ST_APP] invalid uri %s\n", request->uri);
    return false;
  }

  return true;
}

static bool
otm_confirm_handler(void)
{
  printf("[ST_APP] OTM request is coming. Will you confirm?[y/n]\n");
  bool ret = false;

  while(1){
    char in = getchar();
    FLUSH_INPUT(in);
    if (in == 'y' || in == 'Y') {
      printf("[ST_APP] CONFIRMED.\n");
      ret = true;
      break;
    } else if (in == 'n' || in == 'N'){
      printf("[ST_APP] DENIED.\n");
      ret = false;
      break;
    } else {
      printf("[ST_APP] Invalid input\n");
    }
  }
  return ret;
}

static void
st_status_handler(st_status_t status)
{
  if (status == ST_STATUS_DONE) {
    printf("[ST_APP] ST connected\n");
  }
#ifdef STATE_MODEL
  else if (status == ST_STATUS_STOP) {
    gstop_flag = true;
    printf("[ST_APP] ST stopped\n");
  }
#endif
  else {
    printf("[ST_APP] ST connecting(%d)\n", status);
  }
}

static bool
st_fota_cmd_handler(fota_cmd_t cmd)
{
  printf("[ST_APP] FOTA Command: %d\n", cmd);
  switch (cmd) {
  case FOTA_CMD_INIT:
    if (st_fota_set_state(FOTA_STATE_IDLE) != ST_ERROR_NONE) {
      printf("[ST_APP] st_fota_set_state failed.\n");
    }
    break;
  case FOTA_CMD_CHECK: {
    char *ver = "1.0";
    char *newver = "2.0";
    char *uri = "http://www.samsung.com";
    if (st_fota_set_fw_info(ver, newver, uri) != ST_ERROR_NONE) {
      printf("[ST_APP] st_fota_set_fw_info failed.\n");
    }
    break;
  }
  case FOTA_CMD_DOWNLOAD:
    if (st_fota_set_result(FOTA_RESULT_NO_MEMORY) != ST_ERROR_NONE) {
      printf("[ST_APP] st_fota_set_result failed.\n");
    }
    break;
  case FOTA_CMD_UPDATE:
    break;
  case FOTA_CMD_DOWNLOAD_UPDATE:
    break;
  }

  return true;
}

#ifdef USER_INPUT
static void
print_menu(void)
{
  printf("[ST_APP] =====================================\n");
  printf("[ST_APP] 1. Reset device\n");
  printf("[ST_APP] 2. notify switch resource\n");
  printf("[ST_APP] 0. Quit\n");

#ifdef STATE_MODEL
  printf("[ST_APP] -------------------------------------\n");
  printf("[ST_APP] 5. Start\n");
  printf("[ST_APP] 6. Stop\n");
  printf("[ST_APP] 7. Deinit (exit program if success)\n");
#endif
  printf("[ST_APP] =====================================\n");
}

static void *
user_input_loop(void *data)
{
  (void)data;
  char key[10];
  fd_set readfds, setfds;
  int stdin_fd = fileno(stdin);

  FD_ZERO(&readfds);
  FD_SET(stdin_fd, &readfds);
  FD_SET(g_user_input_shutdown_pipe[0], &readfds);

  while (1) {
    print_menu();
    fflush(stdin);

    setfds = readfds;
    int n = select(FD_SETSIZE, &setfds, NULL, NULL, NULL);

    if (n == -1) {
      printf("[ST_APP] user input failed!!!!\n");
      st_manager_stop();
      goto exit;
    }

    if (FD_ISSET(g_user_input_shutdown_pipe[0], &setfds)) {
      char buf;
      int count = read(g_user_input_shutdown_pipe[0], &buf, 1);
      (void)count;
      goto exit;
    }

    if (FD_ISSET(stdin_fd, &setfds)) {
      int count = read(stdin_fd, key, 10);
      if (count < 0) {
        goto exit;
      }
      FD_CLR(stdin_fd, &setfds);
    }

    switch (key[0]) {
    case '1':
      st_manager_reset();
      break;
    case '2':
      if (strncmp(power, "on", 2) == 0) {
        printf("[ST_APP] power off\n");
        strncpy(power, "off\0", 4);
      } else {
        printf("[ST_APP] power on\n");
        strncpy(power, "on\0", 3);
      }
      if (st_notify_back(switch_rsc_uri) != ST_ERROR_NONE) {
        printf("[ST_APP] st_notify_back failed.\n");
      }
      break;
#ifdef STATE_MODEL
    case '5':
      printf("[ST_APP] start()\n");
      printf("[ST_APP] result: %d \n", st_manager_start());
      break;
    case '6':
      printf("[ST_APP] stop()\n");
      printf("[ST_APP] result: %d \n", st_manager_stop());
      break;
    case '7':
      printf("[ST_APP] deinit()\n");
      st_error_t result = st_manager_deinitialize();
      printf("[ST_APP] result: %d \n", result);
      if (result == ST_ERROR_NONE)
        goto exit;
      break;
#endif
    case '0':
      st_manager_stop();
#ifdef STATE_MODEL
      goto exit;
#endif
      break;
    default:
      printf("[ST_APP] unsupported command.\n");
      break;
    }
  }
exit:
#ifndef STATE_MODEL
  pthread_exit(NULL);
#endif
  return NULL;
}

#ifndef STATE_MODEL
static int
user_input_thread_init(void)
{
  if (pipe(g_user_input_shutdown_pipe) < 0) {
    printf("shutdown pipe error\n");
    return -1;
  }

  pthread_create(&g_user_input_thread, NULL, user_input_loop, NULL);
  return 0;
}

static void
user_input_thread_destroy(void)
{
  if (write(g_user_input_shutdown_pipe[1], "\n", 1) < 0) {
    printf("[ST_APP] cannot wakeup user input thread\n");
    return;
  }
  pthread_join(g_user_input_thread, NULL);
  close(g_user_input_shutdown_pipe[0]);
  close(g_user_input_shutdown_pipe[1]);
  return;
}
#endif

static int
user_input_init(void)
{
#ifdef STATE_MODEL
  if (pipe(g_user_input_shutdown_pipe) < 0) {
    printf("shutdown pipe error\n");
    return -1;
  }
  return user_input_loop(NULL) == NULL ? 0 : -1;
#else
  return user_input_thread_init();
#endif
}

static void
user_input_deinit(void)
{
#ifndef STATE_MODEL
  user_input_thread_destroy();
#endif
}

#endif /* USER_INPUT */

int
main(void)
{
  st_error_t ret = st_manager_initialize();
  if (ret != ST_ERROR_NONE) {
    printf("[ST_APP] st_manager_initialize failed[%d].\n", ret);
    return -1;
  }

  if (st_register_resource_handler(get_resource_handler,
                                   set_resource_handler) != ST_ERROR_NONE) {
    printf("[ST_APP] st_register_resource_handler failed.\n");
    st_manager_deinitialize();
    return -1;
  }

  if (!st_set_device_profile(st_device_def, st_device_def_len)) {
    printf("[ST_APP] st_set_device_profile failed.\n");
    st_manager_deinitialize();
    return -1;
  }
  st_register_otm_confirm_handler(otm_confirm_handler);
  st_register_status_handler(st_status_handler);
  st_register_fota_cmd_handler(st_fota_cmd_handler);

#ifdef STATE_MODEL
  gstop_flag = false;
  do {
    ret = st_manager_start();
    if (ret != ST_ERROR_NONE) {
      printf("[ST_APP] st_manager_start error occur.(%d)\n", ret);
      sleep(6000);
    }
  } while (ret != ST_ERROR_NONE);
#endif

#ifdef USER_INPUT
  if (user_input_init() != 0) {
    printf("[ST_APP] user_input_init failed.\n");
    st_manager_deinitialize();
    return -1;
  }
#endif /* USER_INPUT */

#ifndef STATE_MODEL
  do {
    ret = st_manager_start();
    if (ret != ST_ERROR_NONE) {
      printf("[ST_APP] st_manager_start failed[%d].\n", ret);
      st_manager_deinitialize();
      return -1;
    }

    ret = st_manager_run_loop();
    if (ret != ST_ERROR_NONE) {
      printf("[ST_APP] st_manager_run_loop failed[%d].\n", ret);
      sleep(6000);
    }
  } while (ret != ST_ERROR_NONE);
#else
  while (!gstop_flag) {
    sleep(1);
  }
#endif

#ifdef USER_INPUT
  user_input_deinit();
#endif

  st_unregister_status_handler();
  st_manager_deinitialize();

  return 0;
}

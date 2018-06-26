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

#include "st_fota_manager.h"
#include "st_port.h"

static st_fota_cmd_cb_t g_st_fota_cmd_cb = NULL;

static int
fota_cmd_handler(fota_cmd_t cmd)
{
  if (g_st_fota_cmd_cb) {
    if (g_st_fota_cmd_cb(cmd))
      return 0;
  }

  return -1;
}

int
st_fota_manager_start(void)
{
  return fota_init(fota_cmd_handler);
}

void
st_fota_manager_stop()
{
  fota_deinit();
}

int
st_fota_set_state(fota_state_t state)
{
  return fota_set_state(state);
}

int
st_fota_set_fw_info(const char *ver, const char *uri)
{
  return fota_set_fw_info(ver, uri);
}

int
st_fota_set_result(fota_result_t result)
{
  return fota_set_result(result);
}

bool
st_register_fota_cmd_handler(st_fota_cmd_cb_t cb)
{
  if (!cb || g_st_fota_cmd_cb) {
    st_print_log("Failed to register fota cmd handler\n");
    return false;
  }

  g_st_fota_cmd_cb = cb;
  return true;
}

void
st_unregister_fota_cmd_handler(void)
{
  g_st_fota_cmd_cb = NULL;
}

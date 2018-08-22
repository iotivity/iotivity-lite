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
#include "fota.h"
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

st_error_t
st_fota_set_state(fota_state_t state)
{
  return (fota_set_state(state) == 0) ? ST_ERROR_NONE
                                      : ST_ERROR_OPERATION_FAILED;
}

st_error_t
st_fota_set_fw_info(const char *cur_version, const char *new_version,
                    const char *uri)
{
  return (fota_set_fw_info(cur_version, new_version, uri) == 0)
           ? ST_ERROR_NONE
           : ST_ERROR_INVALID_PARAMETER;
}

st_error_t
st_fota_set_result(fota_result_t result)
{
  return (fota_set_result(result) == 0) ? ST_ERROR_NONE
                                        : ST_ERROR_INVALID_PARAMETER;
}

bool
st_register_fota_cmd_handler(st_fota_cmd_cb_t cb)
{
  if (!cb) {
    st_print_log("[ST_FM] Invalid parameter\n");
    return false;
  }
  if (g_st_fota_cmd_cb) {
    st_print_log("[ST_FM] Already registered\n");
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

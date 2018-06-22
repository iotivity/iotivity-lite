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

#ifndef FOTA_H
#define FOTA_H

/**
  @brief FOTA API of IoTivity-constrained for firmware update.
  @file
*/

#define FOTA_CMD_INIT "Init"
#define FOTA_CMD_CHECK "Check"
#define FOTA_CMD_DOWNLOAD "Download"
#define FOTA_CMD_UPDATE "Update"
#define FOTA_CMD_DOWNLOAD_UPDATE "DownloadUpdate"

typedef enum {
  FOTA_STATE_IDLE,
  FOTA_STATE_DOWNLOADING,
  FOTA_STATE_DOWNLOADED,
  FOTA_STATE_UPDATING
} fota_state_t;

typedef enum {
  FOTA_RESULT_INIT,
  FOTA_RESULT_SUCCESS,
  FOTA_RESULT_NO_MEMORY,
  FOTA_RESULT_NO_RAM,
  FOTA_RESULT_DISCONNECT,
  FOTA_RESULT_INTEGRITY_FAIL,
  FOTA_RESULT_UNSUPPORT_TYPE,
  FOTA_RESULT_INVALID_URI,
  FOTA_RESULT_FAILED,
  FOTA_RESULT_UNSUPPORT_PROTOCOL
} fota_result_t;

typedef int (*fota_cmd_cb_t)(const char *cmd);

int fota_init(fota_cmd_cb_t cb);
void fota_deinit(void);

int fota_set_state(fota_state_t state);
int fota_set_fw_info(const char *ver, const char *uri);
int fota_set_result(fota_result_t result);

#endif /* FOTA_H */

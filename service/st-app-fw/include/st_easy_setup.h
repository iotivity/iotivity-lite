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

#ifndef ST_EASY_SETUP_H
#define ST_EASY_SETUP_H

#include "easysetup.h"
#include "samsung/sc_easysetup.h"
#include "st_store.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SSID_LEN (32)

typedef enum {
  EASY_SETUP_INITIALIZE,
  EASY_SETUP_PROGRESSING,
  EASY_SETUP_FINISH,
  EASY_SETUP_FAIL,
  EASY_SETUP_RESET
} st_easy_setup_status_t;

typedef void (*st_easy_setup_cb_t)(st_easy_setup_status_t status);

int st_is_easy_setup_finish(void);
int st_easy_setup_start(sc_properties *vendor_props, st_easy_setup_cb_t cb);
void st_easy_setup_stop(void);
int st_gen_ssid(char *ssid, const char *device_name, const char *mnid,
                const char *sid);

#ifdef __cplusplus
}
#endif

#endif /* ST_EASY_SETUP_H */

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

#include "easysetup.h"
#include "samsung/sc_easysetup.h"
#include <stdbool.h>

typedef enum {
  EASY_SETUP_INITIALIZE,
  EASY_SETUP_PROGRESSING,
  EASY_SETUP_FINISH,
  EASY_SETUP_FAIL,
  EASY_SETUP_RESET
} st_easy_setup_status_t;

typedef void (*st_easy_setup_cb_t)(st_easy_setup_status_t status);

bool st_easy_setup_start(sc_properties *vendor_props, st_easy_setup_cb_t cb);
void st_easy_setup_stop(void);

st_easy_setup_status_t get_easy_setup_status(void);
es_coap_cloud_conf_data *get_cloud_informations(void);
sc_coap_cloud_server_conf_properties *get_st_cloud_informations(void);
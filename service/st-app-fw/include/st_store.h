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

#ifndef ST_STORE_H
#define ST_STORE_H

#include "oc_endpoint.h"
#include "oc_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  oc_string_t ssid;
  oc_string_t pwd;
} st_ap_store_t;

typedef struct
{
  oc_string_t ci_server;
  oc_string_t auth_provider;
  oc_string_t uid;
  oc_string_t access_token;
  oc_string_t refresh_token;
  uint8_t status;
} st_cloud_store_t;

typedef struct
{
  oc_string_t salt;
  oc_string_t iv;
  int data_len;
  int encrypted_len;
} st_security_store_t;

typedef struct
{
  bool status;
  st_ap_store_t accesspoint;
  st_cloud_store_t cloudinfo;
#ifdef OC_SECURITY
  st_security_store_t securityinfo;
#endif /* OC_SECURITY */
} st_store_t;

int st_store_load(void);
int st_store_dump(void);
void st_store_dump_async(void);
void st_store_info_initialize(void);
st_store_t *st_store_get_info(void);

#ifdef __cplusplus
}
#endif

#endif /* ST_STORE_H */

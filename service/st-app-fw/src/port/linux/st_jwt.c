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

#ifdef OC_RPK

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <oc_log.h>
#include <oc_uuid.h>
#include <util/oc_mem.h>
#include <cJSON.h>
#include "st_jwt.h"

#ifdef __cplusplus
extern "C"
{
#endif

static bool jwt_json_get_createdts(char *dts)
{
  time_t now = time(NULL);
  sprintf(dts, "%d", now);
  return (now != -1) ? true:false;
}

static bool jwt_json_signup_cjson(char *out_header, char *out_payload, char *sn)
{
  cJSON *jwt_header = cJSON_CreateObject();
  cJSON *jwt_payload = cJSON_CreateObject();

  oc_uuid_t random_uuid;
  char random_uuid_str[OC_UUID_LEN];
  char dts[25];

  cJSON_AddStringToObject(jwt_header,"alg","EdDSA");
  cJSON_AddStringToObject(jwt_header,"kty","OKP");
  cJSON_AddStringToObject(jwt_header,"crv","Ed25519");
  cJSON_AddStringToObject(jwt_header,"typ","JWT");
  cJSON_AddStringToObject(jwt_header,"ver","1.0.0");
  cJSON_AddStringToObject(jwt_header,"kid", sn);

  if(!jwt_json_get_createdts(dts)) {
    //If we fail to create createdts, set time 2018-1-1 00:00
    st_log_print("createdts is NULL, we can not make jwt");
    cJSON_AddStringToObject(jwt_payload,"iat", "1514764800");
  } else {
    cJSON_AddStringToObject(jwt_payload,"iat", dts);
  }

  //make random uuid string
  oc_gen_uuid(&random_uuid);
  oc_uuid_to_str(&random_uuid, random_uuid_str, OC_UUID_LEN);
  cJSON_AddStringToObject(jwt_payload,"jti",random_uuid_str);

  char *header_str = cJSON_Print(jwt_header);
  strncpy(out_header, header_str, JSON_HEADER_SIZE);
  char *payload_str = cJSON_Print(jwt_payload);
  strncpy(out_payload, payload_str, JSON_PAYLOAD_SIZE);

  cJSON_Delete(jwt_header);
  cJSON_Delete(jwt_payload);

  return true;
}

static bool jwt_json_signin_cjson(char *header, char *payload, char *sn)
{
  //now, sign-up, sign-in is same.
  return json_signup_cjson(header, payload, sn);
}

static bool jwt_sign_ed25519(char *signature, const char *pub_key, const char *priv_key,
                             const char *message, int message_len)
{
//Equivalent logic for edsign_sign is required here.
//edsign_sign(signature, pub_key, priv_key, message, message_len);

  return false;
}

bool st_jwt_json_signup_get(char *header, char *payload, char *sn)
{
  return jwt_json_signup_cjson(header, payload, sn);
}

bool st_jwt_json_signin_get(char *header, char *payload, char *sn)
{
  return jwt_json_signin_cjson(header, payload, sn);
}

bool st_jwt_signature_get(char *signature, const char *pub_key, const char *priv_key,
                          const char *message, int message_len)
{
  return jwt_sign_ed25519(signature, pub_key, priv_key, message, message_len);
}

#ifdef __cplusplus
}
#endif

#endif /*OC_RPK*/

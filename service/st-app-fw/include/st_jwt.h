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

#ifndef ST_JWT_H
#define ST_JWT_H
#include <stdbool.h>

#define JSON_HEADER_SIZE 256
#define JSON_PAYLOAD_SIZE 256
#define JSON_SIGNATURE_SIZE 384

#ifdef __cplusplus
extern "C" {
#endif

bool st_jwt_json_signup_get(char *header, char *payload, char *sn);
bool st_jwt_json_signin_get(char *header, char *payload, char *sn);
bool st_jwt_signature_get(char *signature, const char *pub_key, const char *priv_key, const char *message, int message_len);

#ifdef __cplusplus
}
#endif

#endif /*ST_JWT_H*/
#endif /*OC_RPK*/

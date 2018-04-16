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

/**
  @brief Cloud Access API of IoTivity-constrained for client and server.
  @file
*/

#ifndef CLOUD_ACCESS_H
#define CLOUD_ACCESS_H

#include "oc_client_state.h"

/** Account URI.*/
#define OC_RSRVD_ACCOUNT_URI "/oic/account"

/** Account session URI.*/
#define OC_RSRVD_ACCOUNT_SESSION_URI "/oic/account/session"

/** Account token refresh URI.*/
#define OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI "/oic/account/tokenrefresh"

/** Defines auth provider. */
#define OC_RSRVD_AUTHPROVIDER "authprovider"

/** Defines auth code. */
#define OC_RSRVD_AUTHCODE "authcode"

/** Defines access token. */
#define OC_RSRVD_ACCESS_TOKEN "accesstoken"

/** Defines login. */
#define OC_RSRVD_LOGIN "login"

/** Defines grant type. */
#define OC_RSRVD_GRANT_TYPE "granttype"

/** To represent grant type with refresh token. */
#define OC_RSRVD_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

/** Defines refresh token. */
#define OC_RSRVD_REFRESH_TOKEN "refreshtoken"

/** Defines user UUID. */
#define OC_RSRVD_USER_UUID "uid"

/**
  @brief Function for account registration to account server.
  @param host The address of the Cloud.
  @param authProvider Provider name used for authentication.
  @param authCode The authorization code obtained by using an authorization
  server
                  as an intermediary between the client and resource owner.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns True if success.
*/
bool oc_sign_up(const char *host, const char *auth_provider,
                const char *auth_code, oc_response_handler_t handler,
                void *user_data);

/**
  @brief Function for sign-in to account server.
  @param host The address of the Cloud.
  @param uid Identifier of the user obtained by account registration.
  @param access_token Identifier of the resource obtained by account
  registration.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns True if success.
*/
bool oc_sign_in(const char *host, const char *uid, const char *access_token,
                oc_response_handler_t handler, void *user_data);

/**
  @brief Function for sign-out to account server.
  @param host The address of the Cloud.
  @param access_token Identifier of the resource obtained by account
  registration.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns True if success.
*/
bool oc_sign_out(const char *host, const char *access_token,
                 oc_response_handler_t handler, void *user_data);

/**
  @brief Function for refresh access token to account server.
  @param host The address of the Cloud.
  @param uid Identifier of the user obtained by account registration.
  @param refresh_token Refresh token used for access token refresh.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns True if success.
*/
bool oc_refresh_access_token(const char *host, const char *uid,
                             const char *refresh_token,
                             oc_response_handler_t handler, void *user_data);

#endif /* CLOUD_ACCESS_H */
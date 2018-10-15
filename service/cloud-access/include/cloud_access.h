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

#ifdef __cplusplus
extern "C" {
#endif

/** Account URI.*/
#define OC_RSRVD_ACCOUNT_URI "/oic/account"

/** Account session URI.*/
#define OC_RSRVD_ACCOUNT_SESSION_URI "/oic/account/session"

/** Account token refresh URI.*/
#define OC_RSRVD_ACCOUNT_TOKEN_REFRESH_URI "/oic/account/tokenrefresh"

/** Device URI.*/
#define OC_RSRVD_DEVICE_URI "/oic/device"

/** Device profile URI.*/
#define OC_RSRVD_DEVICE_PROFILE_URI "/oic/account/profile/device"

/** Ping URI.*/
#define OC_RSRVD_PING_URI "/oic/ping"

/** To represent grant type with refresh token. */
#define OC_RSRVD_GRANT_TYPE_REFRESH_TOKEN "refresh_token"

/**
  @brief Function for account registration to account server.
  @param endpoint The endpoint of the Cloud.
  @param auth_provider Provider name used for authentication.
  @param uid Identifier of the user obtained by account registration.
  @param access_token Identifier of the resource obtained by account
   registration.
  @param device_index Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_sign_up(oc_endpoint_t *endpoint, const char *auth_provider,
                const char *uid, const char *access_token, size_t device_index,
                oc_response_handler_t handler, void *user_data);

/**
  @brief Function for account registration to account server using auth.
  @param endpoint The endpoint of the Cloud.
  @param auth_provider Provider name used for authentication.
  @param auth_code The authorization code obtained by using an authorization
   server as an intermediary between the client and resource owner.
  @param device_index Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
#ifndef ST_APP_OPTIMIZATION
bool oc_sign_up_with_auth(oc_endpoint_t *endpoint, const char *auth_provider,
                          const char *auth_code, size_t device_index,
                          oc_response_handler_t handler, void *user_data);
#endif

/**
  @brief Function for sign-in to account server.
  @param endpoint The endpoint of the Cloud.
  @param uid Identifier of the user obtained by account registration.
  @param access_token Identifier of the resource obtained by account
   registration.
  @param device_index Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_sign_in(oc_endpoint_t *endpoint, const char *uid,
                const char *access_token, size_t device_index,
                oc_response_handler_t handler, void *user_data);

/**
  @brief Function for sign-out to account server.
  @param endpoint The endpoint of the Cloud.
  @param access_token Identifier of the resource obtained by account
   registration.
  @param device_index Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_sign_out(oc_endpoint_t *endpoint, const char *access_token,
                 size_t device_index, oc_response_handler_t handler,
                 void *user_data);

/**
  @brief Function for refresh access token to account server.
  @param endpoint The endpoint of the Cloud.
  @param uid Identifier of the user obtained by account registration.
  @param refresh_token Refresh token used for access token refresh.
  @param device_index Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_refresh_access_token(oc_endpoint_t *endpoint, const char *uid,
                             const char *refresh_token, size_t device_index,
                             oc_response_handler_t handler, void *user_data);

/**
  @brief Function to register device profile into account server.
  @param endpoint The endpoint of the Cloud.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_set_device_profile(oc_endpoint_t *endpoint,
                           oc_response_handler_t handler, void *user_data);

/**
  @brief Function to delete the device registered on the account signed-in.
  @param endpoint The endpoint of the Cloud.
  @param uid Identifier of the user obtained by account registration.
  @param device_index Index of the device for an unique identifier.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
#ifndef ST_APP_OPTIMIZATION
bool oc_delete_device(oc_endpoint_t *endpoint, const char *uid,
                      size_t device_index, oc_response_handler_t handler,
                      void *user_data);
#endif

/**
  @brief Function for discovers on a ping resource.
  @param endpoint The endpoint of the Cloud.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_find_ping_resource(oc_endpoint_t *endpoint,
                           oc_response_handler_t handler, void *user_data);

/**
  @brief Function for send ping message to remote endpoint.
  @param endpoint The endpoint of the Cloud.
  @param interval The interval value for keep-alive.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
bool oc_send_ping_request(oc_endpoint_t *endpoint, int interval,
                          oc_response_handler_t handler, void *user_data);

/**
  @brief Function for update value of ping interval.
  @param endpoint The endpoint of the Cloud.
  @param interval Integer array for update the interval.
  @param length The length of the interval array.
  @param handler To refer to the request sent out on behalf of calling this API.
  @param user_data The user data passed from the registration function.
  @return Returns true if success.
*/
#ifndef ST_APP_OPTIMIZATION
bool oc_send_ping_update(oc_endpoint_t *endpoint, const int *interval,
                         int length, oc_response_handler_t handler,
                         void *user_data);
#endif

#ifdef __cplusplus
}
#endif

#endif /* CLOUD_ACCESS_H */

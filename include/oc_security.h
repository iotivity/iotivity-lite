/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_SECURITY_H
#define OC_SECURITY_H

#include <stdint.h>
#include <stdbool.h>
#include "oc_endpoint.h"

/**
 * Function pointer for getting peer's public key and token for raw public key OTM.
 * Callback is expected to copy key and token to the pointers provided.
 *
 * Function provides pointers to be filled with key and token binary values and their length.
 *
 * @param cpubkey pointer to peer's public key
 * @param cpubkey_len peer's public key length
 * @param token pointer to security token
 * @param token_len security token length
 */
typedef void (*oc_sec_get_cpubkey_and_token)(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token, int *token_len);

/**
 * Function to setting RPK peer's public key and token callback from user.
 *
 * @param cpubkey_and_token_cb implementation of cpubkey and token callback.
 */
void oc_sec_set_cpubkey_and_token_load(oc_sec_get_cpubkey_and_token cpubkey_and_token_cb);

/**
 * Function to unsetting RPK peer's public key and token callback.
 */
void oc_sec_unset_cpubkey_and_token_load();

/**
 * Function pointer for getting own private key for raw public key OTM.
 * Callback is expected to copy key buffer to the pointer provided and set the buffer length.
 *
 * @param priv_key pointer to own private key buffer
 * @param priv_key_len own private key buffer length
 */
typedef void (*oc_sec_get_own_key)(uint8_t *priv_key, int *priv_key_len);

/**
 * Function to setting RPK own private key callback from user.
 *
 * @param ownkey_cb implementation of own key callback.
 */
void oc_sec_set_own_key_load(oc_sec_get_own_key ownkey_cb);

/**
 * Function to unset RPK private key callback.
 */
void oc_sec_unset_own_key_load();

typedef enum {
  OC_SEC_ERR_ACL,
  OC_SEC_ERR_CRED,
  OC_SEC_ERR_DOXM,
  OC_SEC_ERR_PSTAT,
  OC_SEC_OTM_INIT,
  OC_SEC_OTM_START,
  OC_SEC_OTM_FINISH
} oc_sec_otm_err_code_t;

/**
 * Function pointer returning error code to user
 *
 * @param code error code
 */
typedef void (*oc_sec_otm_err_cb_t)(oc_sec_otm_err_code_t code);

/**
 * Function to setting error callback from user.
 *
 * @param cb implementation of error callback.
 */
void oc_sec_otm_set_err_cb(oc_sec_otm_err_cb_t cb);

/**
 * Function to unset error callback.
 */
#define oc_sec_otm_unset_err_cb() oc_sec_otm_set_err_cb(NULL)

typedef enum
{
  OC_DOXM_JW = 0x0,
  OC_DOXM_MFG = 0x2,
  OC_DOXM_RPK = 0xFF03
} oc_doxm_method_t;

/**
 * Function to setting DOXM method
 *
 * @param oxmsel selected DOXM method
 */
void oc_set_doxm(oc_doxm_method_t oxmsel);

/**
 * Function pointer requesting permission on ownership transfer
 */
typedef bool (*oc_sec_change_owner_cb_t)(void);

/**
 * Function to set user's ownership transfer permission callback
 *
 * @param cb selected DOXM method
 */
void oc_sec_set_owner_cb(oc_sec_change_owner_cb_t cb);

/**
 * Function to unset ownership transfer permission callback
 */
#define oc_sec_unset_owner_cb() oc_sec_set_owner_cb(NULL)

/**
 * Function to set RPK device hash auth key
 *
 * @param endpoint endpoint
 * @param hmac buffer containing HMAC
 * @param hmac_len HMAC length
 */
bool oc_sec_get_rpk_hmac(oc_endpoint_t *endpoint, unsigned char *hmac, int *hmac_len);

#endif /* OC_SECURITY_H */

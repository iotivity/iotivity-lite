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

#ifndef OC_RPK_H
#define OC_RPK_H

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
 * Function pointer for getting peer's public key and token for raw public key OTM.
 * Callback is expected to copy key buffer to the pointer provided and set the buffer length.
 *
 * @param priv_key pointer to own private key buffer
 * @param priv_key_len own private key buffer length
 * @param pub_key pointer to own public key buffer
 * @param pub_key_len own public key buffer length
 */
typedef void (*oc_sec_get_own_key)(uint8_t *priv_key, int *priv_key_len, uint8_t *pub_key, int *pub_key_len);

/**
 * Function to setting RPK own private key callback from user.
 *
 * @param ownkey_cb implementation of own key callback.
 */
void oc_sec_set_own_key_load(oc_sec_get_own_key ownkey_cb);

#endif /* OC_RPK_H */

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

typedef void (*oc_sec_get_cpubkey_and_token)(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token, int *token_len);
void oc_sec_set_cpubkey_and_token_load(oc_sec_get_cpubkey_and_token cpubkey_and_token_cb);

typedef void (*oc_sec_get_own_key)(uint8_t *priv_key, int *priv_key_len);
void oc_sec_set_own_key_load(oc_sec_get_own_key ownkey_cb);

#endif /* OC_RPK_H */

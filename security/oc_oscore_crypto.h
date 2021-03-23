/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_OSCORE_CRYPTO_H
#define OC_OSCORE_CRYPTO_H

#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int HKDF_SHA256(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm,
                uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm,
                uint8_t okm_len);

void oc_oscore_AEAD_nonce(uint8_t *id, uint8_t id_len, uint8_t *piv,
                          uint8_t piv_len, uint8_t *civ, uint8_t *nonce,
                          uint8_t nonce_len);

int oc_oscore_compose_AAD(uint8_t *kid, uint8_t kid_len, uint8_t *piv,
                          uint8_t piv_len, uint8_t *AAD, uint8_t *AAD_len);

int oc_oscore_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                      size_t tag_len, uint8_t *key, size_t key_len,
                      uint8_t *nonce, size_t nonce_len, uint8_t *AAD,
                      size_t AAD_len, uint8_t *output);

int oc_oscore_encrypt(uint8_t *plaintext, size_t plaintext_len, size_t tag_len,
                      uint8_t *key, size_t key_len, uint8_t *nonce,
                      size_t nonce_len, uint8_t *AAD, size_t AAD_len,
                      uint8_t *output);

#ifdef __cplusplus
}
#endif

#endif /* OC_OSCORE_CRYPTO_H */

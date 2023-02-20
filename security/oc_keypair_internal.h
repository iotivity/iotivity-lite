/****************************************************************************
 *
 * Copyright (c) 2018-2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef OC_KEYPAIR_H
#define OC_KEYPAIR_H

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "oc_rep.h"

#include <mbedtls/ecp.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_ECDSA_PUBKEY_SIZE (91)
#define OC_ECDSA_PRIVKEY_SIZE (200)

typedef struct oc_ecdsa_keypair_t
{
  struct oc_ecdsa_keypair_t *next;
  size_t device;
  uint8_t public_key[OC_ECDSA_PUBKEY_SIZE];
  uint8_t private_key[OC_ECDSA_PRIVKEY_SIZE];
  size_t private_key_size;
} oc_ecdsa_keypair_t;

/**
 * @brief Generate an ECP key-pair.
 *
 * @param grpid Mbed TLS elliptic curve identifier
 * @param[out] public_key buffer to store generated public key
 * @param public_key_buf_size size of the public key buffer
 * @param[out] public_key_size size of the generated public key
 * @param[out] private_key buffer to store generated private key
 * @param private_key_buf_size size of the private key buffer
 * @param[out] private_key_size size of the generated private key
 * @return 0 on success
 * @return -1 on failure
 */
int oc_generate_ecdsa_keypair(mbedtls_ecp_group_id grpid, uint8_t *public_key,
                              size_t public_key_buf_size,
                              size_t *public_key_size, uint8_t *private_key,
                              size_t private_key_buf_size,
                              size_t *private_key_size);

/**
 * @brief Encode public and private key-pair to global encoder.
 *
 * @param kp key-pair to encode (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_encode_ecdsa_keypair(const oc_ecdsa_keypair_t *kp);

/**
 * @brief Decode public and private key.
 *
 * @param rep representation to decode (cannot be NULL)
 * @param[out] kp output variable to store the decoded private and public keys
 * (cannot be NULL)
 * @return true on success
 * @return false on failure
 */
bool oc_sec_decode_ecdsa_keypair(const oc_rep_t *rep, oc_ecdsa_keypair_t *kp);

/**
 * @brief Generate a public and private key pair, store it in a global list of
 * key-pairs and associate it with the given device.
 *
 * @note Each device can be associated with only a single key-pair. If this
 * function is called multiple times with a single device then each successful
 * decoding ovewrites the previous key-pair associated with the device.
 *
 * @param rep representation to decode (cannot be NULL)
 * @param device device index
 * @return true on success
 * @return false on failure
 */
bool oc_generate_ecdsa_keypair_for_device(size_t device);

/**
 * @brief Decode public and private key, store it in a global list of key-pairs
 * and associate it with the given device.
 *
 * @note Each device can be associated with only a single key-pair. If this
 * function is called multiple times with a single device then each successful
 * decoding ovewrites the previous key-pair associated with the device.
 *
 * @param rep representation to decode (cannot be NULL)
 * @param device device index
 * @return true on success
 * @return false on failure
 */
bool oc_sec_decode_ecdsa_keypair_for_device(const oc_rep_t *rep, size_t device);

/**
 * @brief Find key-pair associated with given device, encode it to the global
 * encoder.
 *
 * @param device device index
 * @return true on success
 * @return false on failure
 */
bool oc_sec_encode_ecdsa_keypair_for_device(size_t device);

/** Count the number of key-pair in the global list */
size_t oc_sec_count_ecdsa_keypairs(void);

/** Get the key-pair associated with the given index */
oc_ecdsa_keypair_t *oc_sec_get_ecdsa_keypair(size_t device);

/** Free all key-pairs in the global list */
void oc_sec_free_ecdsa_keypairs(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_SECURITY && OC_PKI */

#endif /* OC_KEYPAIR_H */

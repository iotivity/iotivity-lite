/*
// Copyright (c) 2018-2019 Intel Corporation
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

#ifndef OC_KEYPAIR_H
#define OC_KEYPAIR_H

#include "oc_rep.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
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

bool oc_sec_decode_ecdsa_keypair(oc_rep_t *rep, size_t device);
bool oc_sec_encode_ecdsa_keypair(size_t device);
int oc_generate_ecdsa_keypair(uint8_t *public_key, size_t public_key_buf_size,
                              size_t *public_key_size, uint8_t *private_key,
                              size_t private_key_buf_size,
                              size_t *private_key_size);
int oc_generate_ecdsa_keypair_for_device(size_t device);
oc_ecdsa_keypair_t *oc_sec_get_ecdsa_keypair(size_t device);
void oc_free_ecdsa_keypairs(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_KEYPAIR_H */

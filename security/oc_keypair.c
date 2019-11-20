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

#ifdef OC_SECURITY
#ifdef OC_PKI

#include "oc_keypair.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "oc_api.h"
#include "oc_store.h"

OC_MEMB(oc_keypairs_s, oc_ecdsa_keypair_t, OC_MAX_NUM_DEVICES);
OC_LIST(oc_keypairs);

oc_ecdsa_keypair_t *
oc_sec_get_ecdsa_keypair(size_t device)
{
  oc_ecdsa_keypair_t *kp = (oc_ecdsa_keypair_t *)oc_list_head(oc_keypairs);
  while (kp) {
    if (kp->device == device) {
      return kp;
    }
    kp = kp->next;
  }
  return NULL;
}

void
oc_free_ecdsa_keypairs(void)
{
  oc_ecdsa_keypair_t *kp = (oc_ecdsa_keypair_t *)oc_list_pop(oc_keypairs);
  while (kp) {
    oc_memb_free(&oc_keypairs_s, kp);
    kp = (oc_ecdsa_keypair_t *)oc_list_pop(oc_keypairs);
  }
}

static oc_ecdsa_keypair_t *
add_keypair(size_t device)
{
  oc_ecdsa_keypair_t *kp = oc_memb_alloc(&oc_keypairs_s);
  if (!kp) {
    return NULL;
  }
  kp->device = device;
  oc_list_add(oc_keypairs, kp);
  return kp;
}

bool
oc_sec_decode_ecdsa_keypair(oc_rep_t *rep, size_t device)
{
  oc_ecdsa_keypair_t *kp = oc_sec_get_ecdsa_keypair(device);
  if (!kp) {
    kp = add_keypair(device);
    if (!kp) {
      return false;
    }
  }

  while (rep) {
    if (rep->type == OC_REP_BYTE_STRING) {
      if (oc_string_len(rep->name) == 10 &&
          memcmp("public_key", oc_string(rep->name), 10) == 0) {
        if (oc_string_len(rep->value.string) != OC_ECDSA_PUBKEY_SIZE) {
          return false;
        }
        memcpy(kp->public_key, oc_cast(rep->value.string, uint8_t),
               OC_ECDSA_PUBKEY_SIZE);
      } else if (oc_string_len(rep->name) == 11 &&
                 memcmp("private_key", oc_string(rep->name), 11) == 0) {
        if (oc_string_len(rep->value.string) > OC_ECDSA_PRIVKEY_SIZE) {
          return false;
        }
        memcpy(kp->private_key, oc_cast(rep->value.string, uint8_t),
               oc_string_len(rep->value.string));
        kp->private_key_size = (uint8_t)oc_string_len(rep->value.string);
      }
    }
    rep = rep->next;
  }

  return true;
}

bool
oc_sec_encode_ecdsa_keypair(size_t device)
{
  oc_ecdsa_keypair_t *kp = oc_sec_get_ecdsa_keypair(device);
  if (!kp) {
    return false;
  }

  oc_rep_start_root_object();
  oc_rep_set_byte_string(root, public_key, kp->public_key,
                         OC_ECDSA_PUBKEY_SIZE);
  oc_rep_set_byte_string(root, private_key, kp->private_key,
                         kp->private_key_size);
  oc_rep_end_root_object();

  return true;
}

int
oc_generate_ecdsa_keypair(uint8_t *public_key, size_t public_key_buf_size,
                          size_t *public_key_size, uint8_t *private_key,
                          size_t private_key_buf_size, size_t *private_key_size)
{
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_pk_init(&pk);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

#define PERSONALIZATION_DATA "IoTivity-Lite-Key-Pair"

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char *)PERSONALIZATION_DATA,
                                  sizeof(PERSONALIZATION_DATA));

#undef PERSONALIZATION_DATA

  if (ret < 0) {
    OC_ERR("error initializing source of entropy");
    goto generate_ecdsa_keypair_error;
  }

  ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
  if (ret < 0) {
    OC_ERR("error initializing mbedtls pk context");
    goto generate_ecdsa_keypair_error;
  }

  ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(pk),
                            mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret < 0) {
    OC_ERR("error in ECDSA key generation");
    goto generate_ecdsa_keypair_error;
  }

  ret = mbedtls_pk_write_key_der(&pk, private_key, private_key_buf_size);
  if (ret < 0) {
    OC_ERR("error writing EC private key to internal structure");
    goto generate_ecdsa_keypair_error;
  }
  *private_key_size = (uint8_t)ret;
  memmove(private_key, private_key + private_key_buf_size - ret,
          *private_key_size);

  ret = mbedtls_pk_write_pubkey_der(&pk, public_key, public_key_buf_size);
  if (ret < 0) {
    OC_ERR("error writing EC public key to internal structure");
    goto generate_ecdsa_keypair_error;
  }
  *public_key_size = (size_t)ret;

  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_pk_free(&pk);

  return 0;
generate_ecdsa_keypair_error:
  mbedtls_entropy_free(&entropy);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_pk_free(&pk);
  return -1;
}

int
oc_generate_ecdsa_keypair_for_device(size_t device)
{
  oc_ecdsa_keypair_t *kp = oc_sec_get_ecdsa_keypair(device);
  if (!kp) {
    kp = add_keypair(device);
    if (!kp) {
      return -1;
    }
  }

  size_t public_key_size = 0;
  if (oc_generate_ecdsa_keypair(
        kp->public_key, OC_ECDSA_PUBKEY_SIZE, &public_key_size, kp->private_key,
        OC_ECDSA_PRIVKEY_SIZE, &kp->private_key_size) < 0) {
    oc_memb_free(&oc_keypairs_s, kp);
    return -1;
  }

  OC_DBG("successfully generated ECDSA keypair for device %zd", device);

  return 0;
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

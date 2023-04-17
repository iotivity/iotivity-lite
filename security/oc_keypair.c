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

#include "oc_config.h"

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "oc_keypair_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_api.h"
#include "oc_certs.h"
#include "oc_store.h"
#include "security/oc_entropy_internal.h"

#include <assert.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>

OC_MEMB(g_oc_keypairs_s, oc_ecdsa_keypair_t, OC_MAX_NUM_DEVICES);
OC_LIST(g_oc_keypairs);

oc_ecdsa_keypair_t *
oc_sec_ecdsa_get_keypair(size_t device)
{
  oc_ecdsa_keypair_t *kp = (oc_ecdsa_keypair_t *)oc_list_head(g_oc_keypairs);
  while (kp != NULL) {
    if (kp->device == device) {
      return kp;
    }
    kp = kp->next;
  }
  return NULL;
}

size_t
oc_sec_ecdsa_count_keypairs(void)
{
  return (size_t)oc_list_length(g_oc_keypairs);
}

void
oc_sec_ecdsa_free_keypairs(void)
{
  oc_ecdsa_keypair_t *kp = (oc_ecdsa_keypair_t *)oc_list_pop(g_oc_keypairs);
  while (kp) {
    oc_memb_free(&g_oc_keypairs_s, kp);
    kp = (oc_ecdsa_keypair_t *)oc_list_pop(g_oc_keypairs);
  }
}

static oc_ecdsa_keypair_t *
ecdsa_allocate_keypair(void)
{
  oc_ecdsa_keypair_t *kp = oc_memb_alloc(&g_oc_keypairs_s);
  if (kp == NULL) {
    OC_ERR("cannot allocate keypair");
    return NULL;
  }
  return kp;
}

static void
ecdsa_add_keypair(oc_ecdsa_keypair_t *kp, size_t device)
{
  assert(oc_sec_ecdsa_get_keypair(device) == NULL);
  kp->device = device;
  oc_list_add(g_oc_keypairs, kp);
}

bool
oc_sec_ecdsa_decode_keypair(const oc_rep_t *rep, oc_ecdsa_keypair_t *kp)
{
#define PROP_PUBLIC_KEY "public_key"
#define PROP_PRIVATE_KEY "private_key"
#define STR_LEN(x) (sizeof(x) - 1)

  const uint8_t *public_key = NULL;
  size_t public_key_size = 0;
  const uint8_t *private_key = NULL;
  size_t private_key_size = 0;
  for (; rep != NULL; rep = rep->next) {
    if (rep->type != OC_REP_BYTE_STRING) {
      continue;
    }

    if (oc_rep_is_property(rep, PROP_PUBLIC_KEY, STR_LEN(PROP_PUBLIC_KEY))) {
      if (oc_string_len(rep->value.string) > OC_ECDSA_PUBKEY_SIZE) {
        OC_ERR("decode ecp keypair: invalid public key");
        return false;
      }
      public_key = oc_cast(rep->value.string, uint8_t);
      public_key_size = oc_string_len(rep->value.string);
      continue;
    }

    if (oc_rep_is_property(rep, PROP_PRIVATE_KEY, STR_LEN(PROP_PRIVATE_KEY))) {
      if (oc_string_len(rep->value.string) > OC_ECDSA_PRIVKEY_SIZE) {
        OC_ERR("decode ecp keypair: invalid private key");
        return false;
      }
      private_key = oc_cast(rep->value.string, uint8_t);
      private_key_size = oc_string_len(rep->value.string);
      continue;
    }
  }

  if (public_key == NULL) {
    OC_ERR("decode ecp keypair: valid public key not found");
    return false;
  }
  if (private_key == NULL) {
    OC_ERR("decode ecp keypair: valid private key not found");
    return false;
  }

  kp->public_key_size = public_key_size;
  memcpy(kp->public_key, public_key, public_key_size);
  kp->private_key_size = private_key_size;
  memcpy(kp->private_key, private_key, private_key_size);
  return true;
}

bool
oc_sec_ecdsa_encode_keypair(const oc_ecdsa_keypair_t *kp)
{
  oc_rep_start_root_object();
  oc_rep_set_byte_string(root, public_key, kp->public_key, kp->public_key_size);
  oc_rep_set_byte_string(root, private_key, kp->private_key,
                         kp->private_key_size);
  oc_rep_end_root_object();

  if (g_err != 0) {
    OC_ERR("encode ecp keypair: error %d", (int)g_err);
    return false;
  }
  return true;
}

bool
oc_sec_ecdsa_decode_keypair_for_device(const oc_rep_t *rep, size_t device)
{
  oc_ecdsa_keypair_t *kp = oc_sec_ecdsa_get_keypair(device);
  bool exists = kp != NULL;
  if (!exists) {
    kp = ecdsa_allocate_keypair();
    if (kp == NULL) {
      return false;
    }
  }
  if (!oc_sec_ecdsa_decode_keypair(rep, kp)) {
    oc_memb_free(&g_oc_keypairs_s, kp);
    return false;
  }

  if (!exists) {
    ecdsa_add_keypair(kp, device);
  }
  return true;
}

bool
oc_sec_ecdsa_encode_keypair_for_device(size_t device)
{
  const oc_ecdsa_keypair_t *kp = oc_sec_ecdsa_get_keypair(device);
  if (kp == NULL) {
    return false;
  }

  return oc_sec_ecdsa_encode_keypair(kp);
}

int
oc_sec_ecdsa_generate_keypair(mbedtls_ecp_group_id grpid, uint8_t *public_key,
                              size_t public_key_buf_size,
                              size_t *public_key_size, uint8_t *private_key,
                              size_t private_key_buf_size,
                              size_t *private_key_size)
{
  mbedtls_pk_context pk;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_pk_init(&pk);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

  size_t pk_size = 0;
  size_t pk_priv_size = 0;

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
    OC_ERR("error initializing mbedtls pk context: %d", ret);
    goto generate_ecdsa_keypair_error;
  }

  ret = mbedtls_ecp_gen_key(grpid, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random,
                            &ctr_drbg);
  if (ret < 0) {
    OC_ERR("error in ECDSA key generation: %d", ret);
    goto generate_ecdsa_keypair_error;
  }

  ret = mbedtls_pk_write_key_der(&pk, private_key, private_key_buf_size);
  if (ret < 0) {
    OC_ERR("error writing EC private key to internal structure: %d", ret);
    goto generate_ecdsa_keypair_error;
  }
  pk_priv_size = (size_t)ret;

  ret = mbedtls_pk_write_pubkey_der(&pk, public_key, public_key_buf_size);
  if (ret < 0) {
    OC_ERR("error writing EC public key to internal structure: %d", ret);
    goto generate_ecdsa_keypair_error;
  }
  pk_size = (size_t)ret;

  *private_key_size = pk_priv_size;
  memmove(private_key, private_key + private_key_buf_size - pk_priv_size,
          pk_priv_size);
  *public_key_size = pk_size;
  memmove(public_key, public_key + public_key_buf_size - pk_size, pk_size);

  OC_DBG(
    "successfully generated private key (size=%zu) and public key(size=%zu)",
    pk_priv_size, pk_size);

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

bool
oc_sec_ecdsa_generate_keypair_for_device(mbedtls_ecp_group_id grpid,
                                         size_t device)
{
  oc_ecdsa_keypair_t *kp = oc_sec_ecdsa_get_keypair(device);
  bool exists = kp != NULL;
  if (!exists) {
    kp = ecdsa_allocate_keypair();
    if (kp == NULL) {
      return false;
    }
  }

  if (oc_sec_ecdsa_generate_keypair(
        grpid, kp->public_key, OC_ECDSA_PUBKEY_SIZE, &kp->public_key_size,
        kp->private_key, OC_ECDSA_PRIVKEY_SIZE, &kp->private_key_size) < 0) {
    oc_memb_free(&g_oc_keypairs_s, kp);
    return false;
  }

  if (!exists) {
    ecdsa_add_keypair(kp, device);
  }
  OC_DBG("successfully generated ECDSA keypair for device %zd", device);
  return true;
}

#endif /* OC_SECURITY && OC_PKI */

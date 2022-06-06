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

#if defined(OC_SECURITY) && defined(OC_OSCORE)

#include "oc_oscore_crypto.h"
#include "mbedtls/ccm.h"
#include "mbedtls/md.h"
#include "messaging/coap/oscore_constants.h"
#include "oc_rep.h"
#include "port/oc_log.h"

#define HMAC_SHA256_HASHLEN (32)
#define HKDF_OUTPUT_MAXLEN (512)

static int
HMAC_SHA256(const uint8_t *key, uint8_t key_len, const uint8_t *data,
            uint8_t data_len, uint8_t *hmac)
{
  memset(hmac, 0, HMAC_SHA256_HASHLEN);

  mbedtls_md_context_t hmac_SHA256;
  mbedtls_md_init(&hmac_SHA256);
  int ret = 0;
  if ((ret = mbedtls_md_setup(
         &hmac_SHA256, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1)) != 0) {
    OC_ERR("failed to setup message-digest context for HMAC computation: %d",
           ret);
    goto finish;
  }

  if ((ret = mbedtls_md_hmac_starts(&hmac_SHA256, key, key_len)) != 0) {
    OC_ERR("failed to start the HMAC computation: %d", ret);
    goto finish;
  }
  if ((ret = mbedtls_md_hmac_update(&hmac_SHA256, data, data_len)) != 0) {
    OC_ERR("failed to compute HMAC: %d", ret);
    goto finish;
  }
  if ((ret = mbedtls_md_hmac_finish(&hmac_SHA256, hmac)) != 0) {
    OC_ERR("failed to finish the HMAC computation: %d", ret);
    goto finish;
  }

finish:
  mbedtls_md_free(&hmac_SHA256);
  return ret;
}

static int
HKDF_Extract(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm,
             uint8_t ikm_len, uint8_t *prk_buffer)
{
  /* From RFC 5869
   *    HKDF-Extract(salt, IKM) -> PRK, where
   *       PRK = HMAC-Hash(salt, IKM)
   */
  uint8_t zeroes[32];
  memset(zeroes, 0, 32);

  if (salt == NULL || salt_len == 0) {
    /* if salt not provided, it is set to a string of HashLen zeros. */
    return HMAC_SHA256(zeroes, 32, ikm, ikm_len, prk_buffer);
  }
  return HMAC_SHA256(salt, salt_len, ikm, ikm_len, prk_buffer);
}

static int
HKDF_Expand(const uint8_t *prk, const uint8_t *info, uint8_t info_len,
            uint8_t *okm, size_t okm_len)
{
  /* From RFC 5869
   *    HKDF-Expand(PRK, info, L) -> OKM
   */
  if (okm_len > HKDF_OUTPUT_MAXLEN) {
    return -1;
  }

  /* Number of iterations: N = ceil(L/HashLen) */
  int N = (okm_len + HMAC_SHA256_HASHLEN - 1) / HMAC_SHA256_HASHLEN;

  /* Iteration buffer:
   *  T(i) = HMAC-Hash(PRK, T(i - 1) | info | hex(i)), where
   *  T(0) = empty string (zero length)
   *  len(PRK) = HMAC_SHA256_HASHLEN
   *  len(info) = <Maximum length of 'info' array in RFC 8613, Section 3.2.1
   */
  uint8_t iter_buffer[HMAC_SHA256_HASHLEN + OSCORE_INFO_MAX_LEN + 1];

  /* Buffer to hold the output of all iterations:
   *  T = T(1) | T(2) | T(3) | ... | T(N)
   */
  uint8_t okm_buffer[HKDF_OUTPUT_MAXLEN];

  /* Iteration T(1) */
  memcpy(iter_buffer, info, info_len);
  iter_buffer[info_len] = 0x01;
  /* HMAC_SHA256() returns an output of size HMAC_SHA256_HASHLEN */
  HMAC_SHA256(prk, HMAC_SHA256_HASHLEN, iter_buffer, info_len + 1,
              &(okm_buffer[0]));

  /* Iterations T(2)...T(N) */
  uint8_t i;
  for (i = 1; i < N; i++) {
    memcpy(iter_buffer, &okm_buffer[(i - 1) * HMAC_SHA256_HASHLEN],
           HMAC_SHA256_HASHLEN);
    memcpy(&iter_buffer[HMAC_SHA256_HASHLEN], info, info_len);
    iter_buffer[HMAC_SHA256_HASHLEN + info_len] = i + 1;
    HMAC_SHA256(prk, HMAC_SHA256_HASHLEN, iter_buffer,
                HMAC_SHA256_HASHLEN + info_len + 1,
                &okm_buffer[i * HMAC_SHA256_HASHLEN]);
  }

  memcpy(okm, okm_buffer, okm_len);

  return 0;
}

int
HKDF_SHA256(const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm,
            uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm,
            uint8_t okm_len)
{
  uint8_t PRK[HMAC_SHA256_HASHLEN];
  if (HKDF_Extract(salt, salt_len, ikm, ikm_len, PRK) != 0) {
    return -1;
  }
  if (HKDF_Expand(PRK, info, info_len, okm, okm_len) != 0) {
    return -1;
  }
  return 0;
}

void
oc_oscore_AEAD_nonce(uint8_t *id, uint8_t id_len, uint8_t *piv, uint8_t piv_len,
                     uint8_t *civ, uint8_t *nonce, uint8_t nonce_len)
{
  OC_DBG("### computing AEAD nonce ###");
  OC_DBG("Sender ID:");
  OC_LOGbytes(id, id_len);
  OC_DBG("Partial IV:");
  OC_LOGbytes(piv, piv_len);
  OC_DBG("Common IV:");
  OC_LOGbytes(civ, OSCORE_COMMON_IV_LEN);
  /*
         <- nonce length minus 6 B -> <-- 5 bytes -->
    +---+-------------------+--------+---------+-----+
    | S |      padding      | ID_PIV | padding | PIV |----+
    +---+-------------------+--------+---------+-----+    |
                                                          |
    <---------------- nonce length ---------------->      |
    +------------------------------------------------+    |
    |                   Common IV                    |->(XOR)
    +------------------------------------------------+    |
                                                          |
    <---------------- nonce length ---------------->      |
    +------------------------------------------------+    |
    |                     Nonce                      |<---+
    +------------------------------------------------+
  */
  memset(nonce, 0, nonce_len);
  /* Set (up-to) the last 5 bytes to the Partial IV */
  memcpy(nonce + (nonce_len - piv_len), piv, piv_len);
  /* Set (up-to) nonce length - 6 bytes to the Sender ID */
  memcpy(nonce + (nonce_len - 5 - id_len), id, id_len);
  /* Set the 1st byte to the size of the Sender ID */
  nonce[0] = (uint8_t)id_len;
  /* XOR with the Common IV */
  for (int i = 0; i < nonce_len; i++) {
    nonce[i] = nonce[i] ^ civ[i];
  }
}

int
oc_oscore_compose_AAD(uint8_t *kid, uint8_t kid_len, uint8_t *piv,
                      uint8_t piv_len, uint8_t *AAD, uint8_t *AAD_len)
{
  uint8_t aad_array[OSCORE_AAD_MAX_LEN];

  CborEncoder e, a, alg;
  CborError err = CborNoError;

  /* Compose aad_array... From RFC 8613 Section 5.4:

     aad_array = [
     oscore_version : uint,
     algorithms : [ alg_aead : int / tstr ],
     request_kid : bstr,
     request_piv : bstr,
     options : bstr,
   ]
  */
  cbor_encoder_init(&e, aad_array, OSCORE_AAD_MAX_LEN, 0);
  /* Array of 5 elements */
  err |= cbor_encoder_create_array(&e, &a, 5);
  /* oscore_version: 1 */
  err |= cbor_encode_uint(&a, 0x01);
  /* algorithms: contains only alg_aead (10) */
  err |= cbor_encoder_create_array(&a, &alg, 1);
  err |= cbor_encode_int(&alg, 10);
  err |= cbor_encoder_close_container(&a, &alg);
  /* request_kid: set in requests */
  err |= cbor_encode_byte_string(&a, kid, kid_len);
  /* request_piv: set in requests and notification responses */
  err |= cbor_encode_byte_string(&a, piv, piv_len);
  /* options: Class I options, none defined */
  err |= cbor_encode_byte_string(&a, NULL, 0);
  err |= cbor_encoder_close_container(&e, &a);

  if (err != CborNoError) {
    return -1;
  }

  size_t aad_array_len = cbor_encoder_get_buffer_size(&e, aad_array);

  /* Compose AAD:
       AAD = Enc_structure = [ "Encrypt0", h'', external_aad ]
     where external_aad = bstr .cbor aad_array
  */
  cbor_encoder_init(&e, AAD, OSCORE_AAD_MAX_LEN, 0);
  /* Array of 3 elements */
  err |= cbor_encoder_create_array(&e, &a, 3);
  /* "Encrypt0" for a COSE_Encrypt0 message */
  err |= cbor_encode_text_string(&a, "Encrypt0", 8);
  /* No protected arrtibutes: so empty map (RFC 8152 Section 5.3) */
  err |= cbor_encode_byte_string(&a, NULL, 0);
  /* external_aad: encode aad_array as a bstr */
  err |= cbor_encode_byte_string(&a, aad_array, aad_array_len);
  err |= cbor_encoder_close_container(&e, &a);

  if (err != CborNoError) {
    return -1;
  }

  *AAD_len = cbor_encoder_get_buffer_size(&e, AAD);

  return 0;
}

int
oc_oscore_encrypt(uint8_t *plaintext, size_t plaintext_len, size_t tag_len,
                  uint8_t *key, size_t key_len, uint8_t *nonce,
                  size_t nonce_len, uint8_t *AAD, size_t AAD_len,
                  uint8_t *output)
{
  mbedtls_ccm_context ccm;
  mbedtls_ccm_init(&ccm);
  mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);

  int ret = mbedtls_ccm_encrypt_and_tag(&ccm, plaintext_len, nonce, nonce_len,
                                        AAD, AAD_len, plaintext, output,
                                        plaintext + plaintext_len, tag_len);

  if (ret != 0) {
    OC_ERR("***error encrypting OSCORE plaintext: mbedtls (%d)***", ret);
  }

  mbedtls_ccm_free(&ccm);
  return ret;
}

int
oc_oscore_decrypt(uint8_t *ciphertext, size_t ciphertext_len, size_t tag_len,
                  uint8_t *key, size_t key_len, uint8_t *nonce,
                  size_t nonce_len, uint8_t *AAD, size_t AAD_len,
                  uint8_t *output)
{
  mbedtls_ccm_context ccm;
  mbedtls_ccm_init(&ccm);
  mbedtls_ccm_setkey(&ccm, MBEDTLS_CIPHER_ID_AES, key, key_len * 8);

  int ret = mbedtls_ccm_auth_decrypt(
    &ccm, ciphertext_len - tag_len, nonce, nonce_len, AAD, AAD_len, ciphertext,
    output, ciphertext + ciphertext_len - tag_len, tag_len);

  if (ret != 0) {
    OC_ERR("***error decrypting/verifying response: mbedtls (%d)***", ret);
  }

  mbedtls_ccm_free(&ccm);
  return ret;
}

#else  /* OC_SECURITY && OC_OSCORE */
typedef int dummy_declaration;
#endif /* !OC_SECURITY && !OC_OSCORE */

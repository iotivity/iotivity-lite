/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
 *               2018-2019 Intel Corporation
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

#include "oc_csr.h"
#include "api/oc_core_res_internal.h"
#include "oc_api.h"
#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_csr_internal.h"
#include "security/oc_entropy_internal.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_pki_internal.h"
#include "security/oc_tls_internal.h"

#include <assert.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_csr.h>

static bool
csr_init_pk_context(size_t device, mbedtls_pk_context *pk)
{
  const oc_ecdsa_keypair_t *kp = oc_sec_ecdsa_get_keypair(device);
  if (kp == NULL) {
    OC_ERR("could not find public/private key pair on device %zd", device);
    return false;
  }
  int ret =
    mbedtls_pk_parse_public_key(pk, kp->public_key, kp->public_key_size);
  if (ret != 0) {
    OC_ERR("could not parse public key for device %zd", device);
    return false;
  }

  ret = oc_mbedtls_pk_parse_key(
    device, pk, kp->private_key, kp->private_key_size, 0, 0,
    mbedtls_ctr_drbg_random, oc_tls_ctr_drbg_context());
  if (ret != 0) {
    OC_ERR("could not parse private key for device %zd %d", device, ret);
    return false;
  }
  return true;
}

static bool
csr_init_pk_context_with_reset(size_t device, mbedtls_pk_context *pk)
{
  assert(pk != NULL);

  OC_DBG("oc_csr: init pk context");
  mbedtls_pk_init(pk);
  if (csr_init_pk_context(device, pk)) {
    return true;
  }

  OC_DBG("oc_csr: init pk context, reset keypair");
  mbedtls_pk_free(pk);
  mbedtls_pk_init(pk);
  OC_DBG(
    "could not load keypair for device %zd - try to regenerating the new one",
    device);
  if (oc_sec_ecdsa_reset_keypair(device, true) == 0 &&
      csr_init_pk_context(device, pk)) {
    return true;
  }
  mbedtls_pk_free(pk);
  return false;
}

int
oc_sec_csr_generate(size_t device, mbedtls_md_type_t md, unsigned char *csr,
                    size_t csr_size)
{
  assert(csr != NULL);

  const oc_uuid_t *uuid = oc_core_get_device_id(device);
  if (uuid == NULL) {
    OC_ERR("could not obtain UUID for device %zd", device);
    return -1;
  }

  char subject[50];
  if (!oc_certs_encode_CN_with_UUID(uuid, subject, sizeof(subject))) {
    return -1;
  }

  mbedtls_pk_context pk;
  if (!csr_init_pk_context_with_reset(device, &pk)) {
    return -1;
  }

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

  mbedtls_x509write_csr request;
  memset(&request, 0, sizeof(mbedtls_x509write_csr));

#define PERSONALIZATION_DATA "IoTivity-Lite-CSR-Generation"

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char *)PERSONALIZATION_DATA,
                                  sizeof(PERSONALIZATION_DATA));

#undef PERSONALIZATION_DATA

  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto generate_csr_error;
  }

  mbedtls_x509write_csr_init(&request);
  mbedtls_x509write_csr_set_md_alg(&request, md);
  mbedtls_x509write_csr_set_key(&request, &pk);

  ret = mbedtls_x509write_csr_set_subject_name(&request, subject);
  if (ret != 0) {
    OC_ERR("could not write subject name into CSR for device %zd %d", device,
           ret);
    goto generate_csr_error;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_x509write_csr_pem(&request, csr, csr_size,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret != 0) {
    OC_ERR("could not write CSR for device %zd into buffer %d", device, ret);
    goto generate_csr_error;
  }

  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_x509write_csr_free(&request);

  OC_DBG("successfully generated CSR for device %zd", device);

  return ret;

generate_csr_error:
  mbedtls_pk_free(&pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_x509write_csr_free(&request);

  return -1;
}

/**
 * @brief Verify CSR signature
 *
 * @param csr parsed CSR to check (cannot be NULL)
 * @param md_flags bitmask of allowed signatures (if 0 then signature is not
 * checked)
 * @return true on success
 * @return false on failure
 */
static bool
oc_sec_csr_verify_signature(mbedtls_x509_csr *csr, unsigned md_flags)
{
  if (md_flags == 0) {
    OC_DBG("signature verification disabled");
    return true;
  }

  if ((MBEDTLS_X509_ID_FLAG(csr->sig_md) & md_flags) == 0) {
    OC_ERR("unallowed signature MD type(%d)", (int)csr->sig_md);
    return false;
  }

  if (csr->sig.len == 0 || csr->sig.p == NULL || csr->cri.len == 0 ||
      csr->cri.p == NULL) {
    OC_ERR("invalid input CSR");
    return false;
  }
  unsigned char cri[MBEDTLS_MD_MAX_SIZE];
  int ret = mbedtls_md(mbedtls_md_info_from_type(csr->sig_md), csr->cri.p,
                       csr->cri.len, cri);
  if (ret < 0) {
    OC_ERR("unable to get hash CertificationRequestInfo in CSR %d", ret);
    return false;
  }
  ret =
    mbedtls_pk_verify(&csr->pk, csr->sig_md, cri, 0, csr->sig.p, csr->sig.len);
  if (ret < 0) {
    OC_ERR("unable to verify signature in CSR %d", ret);
    return false;
  }
  return true;
}

bool
oc_sec_csr_validate(mbedtls_x509_csr *csr, mbedtls_pk_type_t pk_type,
                    unsigned md_flags)
{
  assert(csr != NULL);
  mbedtls_pk_type_t pk = mbedtls_pk_get_type(&csr->pk);
  if (pk != pk_type) {
    OC_ERR("invalid public key type(%d) in CSR", (int)pk);
    return false;
  }

  return oc_sec_csr_verify_signature(csr, md_flags);
}

int
oc_sec_csr_extract_subject_DN(const mbedtls_x509_csr *csr, char *buffer,
                              size_t buffer_size)
{
  assert(csr != NULL);
  int ret = mbedtls_x509_dn_gets(buffer, buffer_size, &csr->subject);
  if (ret < 0) {
    OC_ERR("unable to retrieve subject from CSR %d", ret);
    return -1;
  }
  return ret;
}

int
oc_sec_csr_extract_public_key(const mbedtls_x509_csr *csr, uint8_t *buffer,
                              size_t buffer_size)
{
  assert(csr != NULL);
  int ret = oc_mbedtls_pk_write_pubkey_der(&csr->pk, buffer, buffer_size);
  if (ret < 0) {
    OC_ERR("unable to read public key from CSR %d", ret);
    return -1;
  }

  if (ret > 0) {
    // mbedtls_pk_write_pubkey_der writes the key at the end of the buffer, we
    // move it to the beginning
    memmove(buffer, buffer + buffer_size - ret, ret);
  }
  return ret;
}

static void
csr_resource_get(oc_request_t *request, oc_interface_mask_t iface_mask,
                 void *data)
{
  (void)data;

  size_t device = request->resource->device;
  unsigned char csr[512] = { 0 };
  int ret = oc_sec_csr_generate(device, oc_sec_certs_md_signature_algorithm(),
                                csr, sizeof(csr));
  if (ret != 0) {
    oc_send_response_with_callback(request, OC_STATUS_INTERNAL_SERVER_ERROR,
                                   true);
    return;
  }

  oc_rep_start_root_object();
  if ((iface_mask & OC_IF_BASELINE) != 0) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_CSR, device));
  }
  oc_rep_set_text_string(root, csr, (const char *)csr);
  oc_rep_set_text_string(root, encoding, OC_ENCODING_PEM_STR);
  oc_rep_end_root_object();

  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

void
oc_sec_csr_create_resource(size_t device)
{
  oc_core_populate_resource(
    OCF_SEC_CSR, device, OCF_SEC_CSR_URI, OC_IF_RW | OC_IF_BASELINE, OC_IF_RW,
    OC_DISCOVERABLE | OC_SECURE, csr_resource_get, /*put*/ NULL, /*post*/ NULL,
    /*delete*/ NULL, 1, OCF_SEC_CSR_RT);
}

#endif /* OC_SECURITY && OC_PKI */

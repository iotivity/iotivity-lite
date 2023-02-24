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
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "security/oc_certs_internal.h"
#include "security/oc_csr_internal.h"
#include "security/oc_entropy_internal.h"
#include "security/oc_keypair.h"
#include "security/oc_tls.h"

#include <assert.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_csr.h>

int
oc_sec_csr_generate(size_t device, mbedtls_md_type_t md, unsigned char *csr,
                    size_t csr_size)
{
  assert(csr != NULL);
  const oc_ecdsa_keypair_t *kp = oc_sec_get_ecdsa_keypair(device);
  if (kp == NULL) {
    OC_ERR("could not find public/private key pair on device %zd", device);
    return -1;
  }

  const oc_uuid_t *uuid = oc_core_get_device_id(device);
  if (uuid == NULL) {
    OC_ERR("could not obtain UUID for device %zd", device);
    return -1;
  }

  char subject[50];
  if (!oc_certs_encode_CN_with_UUID(uuid, subject, sizeof(subject))) {
    return -1;
  }

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  int ret =
    mbedtls_pk_parse_public_key(&pk, kp->public_key, OC_ECDSA_PUBKEY_SIZE);
  if (ret != 0) {
    OC_ERR("could not parse public key for device %zd", device);
    goto generate_csr_error;
  }

  ret = mbedtls_pk_parse_key(&pk, kp->private_key, kp->private_key_size, 0, 0,
                             mbedtls_ctr_drbg_random, &g_oc_ctr_drbg_ctx);
  if (ret != 0) {
    OC_ERR("could not parse private key for device %zd %d", device, ret);
    goto generate_csr_error;
  }

#define PERSONALIZATION_DATA "IoTivity-Lite-CSR-Generation"

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)PERSONALIZATION_DATA,
                              sizeof(PERSONALIZATION_DATA));

#undef PERSONALIZATION_DATA

  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto generate_csr_error;
  }

  mbedtls_x509write_csr request;
  memset(&request, 0, sizeof(mbedtls_x509write_csr));
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

bool
oc_sec_csr_verify_signature(mbedtls_x509_csr *csr, int md_flags)
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
    OC_ERR("unable to hash CertificationRequestInfo in CSR %d", ret);
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

int
oc_sec_csr_validate(const unsigned char *csr, size_t csr_len,
                    mbedtls_pk_type_t pk_type, int md_flags,
                    oc_string_t *subject_DN, uint8_t *public_key,
                    size_t public_key_size)
{
  assert(csr != NULL);
  mbedtls_x509_csr c;
  int ret = mbedtls_x509_csr_parse(&c, csr, csr_len);
  if (ret < 0) {
    OC_ERR("unable to parse CSR %d", ret);
    return -1;
  }

  mbedtls_pk_type_t pk = mbedtls_pk_get_type(&c.pk);
  if (pk != pk_type) {
    OC_ERR("invalid public key type(%d) in CSR", (int)pk);
    ret = -1;
    goto exit_csr;
  }

  if (!oc_sec_csr_verify_signature(&c, md_flags)) {
    ret = -1;
    goto exit_csr;
  }

  if (subject_DN != NULL) {
    char DN[512];
    ret = mbedtls_x509_dn_gets(DN, sizeof(DN), &c.subject);
    if (ret < 0) {
      OC_ERR("unable to retrieve subject from CSR %d", ret);
      goto exit_csr;
    }
    oc_new_string(subject_DN, DN, ret);
  }

  if (public_key != NULL) {
    ret = mbedtls_pk_write_pubkey_der(&c.pk, public_key, public_key_size);
    if (ret < 0) {
      OC_ERR("unable to read public key from CSR %d", ret);
      goto exit_csr;
    }
  }

exit_csr:
  mbedtls_x509_csr_free(&c);
  if (ret < 0) {
    OC_ERR("received invalid or non-compliant CSR");
    oc_free_string(subject_DN);
    return -1;
  }

  return 0;
}

void
get_csr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;

  size_t device = request->resource->device;
  unsigned char csr[512];
  int ret = oc_sec_csr_generate(device, oc_certs_signature_md_algorithm(), csr,
                                sizeof(csr));
  if (ret != 0) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }

  oc_rep_start_root_object();
  if ((iface_mask & OC_IF_BASELINE) != 0) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_CSR, device));
  }
  oc_rep_set_text_string(root, csr, (const char *)csr);
  oc_rep_set_text_string(root, encoding, "oic.sec.encoding.pem");
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
}

#endif /* OC_SECURITY && OC_PKI */

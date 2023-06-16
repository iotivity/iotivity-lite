/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
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

#ifndef OC_DYNAMIC_ALLOCATION
#error "ERROR: Please rebuild with OC_DYNAMIC_ALLOCATION"
#endif /* !OC_DYNAMIC_ALLOCATION */

#include "oc_store.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_generate_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_obt_internal.h"
#include "util/oc_secure_string_internal.h"

#define OC_OBT_CERTS_SERIAL_NUMBER_SIZE (20)

// 12/31/2029 23:59:59
#define OC_OBT_CERTS_NOT_AFTER_RFC3339 "2029-12-31T23:59:59Z"
// 12/31/2029 23:59:59 to seconds since epoch
#define OC_OBT_CERTS_NOT_AFTER (1893455999)

int
oc_obt_generate_self_signed_root_cert_pem(
  oc_obt_generate_root_cert_data_t cert_data, unsigned char *buffer,
  size_t buffer_size)
{
#define PERSONALIZATION_DATA "IoTivity-Lite-Self-Signed-Cert"
  oc_certs_generate_t root_cert = {
    .personalization_string = { (const uint8_t *)PERSONALIZATION_DATA,
                                sizeof(PERSONALIZATION_DATA) },
    .serial_number_size = OC_OBT_CERTS_SERIAL_NUMBER_SIZE,
    /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
    .validity = { .not_before = oc_certs_timestamp_now(),
                  .not_after = { OC_OBT_CERTS_NOT_AFTER, 0, 0 } },
    .subject = {
      .name = cert_data.subject_name,
      .public_key = { cert_data.public_key, cert_data.public_key_size },
      .private_key = { cert_data.private_key, cert_data.private_key_size },
    },
    .key_usage = { .key_usage = MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN |
             MBEDTLS_X509_KU_DIGITAL_SIGNATURE },
    .signature_md = cert_data.signature_md_alg,
    .is_CA = true,
  };
#undef PERSONALIZATION_DATA
  return oc_certs_generate(&root_cert, buffer, buffer_size);
}

int
oc_obt_generate_self_signed_root_cert(
  oc_obt_generate_root_cert_data_t cert_data, size_t device)
{
  unsigned char cert_pem[4096];
  if (oc_obt_generate_self_signed_root_cert_pem(cert_data, cert_pem,
                                                sizeof(cert_pem)) < 0) {
    return -1;
  }

  oc_sec_encoded_data_t privatedata = { NULL, 0, 0 };
  oc_sec_encoded_data_t publicdata = {
    cert_pem, oc_strnlen((const char *)cert_pem, sizeof(cert_pem)),
    OC_ENCODING_PEM
  };
  int ret = oc_sec_add_new_cred(
    device, false, NULL, -1, OC_CREDTYPE_CERT, OC_CREDUSAGE_TRUSTCA, "*",
    privatedata, publicdata, oc_string_view2(NULL), oc_string_view2(NULL),
    oc_string_view2(NULL), NULL);

  if (ret == -1) {
    OC_ERR("could not write root cert into /oic/sec/cred");
    return -1;
  }

  oc_sec_dump_cred(device);
  return ret;
}

int
oc_obt_generate_identity_cert_pem(
  oc_obt_generate_identity_cert_data_t cert_data, unsigned char *buffer,
  size_t buffer_size)
{
#define PERSONALIZATION_DATA "IoTivity-Lite-Identity-Cert"
  /* extendedKeyUsage: serverAuthentication, clientAuthentication, Identity
   * certificate */
  const unsigned char extendedKeyUsage[] = {
    MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED, /* SEQUENCE OF.. Tag */
    0x20,                                             /* Length of Sequence */
    MBEDTLS_ASN1_OID,                                 /* OID Tag */
    0x08, /* Length of serverAuthentication OID */
    0x2B,
    0x06,
    0x01,
    0x05,
    0x05,
    0x07,
    0x03,
    0x01,             /* OID: 1.3.6.1.5.5.7.3.1 */
    MBEDTLS_ASN1_OID, /* OID Tag */
    0x08,             /* Length of clientAuthentication OID */
    0x2B,
    0x06,
    0x01,
    0x05,
    0x05,
    0x07,
    0x03,
    0x02,             /* OID: 1.3.6.1.5.5.7.3.2 */
    MBEDTLS_ASN1_OID, /* OID Tag */
    0x0A,             /* Length of Identity certificate OID */
    0x2B,
    0x06,
    0x01,
    0x04,
    0x01,
    0x82,
    0xDE,
    0x7C,
    0x01,
    0x06 /* OID: 1.3.6.1.4.1.44924.1.6 */
  };

  oc_certs_key_usage_t key_usage = {
    .key_usage =
      MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT,
    .extended_key_usage = { extendedKeyUsage, sizeof(extendedKeyUsage) },
  };

  oc_certs_generate_t identity_cert = {
    .personalization_string = { (const uint8_t *)PERSONALIZATION_DATA,
                                sizeof(PERSONALIZATION_DATA) },
    .serial_number_size = OC_OBT_CERTS_SERIAL_NUMBER_SIZE,
    /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
    .validity = { .not_before = oc_certs_timestamp_now(),
                  .not_after = { OC_OBT_CERTS_NOT_AFTER, 0, 0 } },
    .subject = { .name = cert_data.subject_name,
                 .public_key = { cert_data.public_key,
                                 cert_data.public_key_size } },
    .issuer = { .name = cert_data.issuer_name,
                .private_key = { cert_data.issuer_private_key,
                                 cert_data.issuer_private_key_size } },
    .key_usage = key_usage,
    .signature_md = cert_data.signature_md_alg,
  };
#undef PERSONALIZATION_DATA

  return oc_certs_generate(&identity_cert, buffer, buffer_size);
}

int
oc_obt_generate_role_cert_pem(oc_obt_generate_role_cert_data_t cert_data,
                              unsigned char *buffer, size_t buffer_size)

{
  if (cert_data.roles == NULL) {
    OC_ERR("did not provide roles");
    return -1;
  }

#define PERSONALIZATION_DATA "IoTivity-Lite-Role-Cert"

  /* extendedKeyUsage: serverAuthentication, clientAuthentication, Role
   * certificate */
  const unsigned char extendedKeyUsage[] = {
    MBEDTLS_ASN1_SEQUENCE | MBEDTLS_ASN1_CONSTRUCTED, /* SEQUENCE OF.. Tag */
    0x20,                                             /* Length of Sequence */
    MBEDTLS_ASN1_OID,                                 /* OID Tag */
    0x08, /* Length of serverAuthentication OID */
    0x2B,
    0x06,
    0x01,
    0x05,
    0x05,
    0x07,
    0x03,
    0x01,             /* OID: 1.3.6.1.5.5.7.3.1 */
    MBEDTLS_ASN1_OID, /* OID Tag */
    0x08,             /* Length of clientAuthentication OID */
    0x2B,
    0x06,
    0x01,
    0x05,
    0x05,
    0x07,
    0x03,
    0x02,             /* OID: 1.3.6.1.5.5.7.3.2 */
    MBEDTLS_ASN1_OID, /* OID Tag */
    0x0A,             /* Length of Role certificate OID */
    0x2B,
    0x06,
    0x01,
    0x04,
    0x01,
    0x82,
    0xDE,
    0x7C,
    0x01,
    0x07 /* OID: 1.3.6.1.4.1.44924.1.7 */
  };

  oc_certs_key_usage_t key_usage = {
    /* keyUsage: digitalSignature (0) and keyAgreement(4) */
    .key_usage =
      MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT,
    .extended_key_usage = { extendedKeyUsage, sizeof(extendedKeyUsage) },
  };

  oc_certs_generate_t role_cert = {
    .personalization_string = { (const uint8_t *)PERSONALIZATION_DATA,
                                sizeof(PERSONALIZATION_DATA) },
    .serial_number_size = OC_OBT_CERTS_SERIAL_NUMBER_SIZE,
    /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
    .validity = { .not_before = oc_certs_timestamp_now(),
                  .not_after = { OC_OBT_CERTS_NOT_AFTER, 0, 0 } },
    .subject = { .name = cert_data.subject_name,
                 .public_key = { cert_data.public_key,
                                 cert_data.public_key_size } },
    .issuer = { .name = cert_data.issuer_name,
                .private_key = { cert_data.issuer_private_key,
                                 cert_data.issuer_private_key_size } },
    .key_usage = key_usage,
    .signature_md = cert_data.signature_md_alg,
    .roles = cert_data.roles,
  };
#undef PERSONALIZATION_DATA

  return oc_certs_generate(&role_cert, buffer, buffer_size);
}

#endif /* OC_SECURITY && OC_PKI */

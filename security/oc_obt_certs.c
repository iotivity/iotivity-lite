/*
// Copyright (c) 2019 Intel Corporation
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
#ifndef OC_DYNAMIC_ALLOCATION
#error "ERROR: Please rebuild with OC_DYNAMIC_ALLOCATION"
#endif /* !OC_DYNAMIC_ALLOCATION */
#ifdef OC_PKI
#include "api/c-timestamp/timestamp.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "oc_obt.h"
#include "security/oc_certs.h"
#include "security/oc_keypair.h"
#include "security/oc_obt_internal.h"
#include "security/oc_store.h"

int oc_obt_generate_role_cert(oc_role_t *roles, const char *subject_name,
                              const uint8_t *subject_public_key,
                              const size_t subject_public_key_size,
                              const char *issuer_name,
                              const uint8_t *issuer_private_key,
                              const size_t issuer_private_key_size,
                              oc_string_t *role_cert) {
  int ret = 0;

  if (!roles || !role_cert) {
    OC_ERR("did not provide roleId or output parameter");
    return -1;
  }

  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_pk_context subject_pub_key;
  mbedtls_pk_init(&subject_pub_key);

  mbedtls_pk_context issuer_priv_key;
  mbedtls_pk_init(&issuer_priv_key);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_x509_general_names *general_names = NULL, *next_name = NULL;

#define PERSONALIZATION_DATA "IoTivity-Lite-Role-Cert"
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const uint8_t *)PERSONALIZATION_DATA,
                              sizeof(PERSONALIZATION_DATA));
#undef PERSONALIZATION_DATA
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_pk_parse_public_key(&subject_pub_key, subject_public_key,
                                    subject_public_key_size);
  if (ret < 0) {
    OC_ERR("error parsing subject's public key %d", ret);
    goto exit;
  }

  ret = mbedtls_pk_parse_key(&issuer_priv_key, issuer_private_key,
                             issuer_private_key_size, 0, 0);
  if (ret < 0) {
    OC_ERR("error parsing issuer's private key %d", ret);
    goto exit;
  }

  /* SerialNumber */
  ret = oc_certs_generate_serial_number(&cert);
  if (ret < 0) {
    OC_ERR("error generating serial number for role cert");
    goto exit;
  }

  /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
  timestamp_t now_t = {0};
  oc_clock_time_t now = oc_clock_time();
  now_t.sec = (int64_t)(now / OC_CLOCK_SECOND);
  now_t.nsec = 0;
  struct tm now_tm;
  memset(&now_tm, 0, sizeof(struct tm));
  timestamp_to_tm_utc(&now_t, &now_tm);
  char now_str[15];
  snprintf(now_str, 15, "%d%02d%02d%02d%02d%02d", now_tm.tm_year + 1900,
           now_tm.tm_mon + 1, now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min,
           now_tm.tm_sec);
  ret = mbedtls_x509write_crt_set_validity(&cert, now_str, "20291231235959");
  if (ret < 0) {
    OC_ERR("error writing role cert validity %d", ret);
    goto exit;
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
  /* Subject */
  ret = mbedtls_x509write_crt_set_subject_name(&cert, subject_name);
  if (ret < 0) {
    OC_ERR("error writing role cert subject name %d", ret);
    goto exit;
  }
  /* Issuer */
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, issuer_name);
  if (ret < 0) {
    OC_ERR("error writing role cert issuer name %d", ret);
    goto exit;
  }
  /* Subject Public Key Info: id-ecPublicKey, secp256r1 */
  mbedtls_x509write_crt_set_subject_key(&cert, &subject_pub_key);
  /* Issuer Private Key */
  mbedtls_x509write_crt_set_issuer_key(&cert, &issuer_priv_key);
  /* basicConstraints: cA = FALSE, pathLenConstraint = not present */
  ret = mbedtls_x509write_crt_set_basic_constraints(&cert, 0, 0);
  if (ret < 0) {
    OC_ERR("error writing role cert basicConstraints %d", ret);
    goto exit;
  }
  /* keyUsage: digitalSignature (0) and keyAgreement(4) */
  ret = mbedtls_x509write_crt_set_key_usage(
      &cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT);
  if (ret < 0) {
    OC_ERR("error writing role cert keyUsage %d", ret);
    goto exit;
  }

  /* subjectAlternativeName */
  while (roles) {
    /* The Common Name (CN) component contains the Role */
    /* The Organizational Unit (OU) component contains the Authority */
    char roleid[512];
    ret = snprintf(roleid, 512, "CN=%s", oc_string(roles->role));
    if (oc_string_len(roles->authority) > 0) {
      ret = snprintf(roleid + ret, 512 - ret, ",OU=%s",
                     oc_string(roles->authority));
    }
    /* A RoleId is encoded in a GeneralName that is of type directoryName into
     * the GeneralNames SEQUEENCE.
     */
    next_name = (mbedtls_x509_general_names *)calloc(
        1, sizeof(mbedtls_x509_general_names));
    if (next_name) {
      next_name->general_name.name_type =
          MBEDTLS_X509_GENERALNAME_DIRECTORYNAME;
      ret = mbedtls_x509_string_to_names(
          &next_name->general_name.name.directory_name, roleid);
      if (ret < 0) {
        OC_ERR("error writing roleid to GeneralName %d", ret);
        goto exit;
      }
    } else {
      OC_ERR("error allocating memory for GeneralName");
      goto exit;
    }

    if (general_names) {
      general_names->next = next_name;
    } else {
      general_names = next_name;
    }
    roles = roles->next;
  }

  next_name = NULL;

  /* The subjectAlternativeName extension is populated with the GeneralNames
   * SEQUENCE containing
   * the Role.
   */
  ret = mbedtls_x509write_crt_set_subject_alt_names(&cert, general_names);
  if (ret < 0) {
    OC_ERR("error writing subjectAlternativeName to cert %d", ret);
    goto exit;
  }
  /* extendedKeyUsage: serverAuthentication , clientAuthentication, Role
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

  ret = mbedtls_x509write_crt_set_extension(
      &cert, MBEDTLS_OID_EXTENDED_KEY_USAGE,
      MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE), 0, extendedKeyUsage,
      sizeof(extendedKeyUsage));
  if (ret < 0) {
    OC_ERR("error writing extendedKeyUsage to cert %d", ret);
    goto exit;
  }

  char cert_pem[4096];
  ret = mbedtls_x509write_crt_pem(&cert, (uint8_t *)cert_pem, 4096,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret == 0) {
    oc_new_string(role_cert, cert_pem, strlen(cert_pem));
  } else if (ret < 0) {
    OC_ERR("error serializing role cert into PEM");
  }

exit:
  if (next_name) {
    mbedtls_asn1_free_named_data_list(
        &next_name->general_name.name.directory_name);
    free(next_name);
  }
  while (general_names) {
    next_name = general_names->next;
    mbedtls_asn1_free_named_data_list(
        &general_names->general_name.name.directory_name);
    free(general_names);
    general_names = next_name;
  }
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&subject_pub_key);
  mbedtls_pk_free(&issuer_priv_key);
  mbedtls_x509write_crt_free(&cert);
  if (ret < 0) {
    OC_ERR("error generating role cert");
    return -1;
  }
  return 0;
}

int oc_obt_generate_identity_cert(const char *subject_name,
                                  const uint8_t *subject_public_key,
                                  const size_t subject_public_key_size,
                                  const char *issuer_name,
                                  const uint8_t *issuer_private_key,
                                  const size_t issuer_private_key_size,
                                  oc_string_t *id_cert) {
  int ret = 0;

  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_pk_context subject_pub_key;
  mbedtls_pk_init(&subject_pub_key);

  mbedtls_pk_context issuer_priv_key;
  mbedtls_pk_init(&issuer_priv_key);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

#define PERSONALIZATION_DATA "IoTivity-Lite-Identity-Cert"
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const uint8_t *)PERSONALIZATION_DATA,
                              sizeof(PERSONALIZATION_DATA));
#undef PERSONALIZATION_DATA
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_pk_parse_public_key(&subject_pub_key, subject_public_key,
                                    subject_public_key_size);
  if (ret < 0) {
    OC_ERR("error parsing subject's public key %d", ret);
    goto exit;
  }

  ret = mbedtls_pk_parse_key(&issuer_priv_key, issuer_private_key,
                             issuer_private_key_size, 0, 0);
  if (ret < 0) {
    OC_ERR("error parsing issuer's private key %d", ret);
    goto exit;
  }

  /* SerialNumber */
  ret = oc_certs_generate_serial_number(&cert);
  if (ret < 0) {
    OC_ERR("error generating serial number for identity cert");
    goto exit;
  }

  /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
  timestamp_t now_t = {0};
  oc_clock_time_t now = oc_clock_time();
  now_t.sec = (int64_t)(now / OC_CLOCK_SECOND);
  now_t.nsec = 0;
  struct tm now_tm;
  memset(&now_tm, 0, sizeof(struct tm));
  timestamp_to_tm_utc(&now_t, &now_tm);
  char now_str[15];
  snprintf(now_str, 15, "%d%02d%02d%02d%02d%02d", now_tm.tm_year + 1900,
           now_tm.tm_mon + 1, now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min,
           now_tm.tm_sec);
  ret = mbedtls_x509write_crt_set_validity(&cert, now_str, "20291231235959");
  if (ret < 0) {
    OC_ERR("error writing identity cert validity %d", ret);
    goto exit;
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
  /* Subject */
  ret = mbedtls_x509write_crt_set_subject_name(&cert, subject_name);
  if (ret < 0) {
    OC_ERR("error writing identity cert subject name %d", ret);
    goto exit;
  }
  /* Issuer */
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, issuer_name);
  if (ret < 0) {
    OC_ERR("error writing identity cert issuer name %d", ret);
    goto exit;
  }
  /* Subject Public Key Info: id-ecPublicKey, secp256r1 */
  mbedtls_x509write_crt_set_subject_key(&cert, &subject_pub_key);
  /* Issuer Private Key */
  mbedtls_x509write_crt_set_issuer_key(&cert, &issuer_priv_key);
  /* basicConstraints: cA = FALSE, pathLenConstraint = not present */
  ret = mbedtls_x509write_crt_set_basic_constraints(&cert, 0, 0);
  if (ret < 0) {
    OC_ERR("error writing identity cert basicConstraints %d", ret);
    goto exit;
  }
  /* keyUsage: digitalSignature (0) and keyAgreement(4) */
  ret = mbedtls_x509write_crt_set_key_usage(
      &cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT);
  if (ret < 0) {
    OC_ERR("error writing identity cert keyUsage %d", ret);
    goto exit;
  }
  /* extendedKeyUsage: serverAuthentication , clientAuthentication, Identity
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

  ret = mbedtls_x509write_crt_set_extension(
      &cert, MBEDTLS_OID_EXTENDED_KEY_USAGE,
      MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE), 0, extendedKeyUsage,
      sizeof(extendedKeyUsage));
  if (ret < 0) {
    OC_ERR("could not write extendedKeyUsage into cert %d", ret);
    goto exit;
  }

  char cert_pem[4096];
  ret = mbedtls_x509write_crt_pem(&cert, (uint8_t *)cert_pem, 4096,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret < 0) {
    OC_ERR("error serializing identity cert into PEM %d", ret);
    goto exit;
  }

  if (id_cert) {
    oc_new_string(id_cert, cert_pem, strlen(cert_pem));
  } else {
    /* Self-provision identity cert */
    ret = oc_sec_add_new_cred(0, false, NULL, -1, OC_CREDTYPE_CERT,
                              OC_CREDUSAGE_IDENTITY_CERT, "*", 0, 0, NULL,
                              OC_ENCODING_PEM, strlen(cert_pem),
                              (uint8_t *)cert_pem, NULL, NULL);

    if (ret == -1) {
      OC_ERR("error writing own identity cert into /oic/sec/cred");
    } else {
      oc_sec_dump_cred(0);
    }
  }
exit:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&subject_pub_key);
  mbedtls_pk_free(&issuer_priv_key);
  mbedtls_x509write_crt_free(&cert);
  if (ret < 0) {
    OC_ERR("error generating identity cert");
  }
  return ret;
}

int oc_obt_generate_self_signed_root_cert(const char *subject_name,
                                          const uint8_t *public_key,
                                          const size_t public_key_size,
                                          const uint8_t *private_key,
                                          const size_t private_key_size) {
  int ret = 0;

  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

#define PERSONALIZATION_DATA "IoTivity-Lite-Self-Signed-Cert"
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const uint8_t *)PERSONALIZATION_DATA,
                              sizeof(PERSONALIZATION_DATA));
#undef PERSONALIZATION_DATA
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_pk_parse_public_key(&pk, public_key, public_key_size);
  if (ret < 0) {
    OC_ERR("error parsing root cert's public key %d", ret);
    goto exit;
  }

  ret = mbedtls_pk_parse_key(&pk, private_key, private_key_size, 0, 0);
  if (ret < 0) {
    OC_ERR("error parsing root cert's private key %d", ret);
    goto exit;
  }

  /* SerialNumber */
  ret = oc_certs_generate_serial_number(&cert);
  if (ret < 0) {
    OC_ERR("error generating serial number for root cert");
    goto exit;
  }

  /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
  timestamp_t now_t = {0};
  oc_clock_time_t now = oc_clock_time();
  now_t.sec = (int64_t)(now / OC_CLOCK_SECOND);
  now_t.nsec = 0;
  struct tm now_tm;
  memset(&now_tm, 0, sizeof(struct tm));
  timestamp_to_tm_utc(&now_t, &now_tm);
  char now_str[15];
  snprintf(now_str, 15, "%d%02d%02d%02d%02d%02d", now_tm.tm_year + 1900,
           now_tm.tm_mon + 1, now_tm.tm_mday, now_tm.tm_hour, now_tm.tm_min,
           now_tm.tm_sec);
  ret = mbedtls_x509write_crt_set_validity(&cert, now_str, "20291231235959");
  if (ret < 0) {
    OC_ERR("error writing root cert validity %d", ret);
    goto exit;
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
  /* Subject */
  ret = mbedtls_x509write_crt_set_subject_name(&cert, subject_name);
  if (ret < 0) {
    OC_ERR("error writing root cert subject name %d", ret);
    goto exit;
  }
  /* Issuer */
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, subject_name);
  if (ret < 0) {
    OC_ERR("error writing root cert issuer name %d", ret);
    goto exit;
  }
  /* Subject Public Key Info: id-ecPublicKey, secp256r1 */
  mbedtls_x509write_crt_set_subject_key(&cert, &pk);
  /* Issuer Private Key */
  mbedtls_x509write_crt_set_issuer_key(&cert, &pk);
  /* basicConstraints: cA = TRUE, pathLenConstraint = unlimited */
  ret = mbedtls_x509write_crt_set_basic_constraints(&cert, 1, -1);
  if (ret < 0) {
    OC_ERR("error writing root cert basicConstraints %d", ret);
    goto exit;
  }
  /* keyUsage: keyCertSign (5), cRLSign and digitalSignature(0) */
  ret = mbedtls_x509write_crt_set_key_usage(
      &cert, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN |
                 MBEDTLS_X509_KU_DIGITAL_SIGNATURE);
  if (ret < 0) {
    OC_ERR("error writing root cert keyUsage %d", ret);
    goto exit;
  }

  char cert_pem[4096];
  ret = mbedtls_x509write_crt_pem(&cert, (uint8_t *)cert_pem, 4096,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret < 0) {
    OC_ERR("error serializing root cert into PEM %d", ret);
    goto exit;
  }

  ret = oc_sec_add_new_cred(
      0, false, NULL, -1, OC_CREDTYPE_CERT, OC_CREDUSAGE_TRUSTCA, "*", 0, 0,
      NULL, OC_ENCODING_PEM, strlen(cert_pem), (uint8_t *)cert_pem, NULL, NULL);

  if (ret == -1) {
    OC_ERR("could not write root cert into /oic/sec/cred");
  } else {
    oc_sec_dump_cred(0);
  }

exit:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_pk_free(&pk);
  mbedtls_x509write_crt_free(&cert);
  if (ret < 0) {
    OC_ERR("error generating self-signed root cert");
  }
  return ret;
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

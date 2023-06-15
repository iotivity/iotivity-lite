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

#include "api/c-timestamp/timestamp.h"
#include "oc_obt.h"
#include "oc_store.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_entropy_internal.h"
#include "security/oc_keypair_internal.h"
#include "security/oc_obt_internal.h"
#include "security/oc_pki_internal.h"
#include "util/oc_secure_string_internal.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>

#define OC_OBT_CERTS_SERIAL_NUMBER_SIZE 20

// 12/31/2029 23:59:59
#define OC_OBT_CERTS_NOT_AFTER_RFC3339 "2029-12-31T23:59:59Z"

/* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
static bool
oc_obt_write_validity(mbedtls_x509write_cert *ctx)
{
  timestamp_t ts = oc_certs_timestamp_now();
  char nb[15] = { 0 };
  if (!oc_certs_timestamp_format(ts, nb, sizeof(nb))) {
    return false;
  }

  memset(&ts, 0, sizeof(ts));
  if (timestamp_parse(OC_OBT_CERTS_NOT_AFTER_RFC3339,
                      sizeof(OC_OBT_CERTS_NOT_AFTER_RFC3339) - 1, &ts) != 0) {
    OC_ERR("cannot parse notAfter timestamp");
    return false;
  }
  char na[15] = { 0 };
  if (!oc_certs_timestamp_format(ts, na, sizeof(na))) {
    return false;
  }

  int ret = mbedtls_x509write_crt_set_validity(ctx, nb, na);
  if (ret < 0) {
    OC_ERR("error writing cert validity %d", ret);
    return false;
  }
  return true;
}

int
oc_obt_generate_self_signed_root_cert_pem(
  oc_obt_generate_root_cert_data_t cert_data, unsigned char *buffer,
  size_t buffer_size)
{
  assert(buffer != NULL);
  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

#define PERSONALIZATION_DATA "IoTivity-Lite-Self-Signed-Cert"
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const uint8_t *)PERSONALIZATION_DATA,
                                  sizeof(PERSONALIZATION_DATA));
#undef PERSONALIZATION_DATA
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_pk_parse_public_key(&pk, cert_data.public_key,
                                    cert_data.public_key_size);
  if (ret < 0) {
    OC_ERR("error parsing root cert's public key %d", ret);
    goto exit;
  }

  ret = oc_mbedtls_pk_parse_key(
    0, &pk, cert_data.private_key, cert_data.private_key_size,
    /*pwd*/ NULL, /*pwd_len*/ 0, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret < 0) {
    OC_ERR("error parsing root cert's private key %d", ret);
    goto exit;
  }

  /* SerialNumber */
  ret = oc_certs_generate_serial_number(&cert, OC_OBT_CERTS_SERIAL_NUMBER_SIZE);
  if (ret < 0) {
    OC_ERR("error generating serial number for root cert");
    goto exit;
  }

  /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
  if (!oc_obt_write_validity(&cert)) {
    OC_ERR("error writing root cert validity");
    goto exit;
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, cert_data.signature_md_alg);
  /* Subject */
  ret = mbedtls_x509write_crt_set_subject_name(&cert, cert_data.subject_name);
  if (ret < 0) {
    OC_ERR("error writing root cert subject name %d", ret);
    goto exit;
  }
  /* Issuer */
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, cert_data.subject_name);
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

  ret = mbedtls_x509write_crt_pem(&cert, buffer, buffer_size,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret < 0) {
    OC_ERR("error serializing root cert into PEM %d", ret);
    goto exit;
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

int
oc_obt_generate_self_signed_root_cert(
  oc_obt_generate_root_cert_data_t cert_data, size_t device)
{

  unsigned char cert_pem[4096];
  if (oc_obt_generate_self_signed_root_cert_pem(cert_data, cert_pem,
                                                sizeof(cert_pem)) < 0) {
    return -1;
  }

  int ret = oc_sec_add_new_cred(
    device, false, NULL, -1, OC_CREDTYPE_CERT, OC_CREDUSAGE_TRUSTCA, "*", 0, 0,
    NULL, OC_ENCODING_PEM, oc_strnlen((const char *)cert_pem, sizeof(cert_pem)),
    cert_pem, NULL, NULL, NULL, NULL);

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
  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_pk_context subject_pub_key;
  mbedtls_pk_init(&subject_pub_key);

  mbedtls_pk_context issuer_priv_key;
  mbedtls_pk_init(&issuer_priv_key);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

#define PERSONALIZATION_DATA "IoTivity-Lite-Identity-Cert"
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const uint8_t *)PERSONALIZATION_DATA,
                                  sizeof(PERSONALIZATION_DATA));
#undef PERSONALIZATION_DATA
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_pk_parse_public_key(&subject_pub_key, cert_data.public_key,
                                    cert_data.public_key_size);
  if (ret < 0) {
    OC_ERR("error parsing subject's public key %d", ret);
    goto exit;
  }

  ret =
    oc_mbedtls_pk_parse_key(0, &issuer_priv_key, cert_data.issuer_private_key,
                            cert_data.issuer_private_key_size, /*pwd*/ NULL,
                            /*pwdlen*/ 0, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret < 0) {
    OC_ERR("error parsing issuer's private key %d", ret);
    goto exit;
  }

  /* SerialNumber */
  ret = oc_certs_generate_serial_number(&cert, OC_OBT_CERTS_SERIAL_NUMBER_SIZE);
  if (ret < 0) {
    OC_ERR("error generating serial number for identity cert");
    goto exit;
  }

  /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
  if (!oc_obt_write_validity(&cert)) {
    OC_ERR("error writing identity cert validity");
    goto exit;
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, cert_data.signature_md_alg);
  /* Subject */
  ret = mbedtls_x509write_crt_set_subject_name(&cert, cert_data.subject_name);
  if (ret < 0) {
    OC_ERR("error writing identity cert subject name %d", ret);
    goto exit;
  }
  /* Issuer */
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, cert_data.issuer_name);
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

  ret = mbedtls_x509write_crt_pem(&cert, buffer, buffer_size,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret < 0) {
    OC_ERR("error serializing identity cert into PEM %d", ret);
    goto exit;
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

void
oc_obt_free_encoded_roles(mbedtls_x509_general_names *general_names)
{
  while (general_names != NULL) {
    mbedtls_x509_general_names *name = general_names->next;
    mbedtls_asn1_free_named_data_list(
      &general_names->general_name.name.directory_name);
    free(general_names);
    general_names = name;
  }
}

static mbedtls_x509_general_names *
oc_obt_encode_role(const oc_role_t *role)
{
  char roleid[512];
  if (!oc_certs_encode_role(role, roleid, sizeof(roleid))) {
    OC_ERR("error encoding roleid");
    return NULL;
  }
  /* A RoleId is encoded in a GeneralName that is of type directoryName into
   * the GeneralNames SEQUEENCE.
   */
  mbedtls_x509_general_names *name =
    (mbedtls_x509_general_names *)calloc(1, sizeof(mbedtls_x509_general_names));
  if (name == NULL) {
    OC_ERR("error allocating memory for GeneralName");
    return NULL;
  }
  name->general_name.name_type = MBEDTLS_X509_GENERALNAME_DIRECTORYNAME;

  int ret = mbedtls_x509_string_to_names(
    &name->general_name.name.directory_name, roleid);
  if (ret < 0) {
    OC_ERR("error writing roleid to GeneralName %d", ret);
    mbedtls_asn1_free_named_data_list(&name->general_name.name.directory_name);
    free(name);
    return NULL;
  }

  return name;
}

int
oc_obt_encode_roles(const oc_role_t *roles,
                    mbedtls_x509_general_names **general_names)
{
  mbedtls_x509_general_names *names = NULL;

  int count = 0;
  while (roles != NULL) {
    mbedtls_x509_general_names *name = oc_obt_encode_role(roles);
    if (name == NULL) {
      oc_obt_free_encoded_roles(names);
      return -1;
    }

    if (names != NULL) {
      names->next = name;
    } else {
      names = name;
    }

    ++count;
    roles = roles->next;
  }

  if (general_names != NULL) {
    *general_names = names;
  }
  return count;
}

static bool
oc_obt_write_roles_to_subject_alt_names(mbedtls_x509write_cert *cert,
                                        const oc_role_t *roles)
{
  mbedtls_x509_general_names *general_names = NULL;
  int ret = oc_obt_encode_roles(roles, &general_names);
  if (ret < 0) {
    return false;
  }

  ret = mbedtls_x509write_crt_set_subject_alt_names(cert, general_names);
  if (ret < 0) {
    OC_ERR("error writing subjectAlternativeName to cert %d", ret);
    oc_obt_free_encoded_roles(general_names);
    return false;
  }

  oc_obt_free_encoded_roles(general_names);
  return true;
}

int
oc_obt_generate_role_cert_pem(oc_obt_generate_role_cert_data_t cert_data,
                              unsigned char *buffer, size_t buffer_size)
{
  assert(buffer != NULL);
  if (cert_data.roles == NULL) {
    OC_ERR("did not provide roles");
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
  oc_entropy_add_source(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

#define PERSONALIZATION_DATA "IoTivity-Lite-Role-Cert"
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const uint8_t *)PERSONALIZATION_DATA,
                                  sizeof(PERSONALIZATION_DATA));
#undef PERSONALIZATION_DATA
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_pk_parse_public_key(&subject_pub_key, cert_data.public_key,
                                    cert_data.public_key_size);
  if (ret < 0) {
    OC_ERR("error parsing subject's public key %d", ret);
    goto exit;
  }

  ret =
    oc_mbedtls_pk_parse_key(0, &issuer_priv_key, cert_data.issuer_private_key,
                            cert_data.issuer_private_key_size, 0, 0,
                            mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret < 0) {
    OC_ERR("error parsing issuer's private key %d", ret);
    goto exit;
  }

  /* SerialNumber */
  ret = oc_certs_generate_serial_number(&cert, OC_OBT_CERTS_SERIAL_NUMBER_SIZE);
  if (ret < 0) {
    OC_ERR("error generating serial number for role cert");
    goto exit;
  }

  /* notBefore and notAfter: [now] to 12/31/2029 23:59:59 */
  if (!oc_obt_write_validity(&cert)) {
    OC_ERR("error writing role cert validity");
    goto exit;
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, cert_data.signature_md_alg);
  /* Subject */
  ret = mbedtls_x509write_crt_set_subject_name(&cert, cert_data.subject_name);
  if (ret < 0) {
    OC_ERR("error writing role cert subject name %d", ret);
    goto exit;
  }
  /* Issuer */
  ret = mbedtls_x509write_crt_set_issuer_name(&cert, cert_data.issuer_name);
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

  /* The subjectAlternativeName extension is populated with the GeneralNames
   * SEQUENCE containing the Role.
   */
  if (!oc_obt_write_roles_to_subject_alt_names(&cert, cert_data.roles)) {
    OC_ERR("error writing role cert subject alt names");
    ret = -1;
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

  ret = mbedtls_x509write_crt_pem(&cert, buffer, buffer_size,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret < 0) {
    OC_ERR("error serializing role cert into PEM");
  }
exit:
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

#endif /* OC_SECURITY && OC_PKI */

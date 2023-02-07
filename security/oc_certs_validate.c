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

#include "oc_certs_validate_internal.h"
#include "port/oc_log.h"

#include <assert.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <string.h>

#define MBEDTLS_ULIMITED_PATHLEN 0

static int
validate_x509v1_fields(const mbedtls_x509_crt *cert, uint32_t *flags)
{
  assert(cert != NULL);
  assert(flags != NULL);

  /* signatureAlgorithm */
  if ((MBEDTLS_X509_ID_FLAG(cert->sig_md) &
       MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256)) == 0) {
    OC_WRN("certificate uses non-compliant signature algorithm");
    return -1;
  }

  /* Version */
  if (cert->version != 3) {
    OC_WRN("non-compliant certificate version (require X.509 v3)");
    return -1;
  }

  /* notBefore */
  if (mbedtls_x509_time_is_future(&cert->valid_from)) {
    OC_WRN("certificate not yet active");
    *flags |= MBEDTLS_X509_BADCERT_FUTURE;
  }

  /* notAfter */
  if (mbedtls_x509_time_is_past(&cert->valid_to)) {
    OC_WRN("certificate has expired");
    *flags |= MBEDTLS_X509_BADCERT_EXPIRED;
  }

  /* Subject Public Key Info */
  /* id-ecPublicKey */
  if ((MBEDTLS_X509_ID_FLAG(cert->sig_pk) &
       MBEDTLS_X509_ID_FLAG(MBEDTLS_PK_ECDSA)) == 0) {
    OC_WRN("certificate uses unsupported public key type");
    return -1;
  }
  /* secp256r1 */
  mbedtls_ecp_group_id gid = mbedtls_pk_ec(cert->pk)->grp.id;
  if ((MBEDTLS_X509_ID_FLAG(gid) &
       MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1)) == 0) {
    OC_WRN("certificate advertises unsupported EC curve");
    return -1;
  }

  return 0;
}

int
oc_certs_validate_non_end_entity_cert(const mbedtls_x509_crt *cert,
                                      bool is_root, bool is_otm, int depth,
                                      uint32_t *flags)
{
  OC_DBG("attempting to validate %s cert", is_root ? "root" : "intermediate");
  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert, flags) < 0) {
    return -1;
  }

  /* Root certificates (and ONLY Root certificates) shall be self-issued */
  bool is_self_issued =
    (cert->issuer_raw.len == cert->subject_raw.len) ||
    memcmp(cert->issuer_raw.p, cert->subject_raw.p, cert->issuer_raw.len) == 0;
  if (is_root && !is_self_issued) {
    OC_WRN("certificate is not a valid root CA");
    return -1;
  }
  if (!is_root && is_self_issued) {
    OC_WRN("certificate is not a valid intermediate CA");
    return -1;
  }

  /* keyCertSign (5) & cRLSign (6) bits SHALL be enabled */
  /* Digital Signature bit may optionally be enabled */
  unsigned int optional_key_usage =
    is_otm ? MBEDTLS_X509_KU_DIGITAL_SIGNATURE
           : MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_CRL_SIGN;
  unsigned int key_usage =
    is_otm ? MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN
           : MBEDTLS_X509_KU_KEY_CERT_SIGN;
  if ((cert->key_usage & key_usage) != key_usage) {
    OC_WRN("key_usage constraints not met");
    return -1;
  }
  if ((cert->key_usage & ~(optional_key_usage | key_usage)) != 0) {
    OC_WRN("key_usage sets additional bits");
    return -1;
  }

  /* cA = TRUE */
  if (cert->ca_istrue == 0) {
    OC_WRN("CA=True constraint is not met");
    return -1;
  }

  /* pathLenConstraint should be at least as long as the signed chain, note that
   * mbedtls max_pathlen = real pathlen + 1 */
  if (cert->max_pathlen != MBEDTLS_ULIMITED_PATHLEN &&
      cert->max_pathlen < depth) {
    OC_WRN("certificate pathLen is not sufficient: %d < %d", cert->max_pathlen,
           depth);
    return -1;
  }

  /* pathLenConstraint = 0 for OTM chains (can only sign end-entity certs) */
  if (is_otm && !is_root && cert->max_pathlen != 1) {
    OC_WRN("only 3-tiered chains are allowed for OTM certificates");
    return -1;
  }

  return 0;
}

int
oc_certs_validate_end_entity_cert(const mbedtls_x509_crt *cert, uint32_t *flags)
{
  OC_DBG("attempting to validate end entity cert");
  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert, flags) < 0) {
    return -1;
  }

  /* digitalSignature (0) and keyAgreement(4) bits SHALL be
   * the only bits enabled.
   */
  unsigned int key_usage =
    (MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT);
  if ((cert->key_usage & key_usage) != key_usage) {
    OC_WRN("key_usage constraints not met");
    return -1;
  }
  if ((cert->key_usage & ~key_usage) != 0) {
    OC_WRN("key_usage sets additional bits");
    return -1;
  }

  /* cA = FALSE and pathLenConstraint = not present */
  if (cert->ca_istrue == 1 || cert->max_pathlen != 0) {
    OC_WRN("CA=False and/or path len constraints not met");
    return -1;
  }

  /* The following extendedKeyUsage (EKU) OID SHALL both be present:
   * serverAuthentication - 1.3.6.1.5.5.7.3.1
   */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, MBEDTLS_OID_SERVER_AUTH,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0) {
    OC_WRN("serverAuthentication OID is absent");
    return -1;
  }

  /* The following extendedKeyUsage (EKU) OID SHALL both be present:
   * clientAuthentication - 1.3.6.1.5.5.7.3.2
   */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, MBEDTLS_OID_CLIENT_AUTH,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH)) != 0) {
    OC_WRN("clientAuthentication OID is absent");
    return -1;
  }

  /* Exactly ONE of the following OIDs SHALL be present:
   * Identity certificate - 1.3.6.1.4.1.44924.1.6
   * Role certificate - 1.3.6.1.4.1.44924.1.7
   */
  const unsigned char identity_cert_oid[] = { 0x2b,             /* 1.3 */
                                              0x06,             /* .6 */
                                              0x01,             /* .1 */
                                              0x04,             /* .4 */
                                              0x01,             /* .1 */
                                              0x82,             /* .44924 */
                                              0xDE, 0x7C, 0x01, /* .1 */
                                              0x06 };           /* .6 */

  const unsigned char role_cert_oid[] = { 0x2b,             /* 1.3 */
                                          0x06,             /* .6 */
                                          0x01,             /* .1 */
                                          0x04,             /* .4 */
                                          0x01,             /* .1 */
                                          0x82,             /* .44924 */
                                          0xDE, 0x7C, 0x01, /* .1 */
                                          0x07 };           /* .7 */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, (const char *)identity_cert_oid, sizeof(identity_cert_oid)) !=
      0) {
    OC_WRN("identity certificate OID is absent");
    return -1;
  }
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, (const char *)role_cert_oid, sizeof(role_cert_oid)) == 0) {
    OC_WRN("role certificate OID present in identity certificate");
    return -1;
  }

  /* End-Entity certificates SHALL NOT contain the anyExtendedKeyUsage
   * OID (2.5.29.37.0)
   */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE)) == 0) {
    OC_WRN("anyExtendedKeyUsage OID present in identity certificate");
    return -1;
  }

  return 0;
}

int
oc_certs_validate_role_cert(const mbedtls_x509_crt *cert, uint32_t *flags)
{
  OC_DBG("attempting to validate role certificate");

  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert, flags) < 0) {
    return -1;
  }

  /* digitalSignature (0) and keyAgreement(4) bits SHALL be
   * the only bits enabled.
   */
  unsigned int key_usage =
    (MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT);
  if ((cert->key_usage & key_usage) != key_usage) {
    OC_WRN("key_usage constraints not met");
    return -1;
  }
  if ((cert->key_usage & ~key_usage) != 0) {
    OC_WRN("key_usage sets additional bits");
    return -1;
  }

  /* cA = FALSE and pathLenConstraint = not present */
  if (cert->ca_istrue == 1 || cert->max_pathlen != 0) {
    OC_WRN("CA=False and/or path len constraints not met");
    return -1;
  }

  /* The following extendedKeyUsage (EKU) OID SHALL both be present:
   * serverAuthentication - 1.3.6.1.5.5.7.3.1
   */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, MBEDTLS_OID_SERVER_AUTH,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH)) != 0) {
    OC_WRN("serverAuthentication OID is absent");
    return -1;
  }

  /* The following extendedKeyUsage (EKU) OID SHALL both be present:
   * clientAuthentication - 1.3.6.1.5.5.7.3.2
   */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, MBEDTLS_OID_CLIENT_AUTH,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_CLIENT_AUTH)) != 0) {
    OC_WRN("clientAuthentication OID is absent");
    return -1;
  }

  /* Exactly ONE of the following OIDs SHALL be present:
   * Identity certificate - 1.3.6.1.4.1.44924.1.6
   * Role certificate - 1.3.6.1.4.1.44924.1.7
   */
  const unsigned char identity_cert_oid[] = { 0x2b,             /* 1.3 */
                                              0x06,             /* .6 */
                                              0x01,             /* .1 */
                                              0x04,             /* .4 */
                                              0x01,             /* .1 */
                                              0x82,             /* .44924 */
                                              0xDE, 0x7C, 0x01, /* .1 */
                                              0x06 };           /* .6 */

  const unsigned char role_cert_oid[] = { 0x2b,             /* 1.3 */
                                          0x06,             /* .6 */
                                          0x01,             /* .1 */
                                          0x04,             /* .4 */
                                          0x01,             /* .1 */
                                          0x82,             /* .44924 */
                                          0xDE, 0x7C, 0x01, /* .1 */
                                          0x07 };           /* .7 */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, (const char *)identity_cert_oid, sizeof(identity_cert_oid)) ==
      0) {
    OC_WRN("identity certificate OID is present in role certificate");
    return -1;
  }
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, (const char *)role_cert_oid, sizeof(role_cert_oid)) != 0) {
    OC_WRN("role certificate OID is absent");
    return -1;
  }

  /* End-Entity certificates SHALL NOT contain the anyExtendedKeyUsage
   * OID (2.5.29.37.0)
   */
  if (mbedtls_x509_crt_check_extended_key_usage(
        cert, MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE,
        MBEDTLS_OID_SIZE(MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE)) == 0) {
    OC_WRN("anyExtendedKeyUsage OID present in identity certificate");
    return -1;
  }

  return 0;
}

#endif /* OC_SECURITY && OC_PKI */

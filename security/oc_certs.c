/*
// Copyright (c) 2018 Intel Corporation
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

#include "oc_certs.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_keypair.h"
#include "security/oc_tls.h"

#define UUID_PREFIX "uuid:"
#define UUID_PREFIX_LEN (5)

int
oc_certs_extract_public_key(const mbedtls_x509_crt *cert, uint8_t *public_key)
{
  return mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)&cert->pk,
                                     public_key, OC_KEYPAIR_PUBKEY_SIZE);
}

int
oc_certs_parse_public_key(const unsigned char *cert, size_t cert_size,
                          uint8_t *public_key)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret < 0) {
    OC_ERR("could not parse the provided cert");
    return -1;
  }

  ret = oc_certs_extract_public_key(&crt, public_key);

  if (ret < 0) {
    mbedtls_x509_crt_free(&crt);
    OC_ERR("could not extract public key from cert");
    return -1;
  }

  mbedtls_x509_crt_free(&crt);

  return ret;
}

int
oc_certs_parse_role_certificate(const unsigned char *role_certificate,
                                size_t cert_size, oc_sec_cred_t *role_cred)
{
  mbedtls_x509_crt *cert = (mbedtls_x509_crt *)role_cred->ctx;

  /* Parse role certificate chain */
  int ret = mbedtls_x509_crt_parse(cert, role_certificate, cert_size);
  if (ret < 0) {
    OC_ERR("could not parse role cert chain");
    return -1;
  }

  if (oc_certs_validate_role_cert(cert) < 0) {
    OC_ERR("role certificate does not meet the necessary constraints");
    return -1;
  }

  /* Verify that the role certificate was signed by a CA */
  uint32_t flags = 0;
  mbedtls_x509_crt *trust_ca = oc_tls_get_trust_anchors();
  ret = mbedtls_x509_crt_verify_with_profile(cert, trust_ca, NULL,
                                             &mbedtls_x509_crt_profile_default,
                                             NULL, &flags, NULL, NULL);
  if (ret != 0 || flags != 0) {
    OC_ERR("error verifying role certificate");
    return -1;
  }

  /* Extract a Role ID from the role certificate's
   * subjectAlternativeName extension and store it inside
   * the "role" and "authority" parameters.
   *
   * For this, inspect the GeneralNames SEQUEENCE.
   */
  for (const mbedtls_x509_general_names *GeneralName = &cert->subject_alt_names;
       GeneralName != NULL; GeneralName = GeneralName->next) {
    bool got_authority = false, got_roleid = false;
    /* A Role is encoded in a GeneralName that is of type directoryName */
    if (GeneralName->general_name.name_type ==
        MBEDTLS_X509_GENERALNAME_DIRECTORYNAME) {
      for (const mbedtls_x509_name *directoryName =
             GeneralName->general_name.name.directory_name;
           directoryName != NULL; directoryName = directoryName->next) {
        /* Look for the Common Name (CN) component in the directoryName */
        if ((directoryName->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) &&
            (memcmp(directoryName->oid.p, MBEDTLS_OID_AT_CN,
                    MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) == 0)) {
          got_roleid = true;
          /* The CN component encodes the Role ID */
          oc_new_string(&role_cred->role.role,
                        (const char *)directoryName->val.p,
                        directoryName->val.len);
        }
        /* Look for an Organizational Unit (OU) component in the directoryName
           */
        else if ((directoryName->oid.len ==
                  MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORG_UNIT)) &&
                 (memcmp(directoryName->oid.p, MBEDTLS_OID_AT_ORG_UNIT,
                         MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORG_UNIT)) == 0)) {
          got_authority = true;
          /* The OU component encodes the authority */
          oc_new_string(&role_cred->role.authority,
                        (const char *)directoryName->val.p,
                        directoryName->val.len);
        }
      }

      if (got_roleid && !got_authority) {
        /* If the OU component was absent in the directoryName, it is assumed
         * that
         * the issuer of this role certificate is the "authority". Accordingly,
         * extract
         * the issuer's name from the issuer's Common Name (CN) component and
         * store it.
         */
        for (const mbedtls_x509_name *Issuer = &cert->issuer; Issuer != NULL;
             Issuer = Issuer->next) {
          if ((Issuer->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) &&
              (memcmp(Issuer->oid.p, MBEDTLS_OID_AT_CN,
                      MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) == 0)) {
            oc_new_string(&role_cred->role.authority,
                          (const char *)Issuer->val.p, Issuer->val.len);
            got_authority = true;
          }
        }
      }

      if (got_roleid && got_authority) {
        OC_DBG("successfully parsed role certificate");
        return 0;
      }
    }
  }

  OC_ERR("invalid role certificate");
  return -1;
}

int
oc_certs_parse_CN_for_UUID(const mbedtls_x509_crt *cert,
                           oc_string_t *subjectuuid)
{
  mbedtls_asn1_named_data *subject =
    (mbedtls_asn1_named_data *)&(cert->subject);

  while (subject) {
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &(subject->oid)) == 0) {
      break;
    }
    subject = subject->next;
  }

  if (!subject) {
    return -1;
  }

  char *uuid = (char *)subject->val.p;

  if (subject->val.len > OC_UUID_LEN - 1) {
    const char *uuid_prefix = strstr(uuid, UUID_PREFIX);
    if (uuid_prefix) {
      if ((subject->val.len - (uuid_prefix - uuid + UUID_PREFIX_LEN)) < 36) {
        return -1;
      }
      uuid = (char *)uuid_prefix + UUID_PREFIX_LEN;
    }
  } else if (subject->val.len < OC_UUID_LEN - 1) {
    return -1;
  }

  oc_alloc_string(subjectuuid, OC_UUID_LEN);
  memcpy(oc_string(*subjectuuid), uuid, OC_UUID_LEN - 1);
  oc_string(*subjectuuid)[OC_UUID_LEN - 1] = '\0';

  return 0;
}

static int
oc_certs_serialize_to_pem(const mbedtls_x509_crt *cert, char *output_buffer,
                          size_t output_buffer_len)
{
#define append_to_output(x)                                                    \
  do {                                                                         \
    output_buffer[j++] = x;                                                    \
    ch++;                                                                      \
    if (ch % 64 == 0) {                                                        \
      output_buffer[j++] = '\r';                                               \
      output_buffer[j++] = '\n';                                               \
    }                                                                          \
  } while (0)

  size_t ch = 0;

  uint8_t alphabet[65] = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                           'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                           'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
                           'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                           'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                           'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
                           '8', '9', '+', '/', '=' };
  uint8_t val = 0;
  size_t i, j = 0;
  size_t input_len = cert->raw.len;
  const uint8_t *input = cert->raw.p;
  size_t output_len = (input_len / 3) * 4;
  if (input_len % 3 != 0) {
    output_len += 4;
  }

  const char *begin = "-----BEGIN CERTIFICATE-----\r\n";
  const char *end = "-----END CERTIFICATE-----\r\n";

  output_len += (output_len + 63) / 64 * 2 + strlen(begin) + strlen(end);

  /* If the output buffer provided was not large enough, return an error. */
  if (output_buffer_len < output_len)
    return -1;

  /* handle the case that an empty input is provided */
  if (input_len == 0) {
    output_buffer[0] = '\0';
  }

  memcpy(output_buffer, begin, strlen(begin));
  j = strlen(begin);

  for (i = 0; i < input_len; i++) {
    if (i % 3 == 0) {
      val = (input[i] >> 2);
      append_to_output(alphabet[val]);
      val = input[i] << 4;
      val &= 0x30;
    } else if (i % 3 == 1) {
      val |= (input[i] >> 4);
      append_to_output(alphabet[val]);
      val = input[i] << 2;
      val &= 0x3D;
    } else {
      val |= (input[i] >> 6);
      append_to_output(alphabet[val]);
      val = input[i] & 0x3F;
      append_to_output(alphabet[val]);
    }
  }

  if (i % 3 != 0) {
    append_to_output(alphabet[val]);
  }

  while (j < (int)output_len - 2 - strlen(end)) {
    output_buffer[j++] = '=';
  }

  output_buffer[j++] = '\r';
  output_buffer[j++] = '\n';

  memcpy(output_buffer + j, end, strlen(end));
  j += strlen(end);
  output_buffer[j] = '\0';

  return (int)j;
}

int
oc_certs_serialize_chain_to_pem(const mbedtls_x509_crt *cert_chain,
                                char *output_buffer, size_t output_buffer_len)
{
  size_t buffer_len = output_buffer_len;
  mbedtls_x509_crt *cert = (mbedtls_x509_crt *)cert_chain;
  while (cert != NULL) {
    if (oc_certs_serialize_to_pem(
          cert, output_buffer + output_buffer_len - buffer_len, buffer_len) ==
        -1) {
      return -1;
    }
    buffer_len -= strlen(output_buffer);
    cert = cert->next;
  }
  return (int)strlen(output_buffer);
}

static int
validate_x509v1_fields(const mbedtls_x509_crt *cert)
{
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
    return -1;
  }

  /* notAfter */
  if (mbedtls_x509_time_is_past(&cert->valid_to)) {
    OC_WRN("certificate has expired");
    return -1;
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
oc_certs_validate_root_cert(const mbedtls_x509_crt *cert)
{
  OC_DBG("attempting to validate root cert");
  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert) < 0) {
    return -1;
  }

  /* Issuer SHALL match the Subject field
   * Subject SHALL match the Issuer field
   */
  if ((cert->issuer_raw.len != cert->subject_raw.len) ||
      memcmp(cert->issuer_raw.p, cert->subject_raw.p, cert->issuer_raw.len) !=
        0) {
    OC_WRN("certificate is not a root CA");
    return -1;
  }

  /* keyCertSign (5) & cRLSign (6) bits SHALL be enabled */
  /* Digital Signature bit may optionally be enabled */
  unsigned int optional_key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
  unsigned int key_usage =
    (MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
  if ((cert->key_usage & key_usage) != key_usage) {
    OC_WRN("key_usage constraints not met");
    return -1;
  }
  if ((cert->key_usage & ~(optional_key_usage | key_usage)) != 0) {
    OC_WRN("key_usage sets additional bits");
    return -1;
  }

  /* cA = TRUE and pathLenConstraint = not present (unlimited) */
  if (cert->ca_istrue == 0 || cert->max_pathlen != 0) {
    OC_WRN("CA=True and/or path len constraints not met");
    return -1;
  }

  return 0;
}

int
oc_certs_validate_intermediate_cert(const mbedtls_x509_crt *cert)
{
  OC_DBG("attempting to validate intermediate cert");
  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert) < 0) {
    return -1;
  }

  if (cert->max_pathlen == 0) {
    OC_WRN("certificate is not an intermediate CA");
    return -1;
  }

  /* Issuer SHALL NOT match the Subject field
   * Subject SHALL NOT match the Issuer field
   */
  if ((cert->issuer_raw.len == cert->subject_raw.len) ||
      memcmp(cert->issuer_raw.p, cert->subject_raw.p, cert->issuer_raw.len) ==
        0) {
    OC_WRN("certificate is not an intermediate CA");
    return -1;
  }

  /* keyCertSign (5) & cRLSign (6) bits SHALL be enabled */
  /* Digital Signature bit may optionally be enabled */
  unsigned int optional_key_usage = MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
  unsigned int key_usage =
    (MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN);
  if ((cert->key_usage & key_usage) != key_usage) {
    OC_WRN("key_usage constraints not met");
    return -1;
  }
  if ((cert->key_usage & ~(optional_key_usage | key_usage)) != 0) {
    OC_WRN("key_usage sets additional bits");
    return -1;
  }

  /* cA = TRUE and pathLenConstraint = 0  (can only sign end-entity certs) */
  if (cert->ca_istrue == 0 || cert->max_pathlen > 1) {
    OC_WRN("CA=True and/or path len constraints not met");
    return -1;
  }

  return 0;
}

int
oc_certs_validate_end_entity_cert(const mbedtls_x509_crt *cert)
{
  OC_DBG("attempting to validate end entity cert");
  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert) < 0) {
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
oc_certs_validate_role_cert(const mbedtls_x509_crt *cert)
{
  OC_DBG("attempting to validate role certificate");

  /* Validate common X.509v1 fields */
  if (validate_x509v1_fields(cert) < 0) {
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

int
oc_certs_is_subject_the_issuer(mbedtls_x509_crt *issuer,
                               mbedtls_x509_crt *child)
{
  if (child->issuer_raw.len == issuer->subject_raw.len &&
      memcmp(child->issuer_raw.p, issuer->subject_raw.p,
             child->issuer_raw.len) == 0) {
    return 0;
  }
  return -1;
}

int
oc_certs_generate_csr(size_t device, unsigned char *csr, size_t csr_len)
{
  oc_ecdsa_keypair_t *kp = oc_sec_get_ecdsa_keypair(device);
  if (!kp) {
    OC_ERR("could not find public/private key pair on device %zd", device);
    return -1;
  }

  oc_uuid_t *uuid = oc_core_get_device_id(device);
  if (!uuid) {
    OC_ERR("could not obtain UUID for device %zd", device);
    return -1;
  }

  char subject[50];
  sprintf(subject, "CN=" UUID_PREFIX);
  oc_uuid_to_str(uuid, subject + UUID_PREFIX_LEN + 3, 37);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  int ret =
    mbedtls_pk_parse_public_key(&pk, kp->public_key, OC_KEYPAIR_PUBKEY_SIZE);
  if (ret != 0) {
    OC_ERR("could not parse public key for device %zd", device);
    goto generate_csr_error;
  }

  ret = mbedtls_pk_parse_key(&pk, kp->private_key, kp->private_key_size, 0, 0);
  if (ret != 0) {
    OC_ERR("could not parse private key for device %zd", device);
    goto generate_csr_error;
  }

#define PERSONALIZATION_DATA "IoTivity-Lite-CSR-Generation"

  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)PERSONALIZATION_DATA,
                              sizeof(PERSONALIZATION_DATA));

#undef PERSONALIZATION_DATA

  if (ret < 0) {
    OC_ERR("error initializing source of entropy");
    goto generate_csr_error;
  }

  mbedtls_x509write_csr request;
  memset(&request, 0, sizeof(mbedtls_x509write_csr));
  mbedtls_x509write_csr_init(&request);
  mbedtls_x509write_csr_set_md_alg(&request, MBEDTLS_MD_SHA256);
  mbedtls_x509write_csr_set_key(&request, &pk);

  ret = mbedtls_x509write_csr_set_subject_name(&request, subject);
  if (ret != 0) {
    OC_ERR("could not write subject name into CSR for device %zd", device);
    goto generate_csr_error;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_x509write_csr_der(&request, csr, csr_len,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret <= 0) {
    OC_ERR("could not write CSR for device %zd into buffer", device);
    goto generate_csr_error;
  }
  memmove(csr, csr + csr_len - ret, ret);

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

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

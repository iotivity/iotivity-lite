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

#include "oc_certs.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#include "port/oc_assert.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_certs_validate_internal.h"
#include "security/oc_entropy_internal.h"
#include "security/oc_pki_internal.h"
#include "security/oc_tls_internal.h"
#include "util/oc_macros.h"

#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>

#include <string.h>

#define UUID_PREFIX "uuid:"
#define UUID_PREFIX_LEN (OC_CHAR_ARRAY_LEN(UUID_PREFIX))
#define CN_UUID_PREFIX "CN=uuid:"
#define CN_UUID_PREFIX_LEN (OC_CHAR_ARRAY_LEN(CN_UUID_PREFIX))

// message digest used for signature of generated certificates or certificate
// signing requests (CSRs)
static mbedtls_md_type_t g_signature_md = MBEDTLS_MD_SHA256;

// allowed message digests signature algorithms
static unsigned g_allowed_mds_mask = MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256);

// groupid of the elliptic curve used for keys in generated certificates or CSRs
static mbedtls_ecp_group_id g_ecp_grpid = MBEDTLS_ECP_DP_SECP256R1;

// allowed groupids of elliptic curves
static unsigned g_allowed_ecp_grpids_mask =
  MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1);

void
oc_sec_certs_default(void)
{
  oc_sec_certs_md_set_signature_algorithm(MBEDTLS_MD_SHA256);
  oc_sec_certs_md_set_algorithms_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_MD_SHA256));
  oc_sec_certs_ecp_set_group_id(MBEDTLS_ECP_DP_SECP256R1);
  oc_sec_certs_ecp_set_group_ids_allowed(
    MBEDTLS_X509_ID_FLAG(MBEDTLS_ECP_DP_SECP256R1));
}

mbedtls_md_type_t
oc_sec_certs_md_signature_algorithm(void)
{
  return g_signature_md;
}

void
oc_sec_certs_md_set_signature_algorithm(mbedtls_md_type_t md)
{
  g_signature_md = md;
  OC_DBG("signature message digest: %d", (int)g_signature_md);
}

void
oc_sec_certs_md_set_algorithms_allowed(unsigned md_mask)
{
  g_allowed_mds_mask = (md_mask & OCF_CERTS_SUPPORTED_MDS);
  OC_DBG("allowed message digests mask: %u", g_allowed_mds_mask);
}

unsigned
oc_sec_certs_md_algorithms_allowed(void)
{
  return g_allowed_mds_mask;
}

bool
oc_sec_certs_md_algorithm_is_allowed(mbedtls_md_type_t md)
{
  return md != MBEDTLS_MD_NONE &&
         (MBEDTLS_X509_ID_FLAG(md) & g_allowed_mds_mask) != 0;
}

void
oc_sec_certs_ecp_set_group_id(mbedtls_ecp_group_id gid)
{
  g_ecp_grpid = gid;
  OC_DBG("elliptic curve groupid: %d", (int)g_ecp_grpid);
}

mbedtls_ecp_group_id
oc_sec_certs_ecp_group_id(void)
{
  return g_ecp_grpid;
}

void
oc_sec_certs_ecp_set_group_ids_allowed(unsigned gid_mask)
{
  g_allowed_ecp_grpids_mask = (gid_mask & OCF_CERTS_SUPPORTED_ELLIPTIC_CURVES);
  OC_DBG("allowed elliptic curve groupids: %u", g_allowed_ecp_grpids_mask);
}

unsigned
oc_sec_certs_ecp_group_ids_allowed(void)
{
  return g_allowed_ecp_grpids_mask;
}

bool
oc_sec_certs_ecp_group_id_is_allowed(mbedtls_ecp_group_id gid)
{
  return gid != MBEDTLS_ECP_DP_NONE &&
         (MBEDTLS_X509_ID_FLAG(gid) & g_allowed_ecp_grpids_mask) != 0;
}

int
oc_certs_generate_serial_number(mbedtls_x509write_cert *crt, size_t size)
{
  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

#define PERSONALIZATION_DATA "IoTivity-Lite-Certificate_Serial_Number"

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  (const unsigned char *)PERSONALIZATION_DATA,
                                  sizeof(PERSONALIZATION_DATA));

#undef PERSONALIZATION_DATA

  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    return -1;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  ret = mbedtls_mpi_fill_random(&crt->serial, size, mbedtls_ctr_drbg_random,
                                &ctr_drbg);

  if (ret < 0) {
    OC_ERR("error generating random serial number for certificate %d", ret);
    return -1;
  }

  return 0;
}

bool
oc_certs_is_PEM(const unsigned char *cert, size_t cert_len)
{
#define PEM_BEGIN "-----BEGIN "
  size_t pem_begin_len = sizeof(PEM_BEGIN) - 1;
  return cert_len > pem_begin_len &&
         memcmp(cert, PEM_BEGIN, pem_begin_len) == 0;
}

int
oc_certs_extract_serial_number(const mbedtls_x509_crt *cert, char *buffer,
                               size_t buffer_size)
{
  return mbedtls_x509_serial_gets(buffer, buffer_size, &cert->serial);
}

int
oc_certs_parse_serial_number(const unsigned char *cert, size_t cert_size,
                             char *buffer, size_t buffer_size)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret != 0) {
    OC_ERR("could not parse the provided cert %d", ret);
    return -1;
  }

  ret = oc_certs_extract_serial_number(&crt, buffer, buffer_size);
  mbedtls_x509_crt_free(&crt);
  return ret;
}

int
oc_certs_extract_private_key(size_t device, const mbedtls_x509_crt *cert,
                             unsigned char *buffer, size_t buffer_size)
{
  int ret = oc_mbedtls_pk_write_key_der(device, &cert->pk, buffer, buffer_size);
  if (ret < 0) {
    OC_ERR("could not extract private key from cert %d", ret);
    return ret;
  }
  if (ret > 0) {
    // mbedtls_pk_write_key_der writes the key at the end of the buffer, we
    // move it to the beginning
    memmove(buffer, buffer + buffer_size - ret, ret);
  }
  return ret;
}

int
oc_certs_parse_private_key(size_t device, const unsigned char *cert,
                           size_t cert_size, unsigned char *buffer,
                           size_t buffer_size)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret != 0) {
    OC_ERR("could not parse the provided cert %d", ret);
    return -1;
  }

  ret = oc_certs_extract_private_key(device, &crt, buffer, buffer_size);
  mbedtls_x509_crt_free(&crt);
  return ret;
}

int
oc_certs_extract_public_key(const mbedtls_x509_crt *cert, unsigned char *buffer,
                            size_t buffer_size)
{
  int ret = oc_mbedtls_pk_write_pubkey_der(&cert->pk, buffer, buffer_size);
  if (ret < 0) {
    OC_ERR("could not extract public key from cert %d", ret);
    return ret;
  }

  if (ret > 0) {
    // mbedtls_pk_write_pubkey_der writes the key at the end of the buffer, we
    // move it to the beginning
    memmove(buffer, buffer + buffer_size - ret, ret);
  }
  return ret;
}

int
oc_certs_extract_public_key_to_oc_string(const mbedtls_x509_crt *cert,
                                         oc_string_t *buffer)
{
#define RSA_PUB_DER_MAX_BYTES (38 + 2 * MBEDTLS_MPI_MAX_SIZE)
#define ECP_PUB_DER_MAX_BYTES (30 + 2 * MBEDTLS_ECP_MAX_BYTES)

  size_t key_size = mbedtls_pk_get_type(&cert->pk) == MBEDTLS_PK_ECKEY
                      ? ECP_PUB_DER_MAX_BYTES
                      : RSA_PUB_DER_MAX_BYTES;
  oc_string_t pk;
  oc_alloc_string(&pk, key_size);
  int ret = oc_certs_extract_public_key(cert, oc_cast(pk, uint8_t), key_size);
  if (ret < 0) {
    oc_free_string(&pk);
    return ret;
  }

  if (ret > 0) {
    oc_alloc_string(buffer, (size_t)ret);
    memcpy(oc_cast(*buffer, uint8_t), oc_cast(pk, uint8_t), (size_t)ret);
  }
  oc_free_string(&pk);
  return ret;
}

int
oc_certs_parse_public_key(const unsigned char *cert, size_t cert_size,
                          unsigned char *buffer, size_t buffer_size)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret != 0) {
    OC_ERR("could not parse the provided cert %d", ret);
    return -1;
  }

  ret = oc_certs_extract_public_key(&crt, buffer, buffer_size);
  mbedtls_x509_crt_free(&crt);
  return ret;
}

int
oc_certs_parse_public_key_to_oc_string(const unsigned char *cert,
                                       size_t cert_size, oc_string_t *buffer)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret != 0) {
    OC_ERR("could not parse the provided cert %d", ret);
    return -1;
  }

  ret = oc_certs_extract_public_key_to_oc_string(&crt, buffer);
  mbedtls_x509_crt_free(&crt);
  return ret;
}

int
oc_certs_parse_role_certificate(const unsigned char *rcert, size_t rcert_size,
                                oc_sec_cred_t *role_cred, bool roles_resource)
{
  mbedtls_x509_crt c;
  mbedtls_x509_crt *cert;
  if (roles_resource) {
    cert = (mbedtls_x509_crt *)role_cred->ctx;
  } else {
    cert = &c;
  }
  mbedtls_x509_crt_init(cert);

  /* Parse role certificate chain */
  int ret = mbedtls_x509_crt_parse(cert, rcert, rcert_size);
  if (ret != 0) {
    OC_ERR("could not parse role cert chain %d", ret);
    goto exit_parse_role_cert;
  }

  uint32_t flags = 0;
  if (oc_certs_validate_role_cert(cert, &flags) < 0 || flags != 0) {
    OC_ERR("role certificate does not meet the necessary constraints");
    goto exit_parse_role_cert;
  }

  /* Verify that the role certificate was signed by a CA */
  mbedtls_x509_crt *trust_ca = oc_tls_get_trust_anchors();
  ret = mbedtls_x509_crt_verify_with_profile(cert, trust_ca, NULL,
                                             &mbedtls_x509_crt_profile_default,
                                             NULL, &flags, NULL, NULL);
  if (ret != 0 || flags != 0) {
    OC_ERR("error verifying role certificate %d", ret);
    goto exit_parse_role_cert;
  }

  /* Extract a Role ID from the role certificate's subjectAlternativeName
   * extension and store it inside the "role" and "authority" parameters.
   *
   * For this, inspect the GeneralNames SEQUENCE.
   */
  if (!oc_certs_extract_first_role(cert, &role_cred->role.role,
                                   &role_cred->role.authority)) {
    OC_ERR("error extracing role and authority from certificate");
    goto exit_parse_role_cert;
  }

  OC_DBG("successfully parsed role certificate");
  if (!roles_resource) {
    mbedtls_x509_crt_free(cert);
  }
  return 0;

exit_parse_role_cert:
  if (!roles_resource) {
    mbedtls_x509_crt_free(cert);
  }
  OC_ERR("invalid role certificate");
  return -1;
}

bool
oc_certs_encode_CN_with_UUID(const oc_uuid_t *uuid, char *buf, size_t buf_len)
{
  if (buf_len < (CN_UUID_PREFIX_LEN + OC_UUID_LEN)) {
    return false;
  }

  int ret = snprintf(buf, buf_len, CN_UUID_PREFIX);
  if (ret < 0 || (size_t)ret >= buf_len) {
    return false;
  }
  oc_uuid_to_str(uuid, buf + CN_UUID_PREFIX_LEN, OC_UUID_LEN);
  return true;
}

static const char *
certs_find_uuid_prefix(const char *haystack, size_t haystack_len)
{
  for (size_t i = 0; i < haystack_len - UUID_PREFIX_LEN + 1; ++i) {
    const char *start = haystack + i;
    if (memcmp(start, UUID_PREFIX, UUID_PREFIX_LEN) == 0) {
      return start;
    }
  }
  return NULL;
}

bool
oc_certs_parse_CN_buffer_for_UUID(mbedtls_asn1_buf val, char *buffer,
                                  size_t buffer_size)
{
  if (buffer_size < OC_UUID_LEN) {
    OC_ERR("buffer too small");
    return false;
  }

  const char *uuid_CN = (const char *)val.p;
  const char *uuid_prefix = NULL;
  if (val.len > UUID_PREFIX_LEN) {
    uuid_prefix = certs_find_uuid_prefix(uuid_CN, val.len);
  }
  size_t uuid_prefix_len = 0;
  if (uuid_prefix != NULL) {
    uuid_prefix_len = (uuid_prefix - uuid_CN) + UUID_PREFIX_LEN;
  }
  if (uuid_prefix_len == 0 ||
      val.len - uuid_prefix_len <
        OC_UUID_LEN - 1) { // -1 because val is not nul-terminated
#if OC_ERR_IS_ENABLED
    oc_string_t cn;
    oc_new_string(&cn, uuid_CN, val.len);
    OC_ERR("invalid Common Name field (tag:%d val:%s)", val.tag, oc_string(cn));
    oc_free_string(&cn);
#endif /* OC_ERR_IS_ENABLED */
    return false;
  }

  memcpy(buffer, val.p + uuid_prefix_len, OC_UUID_LEN - 1);
  buffer[OC_UUID_LEN - 1] = '\0';
  return true;
}

bool
oc_certs_extract_CN_for_UUID(const mbedtls_x509_crt *cert, char *buffer,
                             size_t buffer_size)
{

  const mbedtls_asn1_named_data *subject =
    (mbedtls_asn1_named_data *)&(cert->subject);
  while (subject != NULL) {
    if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &(subject->oid)) == 0) {
      break;
    }
    subject = subject->next;
  }
  if (subject == NULL) {
    OC_ERR("Common Name field not found");
    return false;
  }

  return oc_certs_parse_CN_buffer_for_UUID(subject->val, buffer, buffer_size);
}

bool
oc_certs_parse_CN_for_UUID(const unsigned char *cert, size_t cert_size,
                           char *buffer, size_t buffer_size)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret != 0) {
    OC_ERR("could not parse the provided cert %d", ret);
    return false;
  }

  bool ok = oc_certs_extract_CN_for_UUID(&crt, buffer, buffer_size);
  mbedtls_x509_crt_free(&crt);
  return ok;
}

bool
oc_certs_encode_role(const oc_role_t *role, char *buf, size_t buf_len)
{
  char *buffer = buf;
  size_t length = buf_len;
  int ret = snprintf(buffer, length, "CN=%s", oc_string(role->role));
  if (ret < 0 || (size_t)ret >= length) {
    OC_ERR("could not encode role");
    return false;
  }
  if (oc_string_len(role->authority) == 0) {
    return true;
  }

  buffer = buf + ret;
  length -= ret;
  ret = snprintf(buffer, length, ",OU=%s", oc_string(role->authority));
  if (ret < 0 || (size_t)ret >= length) {
    OC_ERR("could not encode authority");
    return false;
  }
  return true;
}

static bool
oc_certs_DN_is_CN(const mbedtls_x509_name *dn)
{
  return ((dn->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) &&
          (memcmp(dn->oid.p, MBEDTLS_OID_AT_CN,
                  MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) == 0));
}

static bool
oc_certs_DN_is_OU(const mbedtls_x509_name *dn)
{
  return (dn->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORG_UNIT)) &&
         (memcmp(dn->oid.p, MBEDTLS_OID_AT_ORG_UNIT,
                 MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_ORG_UNIT)) == 0);
}

static const mbedtls_x509_name *
oc_certs_CN_extract_issuer(const mbedtls_x509_crt *cert)
{
  for (const mbedtls_x509_name *issuer = &cert->issuer; issuer != NULL;
       issuer = issuer->next) {
    if ((issuer->oid.len == MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) &&
        (memcmp(issuer->oid.p, MBEDTLS_OID_AT_CN,
                MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN)) == 0)) {
      return issuer;
    }
  }
  return NULL;
}

bool
oc_certs_extract_first_role(const mbedtls_x509_crt *cert, oc_string_t *role,
                            oc_string_t *authority)
{
  for (const mbedtls_x509_general_names *san = &cert->subject_alt_names;
       san != NULL; san = san->next) {
    /* A Role is encoded in a GeneralName that is of type directoryName */
    if (san->general_name.name_type != MBEDTLS_X509_GENERALNAME_DIRECTORYNAME) {
      continue;
    }

    const mbedtls_x509_name *dnRole = NULL;
    const mbedtls_x509_name *dnAuthority = NULL;
    for (const mbedtls_x509_name *directoryName =
           san->general_name.name.directory_name;
         directoryName != NULL; directoryName = directoryName->next) {
      /* Look for the Common Name (CN) component in the directoryName */
      if (oc_certs_DN_is_CN(directoryName)) {
        dnRole = directoryName;
      }
      /* Look for an Organizational Unit (OU) component in the directoryName
       */
      else if (oc_certs_DN_is_OU(directoryName)) {
        dnAuthority = directoryName;
      }

      if (dnRole != NULL && dnAuthority != NULL) {
        break;
      }
    }

    if (dnRole == NULL) {
      return false;
    }

    if (dnAuthority == NULL) {
      /* If the OU component was absent in the directoryName, it is assumed
       * that the issuer of this role certificate is the "authority".
       * Accordingly, extract the issuer's name from the issuer's Common Name
       * (CN) component and store it.
       */
      dnAuthority = oc_certs_CN_extract_issuer(cert);
    }

    if (dnAuthority == NULL) {
      return false;
    }

    // both role and authority are set
    oc_new_string(role, (const char *)dnRole->val.p, dnRole->val.len);
    oc_new_string(authority, (const char *)dnAuthority->val.p,
                  dnAuthority->val.len);
    return true;
  }
  return false;
}

bool
oc_certs_parse_first_role(const unsigned char *cert, size_t cert_size,
                          oc_string_t *role, oc_string_t *authority)
{
  mbedtls_x509_crt crt;
  mbedtls_x509_crt_init(&crt);

  int ret = mbedtls_x509_crt_parse(&crt, cert, cert_size);
  if (ret != 0) {
    OC_ERR("could not parse the provided cert %d", ret);
    return false;
  }

  bool ok = oc_certs_extract_first_role(&crt, role, authority);
  mbedtls_x509_crt_free(&crt);
  return ok;
}

timestamp_t
oc_certs_timestamp_now(void)
{
  oc_clock_time_t now = oc_clock_time();
  timestamp_t ts;
  memset(&ts, 0, sizeof(ts));
  ts.sec = (int64_t)(now / OC_CLOCK_SECOND);
  return ts;
}

bool
oc_certs_timestamp_format(timestamp_t ts, char *buffer, size_t buffer_size)
{
  assert(buffer != NULL);

  struct tm now_tm;
  memset(&now_tm, 0, sizeof(struct tm));
  if (timestamp_to_tm_utc(&ts, &now_tm) == NULL) {
    OC_ERR("cannot convert timestamp to string: invalid timestamp");
    return false;
  }

  int ret = snprintf(buffer, buffer_size, "%d%02d%02d%02d%02d%02d",
                     now_tm.tm_year + 1900, now_tm.tm_mon + 1, now_tm.tm_mday,
                     now_tm.tm_hour, now_tm.tm_min, now_tm.tm_sec);
  if (ret < 0 || (size_t)ret >= buffer_size) {
    OC_ERR("cannot convert timestamp to string: buffer too small");
    return false;
  }
  return true;
}

uint64_t
oc_certs_time_to_unix_timestamp(mbedtls_x509_time time)
{
#define MONTHSPERYEAR 12 /* months per calendar year */
  static const int days_offset[MONTHSPERYEAR] = {
    0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334
  };

  int month = time.mon - 1;
  long year = time.year + month / MONTHSPERYEAR;

  long days = (year - 1970) * 365 + days_offset[month % MONTHSPERYEAR];
  // leap years
  days += (year - 1968) / 4;
  days -= (year - 1900) / 100;
  days += (year - 1600) / 400;
  if ((year % 4) == 0 && ((year % 100) != 0 || (year % 400) == 0) &&
      (month % MONTHSPERYEAR) < 2) {
    days--;
  }

  days += time.day - 1;
  uint64_t result = days * 24;
  result += time.hour;
  result *= 60;
  result += time.min;
  result *= 60;
  result += time.sec;
  return result;
}

static int
oc_certs_serialize_to_pem(const mbedtls_x509_crt *cert, char *output_buffer,
                          size_t output_buffer_len)
{
#define NEWLINE "\r\n"
#define NEWLINE_LEN (sizeof(NEWLINE) - 1)

#define append_new_line_to_output                                              \
  do {                                                                         \
    output_buffer[j++] = '\r';                                                 \
    output_buffer[j++] = '\n';                                                 \
  } while (0)

#define append_to_output(x)                                                    \
  do {                                                                         \
    output_buffer[j++] = x;                                                    \
    ch++;                                                                      \
    if (ch % 64 == 0) {                                                        \
      append_new_line_to_output;                                               \
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
  size_t input_len = cert->raw.len;
  const uint8_t *input = cert->raw.p;
  size_t output_len = (input_len / 3) * 4;
  if (input_len % 3 != 0) {
    output_len += 4;
  }

  const char begin_pem[] = "-----BEGIN CERTIFICATE-----" NEWLINE;
  const char end_pem[] = "-----END CERTIFICATE-----" NEWLINE;
#define STR_LEN(x) (sizeof(x) - 1)

  output_len += (output_len + 63) / 64 * NEWLINE_LEN + (STR_LEN(begin_pem)) +
                (STR_LEN(end_pem));

  /* If the output buffer provided was not large enough, return an error. */
  if (output_buffer_len < output_len)
    return -1;

  /* handle the case that an empty input is provided */
  if (input_len == 0) {
    output_buffer[0] = '\0';
  }

  memcpy(output_buffer, begin_pem, STR_LEN(begin_pem));
  size_t j = STR_LEN(begin_pem);

  size_t i = 0;
  for (i = 0; i < input_len; i++) {
    if (i % 3 == 0) {
      val = (input[i] >> 2);
      append_to_output(alphabet[val]);
      val = (uint8_t)(input[i] << 4);
      val &= 0x30;
    } else if (i % 3 == 1) {
      val |= (input[i] >> 4);
      append_to_output(alphabet[val]);
      val = (uint8_t)(input[i] << 2);
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

  while (j < (int)output_len - NEWLINE_LEN - STR_LEN(end_pem)) {
    output_buffer[j++] = '=';
  }

  append_new_line_to_output;

  memcpy(output_buffer + j, end_pem, STR_LEN(end_pem));
  j += STR_LEN(end_pem);
  output_buffer[j] = '\0';

  return (int)j;
}

int
oc_certs_serialize_chain_to_pem(const mbedtls_x509_crt *cert_chain,
                                char *output_buffer, size_t output_buffer_len)
{
  size_t buffer_len = output_buffer_len;
  const mbedtls_x509_crt *cert = cert_chain;
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

int
oc_certs_is_subject_the_issuer(const mbedtls_x509_crt *issuer,
                               const mbedtls_x509_crt *child)
{
  if (child->issuer_raw.len == issuer->subject_raw.len &&
      memcmp(child->issuer_raw.p, issuer->subject_raw.p,
             child->issuer_raw.len) == 0) {
    return 0;
  }
  return -1;
}

#endif /* OC_SECURITY && OC_PKI */

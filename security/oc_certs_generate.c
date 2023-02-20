/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
 *               2019 Intel Corporation
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

#include "oc_certs_generate_internal.h"
#include "api/c-timestamp/timestamp.h"
#include "port/oc_clock.h"
#include "security/oc_entropy_internal.h"

#include <assert.h>
#include <mbedtls/build_info.h>
#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <stdbool.h>

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

timestamp_t
oc_certs_timestamp_now(void)
{
  oc_clock_time_t now = oc_clock_time();
  timestamp_t ts;
  memset(&ts, 0, sizeof(ts));
  ts.sec = (int64_t)(now / OC_CLOCK_SECOND);
  return ts;
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

static bool
certs_validity_is_empty(oc_certs_validity_t validity)
{
  timestamp_t empty = { 0 };
  return timestamp_compare(&empty, &validity.not_before) == 0 &&
         timestamp_compare(&empty, &validity.not_after) == 0;
}

static bool
certs_validity_write(mbedtls_x509write_cert *cert, timestamp_t not_before,
                     timestamp_t not_after)
{
  char nb[15] = { 0 };
  if (!oc_certs_timestamp_format(not_before, nb, sizeof(nb))) {
    return false;
  }

  char na[15] = { 0 };
  if (!oc_certs_timestamp_format(not_after, na, sizeof(na))) {
    return false;
  }

  int ret = mbedtls_x509write_crt_set_validity(cert, nb, na);
  if (ret < 0) {
    OC_ERR("error writing cert validity %d", ret);
    return false;
  }

  OC_DBG("certificate validity not_before:%s not_after:%s", nb, na);
  return true;
}

static int
certs_write_subject_and_issuer(mbedtls_x509write_cert *cert,
                               mbedtls_ctr_drbg_context *ctr_drbg,
                               oc_certs_subject_t subject,
                               mbedtls_pk_context *subject_pk,
                               oc_certs_issuer_t issuer,
                               mbedtls_pk_context *issuer_pk, bool is_CA)
{
  /* Subject */
  OC_DBG("\tadding subject");
  assert(subject.name != NULL);
  int ret = mbedtls_x509write_crt_set_subject_name(cert, subject.name);
  if (ret < 0) {
    OC_ERR("error writing root cert subject name %d", ret);
    return ret;
  }

  assert(subject.public_key.value != NULL);
  ret = mbedtls_pk_parse_public_key(subject_pk, subject.public_key.value,
                                    subject.public_key.size);
  if (ret < 0) {
    OC_ERR("error parsing subjects' public key %d", ret);
    return ret;
  }

  if (is_CA) {
    assert(subject.private_key.value != NULL);

    ret = mbedtls_pk_parse_key(
      subject_pk, subject.private_key.value, subject.private_key.size,
      /*pwd*/ NULL, /*pwd_len*/ 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0) {
      OC_ERR("error parsing subjects' private key %d", ret);
      return ret;
    }
  }
  mbedtls_x509write_crt_set_subject_key(cert, subject_pk);

  /* Issuer */
  OC_DBG("\tadding issuer");
  if (is_CA) {
    ret = mbedtls_x509write_crt_set_issuer_name(cert, subject.name);
    if (ret < 0) {
      OC_ERR("error writing CA certificate issuer name %d", ret);
      return ret;
    }

    mbedtls_x509write_crt_set_issuer_key(cert, subject_pk);
  } else {
    assert(issuer.name != NULL);
    ret = mbedtls_x509write_crt_set_issuer_name(cert, issuer.name);
    if (ret < 0) {
      OC_ERR("error writing certificate issuer name %d", ret);
      return ret;
    }

    assert(issuer.private_key.value != NULL);
    ret = mbedtls_pk_parse_key(
      issuer_pk, issuer.private_key.value, issuer.private_key.size,
      /*pwd*/ NULL, /*pwd_len*/ 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0) {
      OC_ERR("error parsing certificate issuers private key %d", ret);
      return ret;
    }

    mbedtls_x509write_crt_set_issuer_key(cert, issuer_pk);
  }
  return 0;
}

static int
certs_write_key_usage(mbedtls_x509write_cert *cert, oc_certs_key_usage_t ku)
{
  if (ku.key_usage != 0) {
    OC_DBG("\tadding keyUsage");
    int ret = mbedtls_x509write_crt_set_key_usage(cert, ku.key_usage);
    if (ret < 0) {
      OC_ERR("error writing certificate keyUsage: %d", ret);
      return ret;
    }
  }

  if (ku.extended_key_usage.value != NULL) {
    OC_DBG("\tadding extendedKeyUsage");
    int ret = mbedtls_x509write_crt_set_extension(
      cert, MBEDTLS_OID_EXTENDED_KEY_USAGE,
      MBEDTLS_OID_SIZE(MBEDTLS_OID_EXTENDED_KEY_USAGE), 0,
      ku.extended_key_usage.value, ku.extended_key_usage.size);
    if (ret < 0) {
      OC_ERR("error writing certificate extendedKeyUsage: %d", ret);
      return ret;
    }
  }
  return 0;
}

int
oc_certs_generate(oc_certs_generate_t data, unsigned char *buffer,
                  size_t buffer_size)
{
  assert(buffer != NULL);
  OC_DBG("Generating certificate");

  mbedtls_x509write_cert cert;
  mbedtls_x509write_crt_init(&cert);

  mbedtls_entropy_context entropy;
  mbedtls_entropy_init(&entropy);
  oc_entropy_add_source(&entropy);

  mbedtls_ctr_drbg_context ctr_drbg;
  mbedtls_ctr_drbg_init(&ctr_drbg);

  mbedtls_pk_context subject_pk;
  mbedtls_pk_init(&subject_pk);

  mbedtls_pk_context issuer_pk;
  mbedtls_pk_init(&issuer_pk);

  assert(data.personalization_string.value != NULL);
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  data.personalization_string.value,
                                  data.personalization_string.size);
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  if (data.serial_number_size > 0) {
    OC_DBG("\tadding serial number");
    /* SerialNumber */
    ret = oc_certs_generate_serial_number(&cert, data.serial_number_size);
    if (ret < 0) {
      OC_ERR("error generating serial number for root cert");
      goto exit;
    }
  }

  if (!certs_validity_is_empty(data.validity)) {
    if (!certs_validity_write(&cert, data.validity.not_before,
                              data.validity.not_after)) {
      OC_ERR("error writing certificate validity");
      goto exit;
    }
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, data.signature_md);

  if (certs_write_subject_and_issuer(&cert, &ctr_drbg, data.subject,
                                     &subject_pk, data.issuer, &issuer_pk,
                                     data.is_CA) != 0) {
    goto exit;
  }

  int is_CA = data.is_CA ? 1 : 0;
  int max_pathlen = data.is_CA ? -1 : 0; // -1 = unlimited
  /* basicConstraints: cA = TRUE, pathLenConstraint = unlimited */
  ret = mbedtls_x509write_crt_set_basic_constraints(&cert, is_CA, max_pathlen);
  if (ret < 0) {
    OC_ERR("error writing certificate basicConstraints %d", ret);
    goto exit;
  }

  ret = certs_write_key_usage(&cert, data.key_usage);
  if (ret != 0) {
    goto exit;
  }

  ret = mbedtls_x509write_crt_pem(&cert, buffer, buffer_size,
                                  mbedtls_ctr_drbg_random, &ctr_drbg);

  if (ret < 0) {
    OC_ERR("error serializing certificate into PEM %d", ret);
    goto exit;
  }

exit:
  mbedtls_pk_free(&issuer_pk);
  mbedtls_pk_free(&subject_pk);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  mbedtls_x509write_crt_free(&cert);
  return ret;
}

#endif /* OC_SECURITY && OC_PKI */
/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#if defined(OC_SECURITY) && defined(OC_PKI) && defined(OC_DYNAMIC_ALLOCATION)

#include "port/oc_log_internal.h"
#include "security/oc_certs_generate_internal.h"
#include "security/oc_entropy_internal.h"
#include "util/oc_macros_internal.h"

#include <assert.h>
#include <mbedtls/build_info.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/oid.h>

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

static int
certs_validity_write(mbedtls_x509write_cert *cert, timestamp_t not_before,
                     timestamp_t not_after)
{
#define OC_CERTS_TIMESTAMP_BUFFER_SIZE (15)
  char nb[OC_CERTS_TIMESTAMP_BUFFER_SIZE] = { 0 };
  if (!oc_certs_timestamp_format(not_before, nb, OC_ARRAY_SIZE(nb))) {
    return -1;
  }

  char na[OC_CERTS_TIMESTAMP_BUFFER_SIZE] = { 0 };
  if (!oc_certs_timestamp_format(not_after, na, OC_ARRAY_SIZE(na))) {
    return -1;
  }

  int ret = mbedtls_x509write_crt_set_validity(cert, nb, na);
  if (ret < 0) {
    OC_ERR("error writing cert validity %d", ret);
    return ret;
  }

  OC_DBG("certificate validity not_before:%s not_after:%s", nb, na);
  return 0;
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
  assert(subject.name != NULL);
  OC_DBG("\tadding subject(%s)", subject.name);
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
  if (is_CA) {
    // for CA certificates, issuer is the same as subject
    OC_DBG("\tadding CA issuer(%s)", subject.name);

    ret = mbedtls_x509write_crt_set_issuer_name(cert, subject.name);
    if (ret < 0) {
      OC_ERR("error writing CA certificate issuer name %d", ret);
      return ret;
    }
    mbedtls_x509write_crt_set_issuer_key(cert, subject_pk);
  } else {
    assert(issuer.name != NULL);
    OC_DBG("\tadding issuer(%s)", issuer.name);

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

void
oc_certs_free_encoded_roles(mbedtls_x509_general_names *general_names)
{
  while (general_names != NULL) {
    mbedtls_x509_general_names *next = general_names->next;
    mbedtls_asn1_free_named_data_list(
      &general_names->general_name.name.directory_name);
    free(general_names);
    general_names = next;
  }
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

static mbedtls_x509_general_names *
certs_encode_role(const oc_role_t *role)
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
oc_certs_encode_roles(const oc_role_t *roles,
                      mbedtls_x509_general_names **general_names)
{
  mbedtls_x509_general_names *head = NULL;
  mbedtls_x509_general_names *last = NULL;

  int count = 0;
  while (roles != NULL) {
    mbedtls_x509_general_names *name = certs_encode_role(roles);
    if (name == NULL) {
      oc_certs_free_encoded_roles(head);
      return -1;
    }
    OC_DBG("encoding role[%d] (%s:%s)", count, oc_string(roles->role),
           oc_string(roles->authority) != NULL ? oc_string(roles->authority)
                                               : "");

    if (head == NULL) {
      head = name;
    }
    if (last != NULL) {
      last->next = name;
    }
    last = name;

    ++count;
    roles = roles->next;
  }

  *general_names = head;
  return count;
}

static bool
certs_write_roles_to_subject_alt_names(mbedtls_x509write_cert *cert,
                                       const oc_role_t *roles)
{
  mbedtls_x509_general_names *general_names = NULL;
  int ret = oc_certs_encode_roles(roles, &general_names);
  if (ret < 0) {
    return false;
  }

  ret = mbedtls_x509write_crt_set_subject_alt_names(cert, general_names);
  if (ret < 0) {
    OC_ERR("error writing subjectAlternativeName to cert %d", ret);
    oc_certs_free_encoded_roles(general_names);
    return false;
  }

  oc_certs_free_encoded_roles(general_names);
  return true;
}

int
oc_certs_generate(const oc_certs_generate_t *data, unsigned char *buffer,
                  size_t buffer_size)
{
  assert(data != NULL);
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

  assert(data->personalization_string.value != NULL);
  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                  data->personalization_string.value,
                                  data->personalization_string.size);
  if (ret < 0) {
    OC_ERR("error initializing RNG %d", ret);
    goto exit;
  }

  mbedtls_ctr_drbg_set_prediction_resistance(&ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON);

  if (data->serial_number_size > 0) {
    OC_DBG("\tadding serial number");
    /* SerialNumber */
    ret = oc_certs_generate_serial_number(&cert, data->serial_number_size);
    if (ret < 0) {
      goto exit;
    }
  }

  if (!certs_validity_is_empty(data->validity)) {
    ret = certs_validity_write(&cert, data->validity.not_before,
                               data->validity.not_after);
    if (ret < 0) {
      goto exit;
    }
  }

  /* Version: v3 */
  mbedtls_x509write_crt_set_version(&cert, MBEDTLS_X509_CRT_VERSION_3);
  /* signatureAlgorithm: ecdsa-with-SHA256 */
  mbedtls_x509write_crt_set_md_alg(&cert, data->signature_md);

  ret =
    certs_write_subject_and_issuer(&cert, &ctr_drbg, data->subject, &subject_pk,
                                   data->issuer, &issuer_pk, data->is_CA);
  if (ret < 0) {
    goto exit;
  }

  int is_CA = data->is_CA ? 1 : 0;
  int max_pathlen = data->is_CA ? -1 : 0; // -1 = unlimited
  /* basicConstraints: cA = TRUE, pathLenConstraint = unlimited */
  ret = mbedtls_x509write_crt_set_basic_constraints(&cert, is_CA, max_pathlen);
  if (ret < 0) {
    OC_ERR("error writing certificate basicConstraints %d", ret);
    goto exit;
  }

  /* The subjectAlternativeName extension is populated with the GeneralNames
   * SEQUENCE containing the Role. */
  if (data->roles != NULL &&
      !certs_write_roles_to_subject_alt_names(&cert, data->roles)) {
    OC_ERR("error writing role cert subject alt names");
    ret = -1;
    goto exit;
  }

  ret = certs_write_key_usage(&cert, data->key_usage);
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

#endif /* OC_SECURITY && OC_PKI && OC_DYNAMIC_ALLOCATION */

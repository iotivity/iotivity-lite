/*
// Copyright (c) 2018-2019 Intel Corporation
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

#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "oc_certs.h"
#include "oc_cred_internal.h"
#include "oc_store.h"
#include "oc_tls.h"
#include "port/oc_connectivity.h"

static int
pki_add_intermediate_cert(size_t device, int credid, const unsigned char *cert,
                          size_t cert_size)
{
  OC_DBG("attempting to add an intermediate CA certificate");
  int ret = 0;
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *c = oc_list_head(creds->creds);
  for (; c != NULL && c->credid != credid; c = c->next)
    ;

  if (!c) {
    OC_ERR("could not find cred entry for identity cert chain");
    return -1;
  }

  /* Parse the to-be-added intermediate cert */
  size_t c_size = cert_size;
  mbedtls_x509_crt int_ca;
  mbedtls_x509_crt_init(&int_ca);
  if (oc_certs_is_PEM((const unsigned char *)cert, cert_size) != 0) {
    OC_ERR("provided cert is not in PEM format");
    return -1;
  }
  if (cert[cert_size - 1] != '\0') {
    c_size += 1;
  }

  ret = mbedtls_x509_crt_parse(&int_ca, (const unsigned char *)cert, c_size);
  if (ret < 0) {
    OC_ERR("could not parse intermediate cert: %d", ret);
    return -1;
  }
  OC_DBG("parsed intermediate CA cert");

  mbedtls_x509_crt id_cert_chain, *id_cert;
  mbedtls_x509_crt_init(&id_cert_chain);

  /* Parse the identity cert chain */
  ret = mbedtls_x509_crt_parse(
    &id_cert_chain, (const unsigned char *)oc_string(c->publicdata.data),
    oc_string_len(c->publicdata.data) + 1);
  if (ret < 0) {
    OC_ERR("could not parse existing identity cert that chains to this "
           "intermediate cert: %d",
           ret);
    mbedtls_x509_crt_free(&int_ca);
    return -1;
  }
  OC_DBG("parsed identity cert chain");

  id_cert = &id_cert_chain;
  for (; id_cert != NULL; id_cert = id_cert->next) {
    /* If this intermediate cert is already on the chain, return */
    if (id_cert->raw.len == int_ca.raw.len &&
        memcmp(id_cert->raw.p, int_ca.raw.p, int_ca.raw.len) == 0) {
      mbedtls_x509_crt_free(&id_cert_chain);
      mbedtls_x509_crt_free(&int_ca);
      OC_DBG("found intermediate cert in cred with credid %d", credid);
      return 0;
    }

    /* break with the last cert in the identity cert chain */
    if (!id_cert->next) {
      break;
    }
  }

  /* Confirm that the intermediate cert is the issuer of the last cert
   * in the chain, if not return.
   */
  if (oc_certs_is_subject_the_issuer(&int_ca, id_cert) == 0) {
    oc_string_t chain = c->publicdata.data;
    size_t new_publicdata_size = oc_string_len(chain) + c_size;
    oc_alloc_string(&c->publicdata.data, new_publicdata_size);
    memcpy(oc_string(c->publicdata.data), oc_string(chain),
           oc_string_len(chain));
    memcpy(oc_string(c->publicdata.data) + oc_string_len(chain), cert,
           cert_size);
    oc_string(c->publicdata.data)[new_publicdata_size - 1] = '\0';
    oc_free_string(&chain);
    OC_DBG("adding a new intermediate CA cert to /oic/sec/cred");
    oc_sec_dump_cred(device);
    ret = 1;
  } else {
    OC_ERR("supplied intermediate CA cert is not issuer of identity cert");
    ret = -1;
  }

  mbedtls_x509_crt_free(&int_ca);
  mbedtls_x509_crt_free(&id_cert_chain);

  if (ret > 0) {
    OC_DBG("added intermediate CA cert to /oic/sec/cred");
    oc_tls_refresh_identity_certs();
    return credid;
  }
  OC_ERR("could not add intermediate CA cert to /oic/sec/cred");
  return -1;
}

static int
pki_add_identity_cert(size_t device, const unsigned char *cert,
                      size_t cert_size, const unsigned char *key,
                      size_t key_size, oc_sec_credusage_t credusage)
{
  OC_DBG("attempting to add an identity certificate chain");

  size_t c_size = cert_size, k_size = key_size;
  mbedtls_pk_context pkey;
  mbedtls_pk_init(&pkey);

  if (oc_certs_is_PEM(cert, cert_size) != 0) {
    OC_ERR("provided cert is not in PEM format");
    return -1;
  }
  if (cert[cert_size - 1] != '\0') {
    c_size += 1;
  }
  if (oc_certs_is_PEM(key, key_size) == 0) {
    if (key[key_size - 1] != '\0') {
      k_size += 1;
    }
  }

  /* Parse identity cert's private key */
  int ret =
    mbedtls_pk_parse_key(&pkey, (const unsigned char *)key, k_size, NULL, 0);
  if (ret != 0) {
    OC_ERR("could not parse identity cert's private key %d", ret);
    return -1;
  }
  OC_DBG("parsed the provided identity cert's private key");

  /* Serialize identity cert's private key to DER */
  uint8_t privkbuf[200];
  ret = mbedtls_pk_write_key_der(&pkey, privkbuf, 200);

  mbedtls_pk_free(&pkey);

  if (ret < 0) {
    OC_ERR("could not write identity cert's DER encoded private key %d", ret);
    return -1;
  }

  size_t private_key_size = ret;

  mbedtls_x509_crt cert1, cert2;
  mbedtls_x509_crt_init(&cert1);

  /* Parse identity cert chain */
  ret = mbedtls_x509_crt_parse(&cert1, (const unsigned char *)cert, c_size);
  if (ret < 0) {
    OC_ERR("could not parse the provided identity cert");
    return -1;
  }
  OC_DBG("parsed the provided identity cert");

  /* Extract subjectUUID from the CN property in the identity certificate */
  oc_string_t subjectuuid;

  if (oc_certs_parse_CN_for_UUID(&cert1, &subjectuuid) < 0) {
    OC_DBG("could not extract a subjectUUID from the CN property.. Using "
           "'*'instead..");
    oc_new_string(&subjectuuid, "*", 1);
  }
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *c = oc_list_head(creds->creds);
  for (; c != NULL; c = c->next) {
    /* Iterate over all identity certs provisioned to this logical
     * device.
     */
    if (c->credusage != credusage) {
      continue;
    }
    mbedtls_x509_crt_init(&cert2);

    ret = mbedtls_x509_crt_parse(
      &cert2, (const unsigned char *)oc_string(c->publicdata.data),
      oc_string_len(c->publicdata.data) + 1);
    if (ret < 0) {
      mbedtls_x509_crt_free(&cert2);
      continue;
    }

    if (cert1.raw.len == cert2.raw.len &&
        memcmp(cert1.raw.p, cert2.raw.p, cert2.raw.len) == 0) {
      mbedtls_x509_crt_free(&cert1);
      mbedtls_x509_crt_free(&cert2);
      oc_free_string(&subjectuuid);
      OC_DBG("found identity cert in cred with credid %d", c->credid);
      return c->credid;
    }
    mbedtls_x509_crt_free(&cert2);
  }

  OC_DBG("adding a new identity cert chain to /oic/sec/cred");

  mbedtls_x509_crt_free(&cert1);

  int credid = oc_sec_add_new_cred(
    device, false, NULL, -1, OC_CREDTYPE_CERT, credusage,
    oc_string(subjectuuid), OC_ENCODING_RAW, private_key_size,
    privkbuf + (200 - private_key_size), OC_ENCODING_PEM, c_size - 1,
    (const uint8_t *)cert, NULL, NULL);

  if (credid != -1) {
    OC_DBG("added new identity cert chain to /oic/sec/cred");
    oc_sec_dump_cred(device);
  } else {
    OC_ERR("could not add identity cert chain to /oic/sec/cred");
  }

  oc_free_string(&subjectuuid);

  return credid;
}

int
oc_pki_add_mfg_cert(size_t device, const unsigned char *cert, size_t cert_size,
                    const unsigned char *key, size_t key_size)
{
  return pki_add_identity_cert(device, cert, cert_size, key, key_size,
                               OC_CREDUSAGE_MFG_CERT);
}

int
oc_pki_add_mfg_intermediate_cert(size_t device, int credid,
                                 const unsigned char *cert, size_t cert_size)
{
  return pki_add_intermediate_cert(device, credid, cert, cert_size);
}

static int
pki_add_trust_anchor(size_t device, const unsigned char *cert, size_t cert_size,
                     oc_sec_credusage_t credusage)
{
  OC_DBG("attempting to add a trust anchor");

  mbedtls_x509_crt cert1, cert2;
  mbedtls_x509_crt_init(&cert1);
  size_t c_size = cert_size;

  /* Parse root cert */
  if (oc_certs_is_PEM((const unsigned char *)cert, cert_size) != 0) {
    OC_ERR("provided cert is not in PEM format");
    return -1;
  }
  if (cert[cert_size - 1] != '\0') {
    c_size += 1;
  }
  int ret = mbedtls_x509_crt_parse(&cert1, (const unsigned char *)cert, c_size);
  if (ret < 0) {
    OC_ERR("could not parse the provided trust anchor: %d", ret);
    return -1;
  }
  OC_DBG("parsed the provided trust anchor");

  /* Pass through all known trust anchors looking for a match */
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  oc_sec_cred_t *c = oc_list_head(creds->creds);
  for (; c != NULL; c = c->next) {
    if (c->credusage != credusage) {
      continue;
    }
    mbedtls_x509_crt_init(&cert2);
    ret = mbedtls_x509_crt_parse(
      &cert2, (const unsigned char *)oc_string(c->publicdata.data),
      oc_string_len(c->publicdata.data) + 1);
    if (ret < 0) {
      OC_ERR("could not parse stored certificate: %d", ret);
      mbedtls_x509_crt_free(&cert2);
      continue;
    }

    mbedtls_x509_crt *trustca = &cert2;
    for (; trustca != NULL; trustca = trustca->next) {
      if (trustca->raw.len == cert1.raw.len &&
          memcmp(trustca->raw.p, cert1.raw.p, cert1.raw.len) == 0) {
        break;
      }
    }

    mbedtls_x509_crt_free(&cert2);

    if (trustca) {
      mbedtls_x509_crt_free(&cert1);
      OC_DBG("found trust anchor in cred with credid %d", c->credid);
      return c->credid;
    }
  }

  OC_DBG("adding a new trust anchor entry to /oic/sec/cred");

  ret = oc_sec_add_new_cred(device, false, NULL, -1, OC_CREDTYPE_CERT,
                            credusage, "*", 0, 0, NULL, OC_ENCODING_PEM,
                            c_size - 1, (const uint8_t *)cert, NULL, NULL);
  if (ret != -1) {
    OC_DBG("added new trust anchor entry to /oic/sec/cred");
    oc_sec_dump_cred(device);
  } else {
    OC_ERR("could not add trust anchor entry to /oic/sec/cred");
  }

  mbedtls_x509_crt_free(&cert1);
  return ret;
}

int
oc_pki_add_mfg_trust_anchor(size_t device, const unsigned char *cert,
                            size_t cert_size)
{
  return pki_add_trust_anchor(device, cert, cert_size,
                              OC_CREDUSAGE_MFG_TRUSTCA);
}

int
oc_pki_add_trust_anchor(size_t device, const unsigned char *cert,
                        size_t cert_size)
{
  return pki_add_trust_anchor(device, cert, cert_size, OC_CREDUSAGE_TRUSTCA);
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

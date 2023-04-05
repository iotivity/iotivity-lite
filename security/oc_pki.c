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

#include "oc_pki.h"
#include "oc_certs_internal.h"
#include "oc_cred_internal.h"
#include "oc_pki_internal.h"
#include "oc_store.h"
#include "oc_tls_internal.h"
#include "port/oc_connectivity.h"

#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>

static oc_pki_verify_certificate_cb_t g_verify_certificate_cb;
static oc_pki_pk_functions_t g_pk_functions;
static bool g_pk_functions_set = false;

static int
pki_add_intermediate_cert(size_t device, int credid, const unsigned char *cert,
                          size_t cert_size)
{
  OC_DBG("attempting to add an intermediate CA certificate");
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
  if (!oc_certs_is_PEM(cert, cert_size)) {
    OC_ERR("provided cert is not in PEM format");
    return -1;
  }
  if (cert[cert_size - 1] != '\0') {
    c_size += 1;
  }

  int ret = mbedtls_x509_crt_parse(&int_ca, cert, c_size);
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
      OC_DBG("found intermediate cert in identity cred(credid=%d)", credid);
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
  if (oc_certs_is_subject_the_issuer(&int_ca, id_cert) != 0) {
    OC_ERR("could not add intermediate CA cert to /oic/sec/cred: supplied "
           "intermediate CA cert is not issuer of identity cert");
    mbedtls_x509_crt_free(&int_ca);
    mbedtls_x509_crt_free(&id_cert_chain);
    return -1;
  }

  oc_string_t chain;
  oc_new_string(&chain, oc_string(c->publicdata.data),
                oc_string_len(c->publicdata.data));
  oc_free_string(&c->publicdata.data);
  size_t new_publicdata_size = oc_string_len(chain) + c_size;
  oc_alloc_string(&c->publicdata.data, new_publicdata_size);
  memcpy(oc_string(c->publicdata.data), oc_string(chain), oc_string_len(chain));
  memcpy(oc_string(c->publicdata.data) + oc_string_len(chain), cert, cert_size);
  oc_string(c->publicdata.data)[new_publicdata_size - 1] = '\0';
  oc_free_string(&chain);
  OC_DBG("adding a new intermediate CA cert to /oic/sec/cred");
  oc_sec_dump_cred(device);

  mbedtls_x509_crt_free(&int_ca);
  mbedtls_x509_crt_free(&id_cert_chain);

  OC_DBG("added intermediate CA(identity cred credid=%d) cert to /oic/sec/cred",
         credid);
  oc_tls_resolve_new_identity_certs();
  return credid;
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

  if (!oc_certs_is_PEM(cert, cert_size)) {
    OC_ERR("provided cert is not in PEM format");
    return -1;
  }
  if (cert[cert_size - 1] != '\0') {
    c_size += 1;
  }
  if (oc_certs_is_PEM(key, key_size)) {
    if (key[key_size - 1] != '\0') {
      k_size += 1;
    }
  }

  /* Parse identity cert's private key */
  int ret =
    oc_mbedtls_pk_parse_key(device, &pkey, key, k_size, NULL, 0,
                            mbedtls_ctr_drbg_random, oc_tls_ctr_drbg_context());
  if (ret != 0) {
    OC_ERR("could not parse identity cert's private key %d", ret);
    return -1;
  }
  OC_DBG("parsed the provided identity cert's private key");

  /* Serialize identity cert's private key to DER */
  uint8_t privkbuf[200];
  ret = oc_mbedtls_pk_write_key_der(device, &pkey, privkbuf, 200);

  mbedtls_pk_free(&pkey);

  if (ret < 0) {
    OC_ERR("could not write identity cert's DER encoded private key %d", ret);
    return -1;
  }

  size_t private_key_size = ret;

  mbedtls_x509_crt cert1, cert2;
  mbedtls_x509_crt_init(&cert1);

  /* Parse identity cert chain */
  ret = mbedtls_x509_crt_parse(&cert1, cert, c_size);
  if (ret < 0) {
    OC_ERR("could not parse the provided identity cert");
    return -1;
  }
  OC_DBG("parsed the provided identity cert");

  /* Extract subjectUUID from the CN property in the identity certificate */
  char subjectuuid[OC_UUID_LEN] = { 0 };
  if (!oc_certs_extract_CN_for_UUID(&cert1, subjectuuid, sizeof(subjectuuid))) {
    OC_DBG("could not extract a subjectUUID from the CN property.. Using '*' "
           "instead..");
    subjectuuid[0] = '*';
    subjectuuid[1] = '\0';
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

    ret =
      mbedtls_x509_crt_parse(&cert2, oc_cast(c->publicdata.data, unsigned char),
                             oc_string_len(c->publicdata.data) + 1);
    if (ret < 0) {
      mbedtls_x509_crt_free(&cert2);
      continue;
    }

    if (cert1.raw.len == cert2.raw.len &&
        memcmp(cert1.raw.p, cert2.raw.p, cert2.raw.len) == 0) {
      mbedtls_x509_crt_free(&cert1);
      mbedtls_x509_crt_free(&cert2);
      OC_DBG("found identity cert in cred with credid %d", c->credid);
      return c->credid;
    }
    mbedtls_x509_crt_free(&cert2);
  }

  OC_DBG("adding a new identity cert chain to /oic/sec/cred");

  mbedtls_x509_crt_free(&cert1);

  int credid = oc_sec_add_new_cred(
    device, false, NULL, -1, OC_CREDTYPE_CERT, credusage, subjectuuid,
    OC_ENCODING_RAW, private_key_size, privkbuf + (200 - private_key_size),
    OC_ENCODING_PEM, c_size - 1, cert, NULL, NULL, NULL, NULL);

  if (credid != -1) {
    OC_DBG("added new identity cert(credid=%d) chain to /oic/sec/cred", credid);
    oc_sec_dump_cred(device);
  } else {
    OC_ERR("could not add identity cert chain to /oic/sec/cred");
  }

  return credid;
}

int
oc_pki_add_identity_cert(size_t device, const unsigned char *cert,
                         size_t cert_size, const unsigned char *key,
                         size_t key_size)
{
  return pki_add_identity_cert(device, cert, cert_size, key, key_size,
                               OC_CREDUSAGE_IDENTITY_CERT);
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
  if (!oc_certs_is_PEM(cert, cert_size)) {
    OC_ERR("provided cert is not in PEM format");
    return -1;
  }
  if (cert[cert_size - 1] != '\0') {
    c_size += 1;
  }
  int ret = mbedtls_x509_crt_parse(&cert1, cert, c_size);
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
    ret =
      mbedtls_x509_crt_parse(&cert2, oc_cast(c->publicdata.data, unsigned char),
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
                            c_size - 1, cert, NULL, NULL, NULL, NULL);
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

void
oc_pki_set_verify_certificate_cb(oc_pki_verify_certificate_cb_t cb)
{
  g_verify_certificate_cb = cb;
}

static int
default_verify_certificate_cb(struct oc_tls_peer_t *peer,
                              const mbedtls_x509_crt *crt, int depth,
                              uint32_t *flags)
{
  (void)peer;
  (void)depth;
#if OC_ERR_IS_ENABLED
  if (flags != NULL && (*flags & MBEDTLS_X509_BADCERT_EXPIRED) != 0) {
    char buf[256];
    int ret = mbedtls_x509_dn_gets(buf, sizeof(buf) - 1, &crt->subject);
    if (ret >= 0) {
      buf[ret] = 0;
    } else {
      ret = snprintf(buf, sizeof(buf) - 1, "unknown");
      buf[ret] = 0;
    }
    OC_ERR("certificate %s is expired on %d-%02d-%02d %02d:%02d:%02d", buf,
           crt->valid_to.year, crt->valid_to.mon, crt->valid_to.day,
           crt->valid_to.hour, crt->valid_to.min, crt->valid_to.sec);
  }
  if (flags != NULL && (*flags & MBEDTLS_X509_BADCERT_FUTURE) != 0) {
    char buf[256];
    int ret = mbedtls_x509_dn_gets(buf, sizeof(buf) - 1, &crt->subject);
    if (ret >= 0) {
      buf[ret] = 0;
    } else {
      ret = snprintf(buf, sizeof(buf) - 1, "unknown");
      buf[ret] = 0;
    }
    OC_ERR("certificate %s will be valid from %d-%02d-%02d %02d:%02d:%02d", buf,
           crt->valid_from.year, crt->valid_from.mon, crt->valid_from.day,
           crt->valid_from.hour, crt->valid_from.min, crt->valid_from.sec);
  }
#else  /* !OC_ERR_IS_ENABLED */
  (void)crt;
  (void)flags;
#endif /* OC_ERR_IS_ENABLED */
  return 0;
}

oc_pki_verify_certificate_cb_t
oc_pki_get_verify_certificate_cb(void)
{
  if (g_verify_certificate_cb == NULL) {
    return &default_verify_certificate_cb;
  }
  return g_verify_certificate_cb;
}

int
oc_mbedtls_pk_parse_key(size_t device, mbedtls_pk_context *pk,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *pwd, size_t pwdlen,
                        int (*f_rng)(void *, unsigned char *, size_t),
                        void *p_rng)
{
  if (!g_pk_functions_set) {
    return mbedtls_pk_parse_key(pk, key, keylen, pwd, pwdlen, f_rng, p_rng);
  }
  if (g_pk_functions.mbedtls_pk_parse_key == NULL) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
  }
  return g_pk_functions.mbedtls_pk_parse_key(device, pk, key, keylen, pwd,
                                             pwdlen, f_rng, p_rng);
}

int
oc_mbedtls_pk_write_key_der(size_t device, const mbedtls_pk_context *ctx,
                            unsigned char *buf, size_t size)
{
  if (!g_pk_functions_set) {
    return mbedtls_pk_write_key_der(ctx, buf, size);
  }
  if (g_pk_functions.mbedtls_pk_write_key_der == NULL) {
    return MBEDTLS_ERR_PK_FEATURE_UNAVAILABLE;
  }
  return g_pk_functions.mbedtls_pk_write_key_der(device, ctx, buf, size);
}

int
oc_mbedtls_pk_write_pubkey_der(const mbedtls_pk_context *ctx,
                               unsigned char *buf, size_t size)
{
  return mbedtls_pk_write_pubkey_der(ctx, buf, size);
}

int
oc_mbedtls_pk_ecp_gen_key(size_t device, mbedtls_ecp_group_id grp_id,
                          mbedtls_pk_context *pk,
                          int (*f_rng)(void *, unsigned char *, size_t),
                          void *p_rng)
{
  if (!g_pk_functions_set) {
    return mbedtls_ecp_gen_key(grp_id, mbedtls_pk_ec(*pk), f_rng, p_rng);
  }
  if (g_pk_functions.mbedtls_pk_ecp_gen_key == NULL) {
    return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
  }
  return g_pk_functions.mbedtls_pk_ecp_gen_key(device, grp_id, pk, f_rng,
                                               p_rng);
}

bool
oc_pk_free_key(size_t device, const unsigned char *key, size_t keylen)
{
  if (!g_pk_functions_set) {
    return false;
  }
  if (g_pk_functions.pk_free_key == NULL) {
    return false;
  }
  return g_pk_functions.pk_free_key(device, key, keylen);
}

bool
oc_pki_set_pk_functions(const oc_pki_pk_functions_t *pk_functions)
{
  if (pk_functions == NULL) {
    g_pk_functions_set = false;
    return true;
  }
  if (pk_functions->mbedtls_pk_ecp_gen_key == NULL ||
      pk_functions->mbedtls_pk_parse_key == NULL ||
      pk_functions->mbedtls_pk_write_key_der == NULL ||
      pk_functions->pk_free_key == NULL) {
    return false;
  }
  g_pk_functions_set = true;
  g_pk_functions.mbedtls_pk_ecp_gen_key = pk_functions->mbedtls_pk_ecp_gen_key;
  g_pk_functions.mbedtls_pk_parse_key = pk_functions->mbedtls_pk_parse_key;
  g_pk_functions.mbedtls_pk_write_key_der =
    pk_functions->mbedtls_pk_write_key_der;
  g_pk_functions.pk_free_key = pk_functions->pk_free_key;
  return true;
}

bool
oc_pki_get_pk_functions(oc_pki_pk_functions_t *pk_functions)
{
  if (pk_functions != NULL) {
    *pk_functions = g_pk_functions;
  }
  return g_pk_functions_set;
}

#endif /* OC_SECURITY && OC_PKI */

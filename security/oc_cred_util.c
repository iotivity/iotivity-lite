/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#ifdef OC_SECURITY

#include "oc_base64.h"
#include "oc_cred.h"
#include "port/oc_log_internal.h"
#include "security/oc_cred_internal.h"
#include "security/oc_cred_util_internal.h"
#include "util/oc_mmem_internal.h"

#include <assert.h>

const char *
oc_cred_credtype_string(oc_sec_credtype_t credtype)
{
  if (credtype == OC_CREDTYPE_PSK) {
    return OC_CREDTYPE_PSK_STR;
  }
  if (credtype == OC_CREDTYPE_CERT) {
    return OC_CREDTYPE_CERT_STR;
  }
  return "Unknown";
}

oc_string_view_t
oc_cred_encoding_to_string(oc_sec_encoding_t encoding)
{
  switch (encoding) {
  case OC_ENCODING_BASE64:
    return oc_string_view(OC_ENCODING_BASE64_STR,
                          OC_CHAR_ARRAY_LEN(OC_ENCODING_BASE64_STR));
  case OC_ENCODING_RAW:
    return oc_string_view(OC_ENCODING_RAW_STR,
                          OC_CHAR_ARRAY_LEN(OC_ENCODING_RAW_STR));
#ifdef OC_PKI
  case OC_ENCODING_PEM:
    return oc_string_view(OC_ENCODING_PEM_STR,
                          OC_CHAR_ARRAY_LEN(OC_ENCODING_PEM_STR));
#endif /* OC_PKI */
  case OC_ENCODING_HANDLE:
    return oc_string_view(OC_ENCODING_HANDLE_STR,
                          OC_CHAR_ARRAY_LEN(OC_ENCODING_HANDLE_STR));
  default:
    break;
  }
  return oc_string_view("Unknown", OC_CHAR_ARRAY_LEN("Unknown"));
}

const char *
oc_cred_read_encoding(oc_sec_encoding_t encoding)
{
  oc_string_view_t enc = oc_cred_encoding_to_string(encoding);
  return enc.data;
}

oc_sec_encoding_t
oc_cred_encoding_from_string(const char *str, size_t str_len)
{
  oc_string_view_t view = oc_string_view(str, str_len);
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_ENCODING_BASE64_STR), view)) {
    return OC_ENCODING_BASE64;
  }
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_ENCODING_RAW_STR), view)) {
    return OC_ENCODING_RAW;
  }
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_ENCODING_HANDLE_STR), view)) {
    return OC_ENCODING_HANDLE;
  }
#ifdef OC_PKI
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_ENCODING_PEM_STR), view)) {
    return OC_ENCODING_PEM;
  }
#endif /* OC_PKI */
  return OC_ENCODING_UNSUPPORTED;
}

oc_sec_encoding_t
oc_cred_parse_encoding(const oc_string_t *encoding_string)
{
  return oc_cred_encoding_from_string(oc_string(*encoding_string),
                                      oc_string_len(*encoding_string));
}

bool
oc_cred_data_is_equal_to_encoded_data(oc_cred_data_t cd,
                                      oc_sec_encoded_data_t sed)
{
  if (cd.encoding != sed.encoding) {
    return false;
  }
  size_t cddata_size =
    cd.encoding == OC_ENCODING_PEM ? oc_string_len(cd.data) : cd.data.size;
  return cddata_size == sed.size &&
         (sed.data == NULL ||
          (memcmp(oc_string(cd.data), sed.data, sed.size) == 0));
}

bool
oc_cred_has_tag(const oc_sec_cred_t *cred, oc_string_view_t tag)
{
  oc_string_view_t credtag = oc_string_view2(&cred->tag);
  return oc_string_view_is_equal(credtag, tag);
}

bool
oc_cred_is_duplicate(const oc_sec_cred_t *cred, oc_sec_credtype_t credtype,
                     oc_uuid_t subject, oc_string_view_t tag,
                     oc_sec_encoded_data_t privatedata,
                     oc_sec_encoded_data_t publicdata,
                     oc_sec_credusage_t credusage)
{
  if ((cred->credtype != credtype) ||
      !oc_uuid_is_equal(cred->subjectuuid, subject) ||
      !oc_cred_data_is_equal_to_encoded_data(cred->privatedata, privatedata) ||
      !oc_cred_has_tag(cred, tag)) {
    return false;
  }

#ifdef OC_PKI
  if ((cred->credusage != credusage) ||
      !oc_cred_data_is_equal_to_encoded_data(cred->publicdata, publicdata)) {
    return false;
  }
#else  /* !OC_PKI */
  (void)publicdata;
  (void)credusage;
#endif /* OC_PKI */
  return true;
}

void
oc_cred_iterate(const oc_list_t creds, oc_cred_iterate_fn_t iterate,
                void *iterate_data)
{
  for (oc_sec_cred_t *cred = (oc_sec_cred_t *)oc_list_head(creds); cred != NULL;
       cred = cred->next) {
    // simplifying expectation -> the creds list is not modified by the
    // iteration function or it exits immediately after modification
    if (!iterate(cred, iterate_data)) {
      break;
    }
  }
}

bool
oc_sec_cred_set_subject(const char *subjectuuid, oc_sec_credusage_t credusage,
                        oc_uuid_t *subject)
{
  if (subjectuuid == NULL) {
    if (credusage == OC_CREDUSAGE_ROLE_CERT) {
      subject->id[0] = '*';
      return true;
    }
    return false;
  }

  if (subjectuuid[0] == '*') {
    subject->id[0] = '*';
  } else {
    oc_str_to_uuid(subjectuuid, subject);
  }
  return true;
}

static bool
cred_check_symmetric_key_length(size_t key_size)
{
// https://openconnectivity.org/specs/OCF_Security_Specification_v2.2.5.pdf
// 13.3.3.1 Symmetric key formatting
#define SYMMETRIC_KEY_128BIT_LEN 16
#define SYMMETRIC_KEY_256BIT_LEN 32
  if (key_size != SYMMETRIC_KEY_128BIT_LEN &&
      key_size != SYMMETRIC_KEY_256BIT_LEN) {
    OC_ERR("oc_cred: invalid PSK length(%zu)", key_size);
    return false;
  }
  return true;
#undef SYMMETRIC_KEY_256BIT_LEN
#undef SYMMETRIC_KEY_128BIT_LEN
}

bool
oc_cred_set_privatedata(oc_sec_cred_t *cred, const uint8_t *data,
                        size_t data_size, oc_sec_encoding_t encoding)
{
  if (cred->credtype == OC_CREDTYPE_PSK) {
    if (encoding == OC_ENCODING_BASE64) {
      if (data_size > 64) {
        return false;
      }
      uint8_t key[64];
      memcpy(key, data, data_size);
      int key_size = oc_base64_decode(key, data_size);
      if (key_size < 0 || !cred_check_symmetric_key_length((size_t)key_size)) {
        return false;
      }
      oc_new_string(&cred->privatedata.data, (const char *)key, key_size);
      cred->privatedata.encoding = OC_ENCODING_RAW;
      return true;
    }
    if (!cred_check_symmetric_key_length(data_size)) {
      return false;
    }
  }
  oc_new_string(&cred->privatedata.data, (const char *)data, data_size);
  cred->privatedata.encoding = encoding;
  return true;
}

#ifdef OC_PKI

oc_string_view_t
oc_cred_credusage_to_string(oc_sec_credusage_t credusage)
{
  switch (credusage) {
  case OC_CREDUSAGE_TRUSTCA:
    return oc_string_view(OC_CREDUSAGE_TRUSTCA_STR,
                          OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_TRUSTCA_STR));
  case OC_CREDUSAGE_IDENTITY_CERT:
    return oc_string_view(OC_CREDUSAGE_IDENTITY_CERT_STR,
                          OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_IDENTITY_CERT_STR));
  case OC_CREDUSAGE_ROLE_CERT:
    return oc_string_view(OC_CREDUSAGE_ROLE_CERT_STR,
                          OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_ROLE_CERT_STR));
  case OC_CREDUSAGE_MFG_TRUSTCA:
    return oc_string_view(OC_CREDUSAGE_MFG_TRUSTCA_STR,
                          OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_MFG_TRUSTCA_STR));
  case OC_CREDUSAGE_MFG_CERT:
    return oc_string_view(OC_CREDUSAGE_MFG_CERT_STR,
                          OC_CHAR_ARRAY_LEN(OC_CREDUSAGE_MFG_CERT_STR));
  default:
    break;
  }
  return oc_string_view("None", OC_CHAR_ARRAY_LEN("None"));
}

const char *
oc_cred_read_credusage(oc_sec_credusage_t credusage)
{
  oc_string_view_t cu = oc_cred_credusage_to_string(credusage);
  return cu.data;
}

oc_sec_credusage_t
oc_cred_usage_from_string(const char *str, size_t str_len)
{
  oc_string_view_t view = oc_string_view(str, str_len);
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_CREDUSAGE_TRUSTCA_STR), view)) {
    return OC_CREDUSAGE_TRUSTCA;
  }
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_CREDUSAGE_IDENTITY_CERT_STR),
                              view)) {
    return OC_CREDUSAGE_IDENTITY_CERT;
  }
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_CREDUSAGE_ROLE_CERT_STR),
                              view)) {
    return OC_CREDUSAGE_ROLE_CERT;
  }
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_CREDUSAGE_MFG_TRUSTCA_STR),
                              view)) {
    return OC_CREDUSAGE_MFG_TRUSTCA;
  }
  if (oc_string_view_is_equal(OC_STRING_VIEW(OC_CREDUSAGE_MFG_CERT_STR),
                              view)) {
    return OC_CREDUSAGE_MFG_CERT;
  }
  return OC_CREDUSAGE_NULL;
}

oc_sec_credusage_t
oc_cred_parse_credusage(const oc_string_t *credusage_string)
{
  return oc_cred_usage_from_string(oc_string(*credusage_string),
                                   oc_string_len(*credusage_string));
}

typedef struct
{
  oc_sec_cred_filter_t filter;
  void *filter_data;
  char *buffer;
  size_t buffer_size;

  bool ok;
} cred_serialize_iterate_data_t;

static bool
cred_serialize_iterate(const oc_sec_cred_t *cred, void *data)
{
  cred_serialize_iterate_data_t *sid = (cred_serialize_iterate_data_t *)data;
  if (cred->credtype != OC_CREDTYPE_CERT ||
      (sid->filter != NULL && !sid->filter(cred, sid->filter_data))) {
    // skip to next cred
    return true;
  }

  // we can serialize only public data in PEM
  if (cred->publicdata.encoding != OC_ENCODING_PEM) {
    return true;
  }

  const char *cred_pem = oc_string(cred->publicdata.data);
  size_t cred_pem_len = oc_string_len(cred->publicdata.data);
  assert(cred_pem_len != 0);
  if (sid->buffer == NULL) {
    sid->buffer_size += cred_pem_len;
    return true;
  }

  if (cred_pem_len > sid->buffer_size) {
    OC_ERR("cannot serialize certificate: buffer too small");
    sid->ok = false;
    return false;
  }

  // write to buffer
  memcpy(sid->buffer, cred_pem, cred_pem_len);
  sid->buffer += cred_pem_len;
  sid->buffer_size -= cred_pem_len;
  return true;
}

long
oc_cred_serialize(const oc_list_t creds, oc_sec_cred_filter_t filter,
                  void *filter_data, char *buffer, size_t buffer_size)
{
  assert(buffer != NULL || buffer_size == 0);

  cred_serialize_iterate_data_t sid = {
    .filter = filter,
    .filter_data = filter_data,
    .buffer = buffer,
    .buffer_size = buffer_size,
    .ok = true,
  };

  oc_cred_iterate(creds, cred_serialize_iterate, &sid);
  if (!sid.ok) {
    return -1;
  }

  if (buffer == NULL) {
    return (long)(sid.buffer_size);
  }

  long written = (long)(buffer_size - sid.buffer_size);
  return written;
}

#endif /* OC_PKI */

#endif /* OC_SECURITY */

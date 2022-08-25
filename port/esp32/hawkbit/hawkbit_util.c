/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "hawkbit_util.h"
#include "debug_print.h"

#include <assert.h>
#include <regex.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint8_t
hex_to_uint(char c)
{
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return (c - 'a') + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return (c - 'A') + 10;
  }
  return 0;
}

hawkbit_sha1_digest_t
hawkbit_sha1_hash_to_digest(hawkbit_sha1_hash_t hash)
{
  hawkbit_sha1_digest_t digest;
  for (int i = 0; i < HAWKBIT_SHA1_DIGEST_SIZE; ++i) {
    digest.data[i] = (uint8_t)(hex_to_uint(hash.data[i * 2]) << 4) |
                     hex_to_uint(hash.data[i * 2 + 1]);
  }
  return digest;
}

hawkbit_sha1_hash_t
hawkbit_sha1_digest_to_hash(hawkbit_sha1_digest_t digest)
{
  hawkbit_sha1_hash_t hash;
  for (int i = 0; i < HAWKBIT_SHA1_DIGEST_SIZE; ++i) {
    sprintf(&hash.data[i * 2], "%02x", digest.data[i]);
  }
  hash.data[HAWKBIT_SHA1_HASH_SIZE - 1] = '\0';
  return hash;
}

hawkbit_sha256_digest_t
hawkbit_sha256_hash_to_digest(hawkbit_sha256_hash_t hash)
{

  hawkbit_sha256_digest_t digest;
  for (int i = 0; i < HAWKBIT_SHA256_DIGEST_SIZE; ++i) {
    digest.data[i] = (uint8_t)(hex_to_uint(hash.data[i * 2]) << 4) |
                     hex_to_uint(hash.data[i * 2 + 1]);
  }
  return digest;
}

hawkbit_sha256_hash_t
hawkbit_sha256_digest_to_hash(hawkbit_sha256_digest_t digest)
{
  hawkbit_sha256_hash_t hash;
  for (int i = 0; i < HAWKBIT_SHA256_DIGEST_SIZE; ++i) {
    sprintf(&hash.data[i * 2], "%02x", digest.data[i]);
  }
  hash.data[HAWKBIT_SHA256_HASH_SIZE - 1] = '\0';
  return hash;
}

bool
hawkbit_parse_package_url(const char *purl, hawkbit_url_t *url)
{
  assert(purl != NULL);

  const char *pattern = "^https?://[^[:space:]/$.?#].[^[:space:]/]+("
                        "/([^[:space:]/]+)/controller/v1/([^[:space:]/]+)|"
                        "/([^[:space:]/]+)|"
                        "[^[:space:]]+)?/*$";

  regex_t re;
  int ret = regcomp(&re, pattern, REG_EXTENDED | REG_ICASE);
  if (ret != 0) {
    APP_ERR("cannot compile regular expression: %d", ret);
    return false;
  }
  regmatch_t pmatch[5] = {
    { -1, -1 }, { -1, -1 }, { -1, -1 }, { -1, -1 }, { -1, -1 }
  };
  ret = regexec(&re, purl, sizeof(pmatch) / sizeof(pmatch[0]), pmatch, 0);
  regfree(&re);
  if (ret != 0) {
    APP_DBG("url(%s) doesn't match pattern", purl);
    return false;
  }
  if (url == NULL) {
    return true;
  }

  memset(url, 0, sizeof(hawkbit_url_t));
  if (pmatch[1].rm_so != -1) {
    url->server_url = purl;
    url->server_url_length = pmatch[1].rm_so;

    // if [^[:space:]/]+)/controller/v1/([^[:space:]/]+ matches
    // match[2] = TENANT
    // match[3] = CONTROLLER_ID
    if (pmatch[2].rm_so != -1 && pmatch[3].rm_so != -1) {
      url->tenant = purl + pmatch[2].rm_so;
      url->tenant_length = pmatch[2].rm_eo - pmatch[2].rm_so;
      url->controller_id = purl + pmatch[3].rm_so;
      url->controller_id_length = pmatch[3].rm_eo - pmatch[3].rm_so;
      return true;
    }

    // if [^[:space:]/]+ matches
    // match[4] = TENANT
    if (pmatch[4].rm_so != -1) {
      url->tenant = purl + pmatch[4].rm_so;
      url->tenant_length = pmatch[4].rm_eo - pmatch[4].rm_so;
      return true;
    }
  }

  // otherwise take the full url as base url
  url->server_url = purl;
  url->server_url_length = strlen(purl);
  return true;
}

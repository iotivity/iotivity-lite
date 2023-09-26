/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "api/oc_query_internal.h"
#include "api/oc_helpers_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/coap_options.h"
#include "oc_api.h"
#include "oc_ri.h"
#include "util/oc_secure_string_internal.h"

#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

static size_t g_query_iterator;

#ifdef OC_SERVER

oc_string_view_t
oc_query_encode_interface(oc_interface_mask_t iface_mask)
{
  switch (iface_mask) {
  case OC_IF_BASELINE:
    return OC_STRING_VIEW("if=" OC_IF_BASELINE_STR);
  case OC_IF_LL:
    return OC_STRING_VIEW("if=" OC_IF_LL_STR);
  case OC_IF_B:
    return OC_STRING_VIEW("if=" OC_IF_B_STR);
  case OC_IF_R:
    return OC_STRING_VIEW("if=" OC_IF_R_STR);
  case OC_IF_RW:
    return OC_STRING_VIEW("if=" OC_IF_RW_STR);
  case OC_IF_A:
    return OC_STRING_VIEW("if=" OC_IF_A_STR);
  case OC_IF_S:
    return OC_STRING_VIEW("if=" OC_IF_S_STR);
  case OC_IF_CREATE:
    return OC_STRING_VIEW("if=" OC_IF_CREATE_STR);
  case OC_IF_W:
    return OC_STRING_VIEW("if=" OC_IF_W_STR);
  case OC_IF_STARTUP:
    return OC_STRING_VIEW("if=" OC_IF_STARTUP_STR);
  case OC_IF_STARTUP_REVERT:
    return OC_STRING_VIEW("if=" OC_IF_STARTUP_REVERT_STR);
  default:
    break;
  }
  return OC_STRING_VIEW_NULL();
}

#endif /* OC_SERVER */

// representation of query key-value pairs (&key=value)
typedef struct
{
  const char *key;
  size_t key_len;
  const char *value;
  size_t value_len;
} key_value_pair_t;

static key_value_pair_t
oc_ri_find_query_nth_key_value_pair(const char *query, size_t query_len,
                                    size_t n)
{
  assert(n > 0);
  key_value_pair_t res = { NULL, 0, NULL, 0 };
  if (query == NULL || query_len == 0) {
    return res;
  }
  const char *start = query;
  const char *end = query + query_len;
  // find nth key-value pair
  size_t i = 0;
  while (i < (n - 1)) {
    start = (const char *)memchr(start, '&', end - start);
    if (start == NULL) {
      return res;
    }
    ++i;
    ++start;
  }
  res.key = start;

  const char *value = (const char *)memchr(start, '=', end - start);
  const char *next_pair = (const char *)memchr(start, '&', end - start);
  // verify that the found value belongs to the current key
  if (next_pair != NULL && (next_pair < value)) {
    // the current key does not have a '='
    value = NULL;
  }
  if (value == NULL) {
    res.key_len = next_pair != NULL ? next_pair - res.key : end - res.key;
    return res;
  }
  res.key_len = value - res.key;

  ++value; // move past '='
  res.value = value;
  res.value_len = next_pair != NULL ? next_pair - res.value : end - res.value;
  return res;
}

int
oc_ri_get_query_nth_key_value(const char *query, size_t query_len,
                              const char **key, size_t *key_len,
                              const char **value, size_t *value_len, size_t n)
{
  assert(key != NULL);
  assert(key_len != NULL);
  assert(n > 0);
  key_value_pair_t kv =
    oc_ri_find_query_nth_key_value_pair(query, query_len, n);
  if (kv.key == NULL) {
    return -1;
  }

  *key = kv.key;
  *key_len = kv.key_len;
  if (value != NULL) {
    *value = kv.value;
  }
  if (value_len != NULL) {
    *value_len = kv.value_len;
  }

  size_t next_pos =
    kv.value != NULL ? (size_t)((kv.value + kv.value_len) - query) : kv.key_len;
  ++next_pos; // +1 for '&'

  assert(next_pos <= INT_MAX);
  return (int)next_pos;
}

int
oc_ri_get_query_value_v1(const char *query, size_t query_len, const char *key,
                         size_t key_len, const char **value)
{
  assert(key != NULL);
  // we can limit the key length by the maximal allowed query option size
  if (key_len > COAP_OPTION_QUERY_MAX_SIZE) {
    return -1;
  }

  int found = -1;
  size_t pos = 0;
  while (pos < query_len) {
    const char *k;
    size_t kl;
    const char *v;
    size_t vl;
    int next_pos = oc_ri_get_query_nth_key_value(query + pos, query_len - pos,
                                                 &k, &kl, &v, &vl, 1u);
    if (next_pos == -1) {
      return -1;
    }

    if (kl == key_len && strncasecmp(key, k, kl) == 0) {
      assert(vl <= INT_MAX);
      *value = v;
      found = (int)vl;
      break;
    }

    pos += next_pos;
  }
  return found;
}

int
oc_ri_get_query_value(const char *query, size_t query_len, const char *key,
                      const char **value)
{
  assert(key != NULL);
  size_t key_len = oc_strnlen(key, COAP_OPTION_QUERY_MAX_SIZE + 1);
  return oc_ri_get_query_value_v1(query, query_len, key, key_len, value);
}

int
oc_ri_query_nth_key_exists(const char *query, size_t query_len,
                           const char **key, size_t *key_len, size_t n)
{
  assert(key != NULL);
  assert(key_len != NULL);
  assert(n > 0);
  key_value_pair_t kv =
    oc_ri_find_query_nth_key_value_pair(query, query_len, n);
  if (kv.key == NULL) {
    return -1;
  }

  *key = kv.key;
  *key_len = kv.key_len;

  size_t next_pos =
    kv.value != NULL ? (size_t)((kv.value + kv.value_len) - query) : kv.key_len;
  if (next_pos < query_len) {
    ++next_pos; // +1 for '&'
  }

  assert(next_pos <= INT_MAX);
  return (int)next_pos;
}

bool
oc_ri_query_exists_v1(const char *query, size_t query_len, const char *key,
                      size_t key_len)
{
  assert(key != NULL);
  if (key_len > COAP_OPTION_QUERY_MAX_SIZE) {
    return false;
  }

  size_t pos = 0;
  while (pos < query_len) {
    const char *k;
    size_t kl;
    int next_pos =
      oc_ri_query_nth_key_exists(query + pos, query_len - pos, &k, &kl, 1u);

    if (next_pos == -1) {
      return false;
    }
    if (kl == key_len && strncasecmp(key, k, kl) == 0) {
      return true;
    }
    assert(next_pos != 0);
    pos += (size_t)next_pos;
  }
  return false;
}

int
oc_ri_query_exists(const char *query, size_t query_len, const char *key)
{
  assert(key != NULL);
  size_t key_len = oc_strnlen(key, COAP_OPTION_QUERY_MAX_SIZE + 1);
  return oc_ri_query_exists_v1(query, query_len, key, key_len) ? 1 : -1;
}

void
oc_init_query_iterator(void)
{
  g_query_iterator = 0;
}

int
oc_iterate_query(const oc_request_t *request, const char **key, size_t *key_len,
                 const char **value, size_t *value_len)
{
  ++g_query_iterator;
  return oc_ri_get_query_nth_key_value(request->query, request->query_len, key,
                                       key_len, value, value_len,
                                       g_query_iterator);
}

bool
oc_iterate_query_get_values_v1(const oc_request_t *request, const char *key,
                               size_t key_len, const char **value,
                               int *value_len)
{
  assert(request != NULL);
  assert(key != NULL);
  assert(value != NULL);
  assert(value_len != NULL);
  if (key_len > COAP_OPTION_QUERY_MAX_SIZE) {
    return false;
  }

  int pos = 0;
  do {
    const char *k = NULL;
    size_t k_len = 0;
    const char *v = NULL;
    size_t v_len = 0;
    pos = oc_iterate_query(request, &k, &k_len, &v, &v_len);
    if (pos != -1 && key_len == k_len && memcmp(key, k, k_len) == 0) {
      *value = v;
      assert(v_len <= INT_MAX);
      *value_len = (int)v_len;
      goto more_or_done;
    }
  } while (pos != -1);

more_or_done:
  return pos != -1 && (size_t)pos < request->query_len;
}

bool
oc_iterate_query_get_values(const oc_request_t *request, const char *key,
                            const char **value, int *value_len)
{
  size_t key_len = oc_strnlen(key, COAP_OPTION_QUERY_MAX_SIZE + 1);
  return oc_iterate_query_get_values_v1(request, key, key_len, value,
                                        value_len);
}

int
oc_get_query_value_v1(const oc_request_t *request, const char *key,
                      size_t key_len, const char **value)
{
  if (request == NULL) {
    return -1;
  }
  return oc_ri_get_query_value_v1(request->query, request->query_len, key,
                                  key_len, value);
}

int
oc_get_query_value(const oc_request_t *request, const char *key,
                   const char **value)
{
  size_t key_len = oc_strnlen(key, COAP_OPTION_QUERY_MAX_SIZE + 1);
  return oc_get_query_value_v1(request, key, key_len, value);
}

bool
oc_query_value_exists_v1(const oc_request_t *request, const char *key,
                         size_t key_len)
{
  if (request == NULL) {
    return false;
  }
  return oc_ri_query_exists_v1(request->query, request->query_len, key,
                               key_len);
}

int
oc_query_value_exists(const oc_request_t *request, const char *key)
{
  size_t key_len = oc_strnlen(key, COAP_OPTION_QUERY_MAX_SIZE + 1);
  return oc_query_value_exists_v1(request, key, key_len) ? 1 : -1;
}

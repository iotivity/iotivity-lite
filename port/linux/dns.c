/****************************************************************************
 *
 * Copyright (c) 2018 Intel Corporation
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

#ifdef OC_DNS_LOOKUP

#include "oc_helpers.h"
#include "oc_endpoint.h"
#include "port/oc_log_internal.h"
#include "port/oc_connectivity.h"
#include "util/oc_memb.h"
#include "util/oc_macros_internal.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>

#ifdef OC_DNS_CACHE

typedef struct oc_dns_cache_t
{
  struct oc_dns_cache_t *next;
  oc_string_t domain;
  union dev_addr addr;
} oc_dns_cache_t;

OC_MEMB(g_dns_s, oc_dns_cache_t, 1);
OC_LIST(g_dns_cache);

static oc_dns_cache_t *
oc_dns_lookup_cache(const char *domain)
{
  if (oc_list_length(g_dns_cache) == 0) {
    return NULL;
  }
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_list_head(g_dns_cache);
  while (c) {
    if (strlen(domain) == oc_string_len(c->domain) &&
        memcmp(domain, oc_string(c->domain), oc_string_len(c->domain)) == 0) {
      return c;
    }
    c = c->next;
  }
  return NULL;
}

static int
oc_dns_cache_domain(const char *domain, const union dev_addr *addr)
{
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_memb_alloc(&g_dns_s);
  if (c) {
    oc_new_string(&c->domain, domain, strlen(domain));
    memcpy(&c->addr, addr, sizeof(union dev_addr));
    oc_list_add(g_dns_cache, c);
    return 0;
  }
  return -1;
}

void
oc_dns_clear_cache(void)
{
  oc_dns_cache_t *c = (oc_dns_cache_t *)oc_list_pop(g_dns_cache);
  while (c) {
    oc_free_string(&c->domain);
    oc_memb_free(&g_dns_s, c);
    c = (oc_dns_cache_t *)oc_list_pop(g_dns_cache);
  }
}
#endif /* OC_DNS_CACHE */

int
oc_dns_lookup(const char *domain, oc_string_t *addr, transport_flags flags)
{
  if (!domain || !addr) {
    OC_ERR("Error of input parameters");
    return -1;
  }
  OC_DBG("trying to resolve address(%s) for flags(%d)", domain, (int)flags);
  int ret = -1;
  union dev_addr a;

#ifdef OC_DNS_CACHE
  const oc_dns_cache_t *c = oc_dns_lookup_cache(domain);

  if (c == NULL) {
#endif /* OC_DNS_CACHE */
    memset(&a, 0, sizeof(union dev_addr));

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = (flags & IPV6) ? AF_INET6 : AF_INET;
    hints.ai_socktype = (flags & TCP) ? SOCK_STREAM : SOCK_DGRAM;
    struct addrinfo *result = NULL;
    ret = getaddrinfo(domain, NULL, &hints, &result);

    if (ret == 0) {
      if ((flags & IPV6) != 0) {
        CLANG_IGNORE_WARNING_START
        CLANG_IGNORE_WARNING("-Wcast-align")
        const struct sockaddr_in6 *r = (struct sockaddr_in6 *)result->ai_addr;
        CLANG_IGNORE_WARNING_END
        memcpy(a.ipv6.address, r->sin6_addr.s6_addr,
               sizeof(r->sin6_addr.s6_addr));
        a.ipv6.port = ntohs(r->sin6_port);
        a.ipv6.scope = (uint8_t)r->sin6_scope_id;
      }
#ifdef OC_IPV4
      else {
        CLANG_IGNORE_WARNING_START
        CLANG_IGNORE_WARNING("-Wcast-align")
        const struct sockaddr_in *r = (struct sockaddr_in *)result->ai_addr;
        CLANG_IGNORE_WARNING_END
        memcpy(a.ipv4.address, &r->sin_addr.s_addr, sizeof(r->sin_addr.s_addr));
        a.ipv4.port = ntohs(r->sin_port);
      }
#endif /* OC_IPV4 */
#ifdef OC_DNS_CACHE
      oc_dns_cache_domain(domain, &a);
#endif /* OC_DNS_CACHE */
      freeaddrinfo(result);
    } else {
      OC_ERR("failed to resolve address(%s) with error(%d): %s", domain, ret,
             gai_strerror(ret));
    }
#ifdef OC_DNS_CACHE
  } else {
    ret = 0;
    memcpy(&a, &c->addr, sizeof(union dev_addr));
  }
#endif /* OC_DNS_CACHE */

  if (ret == 0) {
    char address[INET6_ADDRSTRLEN + 2] = { 0 };
    const char *dest = NULL;
    errno = 0;
    if ((flags & IPV6) != 0) {
      address[0] = '[';
      dest = inet_ntop(AF_INET6, (void *)a.ipv6.address, address + 1,
                       INET6_ADDRSTRLEN);
      size_t addr_len = strlen(address);
      address[addr_len] = ']';
      address[addr_len + 1] = '\0';
    }
#ifdef OC_IPV4
    else {
      dest =
        inet_ntop(AF_INET, (void *)a.ipv4.address, address, INET_ADDRSTRLEN);
    }
#endif /* OC_IPV4 */
    if (dest) {
      OC_DBG("%s address is %s", domain, address);
      oc_new_string(addr, address, strlen(address));
    } else {
      OC_ERR("failed to parse domain(%s) to string: %d", domain, (int)errno);
      ret = -1;
    }
  }

  return ret;
}
#endif /* OC_DNS_LOOKUP */

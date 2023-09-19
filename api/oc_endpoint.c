/****************************************************************************
 *
 * Copyright (c) 2017 Intel Corporation
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

#include "api/oc_endpoint_internal.h"
#include "api/oc_helpers_internal.h"
#include "oc_endpoint.h"
#include "oc_core_res.h"
#include "port/common/oc_ip.h"
#include "port/oc_allocator_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "util/oc_macros_internal.h"
#include "util/oc_memb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OC_IPV6_ADDRLEN (16)
#define OC_IPV4_ADDRLEN (4)
// Max. IPv6 address + 3 ('[',']' and ':') + 5 (uint16_t for port)
#define OC_IPV6_MAXSTRLEN (OC_IPV6_MAXADDRSTRLEN + 8)
// Max. IPv4 address + 1 (':') + 5 (uint16_t for port)
#define OC_IPV4_MAXSTRLEN (OC_IPV4_MAXADDRSTRLEN + 6)

OC_MEMB(oc_endpoints_s, oc_endpoint_t, OC_MAX_NUM_ENDPOINTS);

oc_endpoint_t *
oc_new_endpoint(void)
{
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_endpoint_t *endpoint = (oc_endpoint_t *)oc_memb_alloc(&oc_endpoints_s);
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  return endpoint;
}

void
oc_free_endpoint(oc_endpoint_t *endpoint)
{
  if (endpoint == NULL) {
    return;
  }
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_memb_free(&oc_endpoints_s, endpoint);
#ifndef OC_DYNAMIC_ALLOCATION
  oc_allocator_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION */
}

void
oc_endpoint_set_di(oc_endpoint_t *endpoint, const oc_uuid_t *di)
{
  memcpy(endpoint->di.id, di->id, sizeof(di->id));
}

static oc_string_view_t
endpoint_flags_to_scheme(unsigned flags)
{
#ifdef OC_TCP
  if ((flags & TCP) != 0) {
    if ((flags & SECURED) != 0) {
      return OC_STRING_VIEW(OC_SCHEME_COAPS_TCP);
    }
    return OC_STRING_VIEW(OC_SCHEME_COAP_TCP);
  }
#endif /* OC_TCP */
  if ((flags & SECURED) != 0) {
    return OC_STRING_VIEW(OC_SCHEME_COAPS);
  }
  return OC_STRING_VIEW(OC_SCHEME_COAP);
}

int
oc_endpoint_flags_to_scheme(unsigned flags, char *buffer, size_t buffer_size)
{
  oc_string_view_t scheme = endpoint_flags_to_scheme(flags);
  if (buffer == NULL) {
    return (int)scheme.length;
  }
  if (scheme.length < buffer_size) {
    memcpy(buffer, scheme.data, scheme.length);
    buffer[scheme.length] = '\0';
    return (int)scheme.length;
  }
  return -1;
}

int
oc_endpoint_host(const oc_endpoint_t *endpoint, char *buffer,
                 size_t buffer_size)
{
#ifdef OC_IPV4
  if ((endpoint->flags & IPV4) != 0) {
    return oc_ipv4_address_to_string(&endpoint->addr.ipv4, buffer, buffer_size);
  }
#endif /* OC_IPV4 */
  if ((endpoint->flags & IPV6) != 0) {
    return oc_ipv6_address_to_string(&endpoint->addr.ipv6, buffer, buffer_size);
  }
  return -1;
}

int
oc_endpoint_address_and_port_to_cstring(const oc_endpoint_t *endpoint,
                                        char *buffer, size_t buffer_size)
{
#ifdef OC_IPV4
  if ((endpoint->flags & IPV4) != 0) {
    return oc_ipv4_address_and_port_to_string(&endpoint->addr.ipv4, buffer,
                                              buffer_size);
  }
#endif /* OC_IPV4 */
  if ((endpoint->flags & IPV6) != 0) {
    return oc_ipv6_address_and_port_to_string(&endpoint->addr.ipv6, buffer,
                                              buffer_size);
  }
  return -1;
}

int
oc_endpoint_to_cstring(const oc_endpoint_t *endpoint, char *buffer,
                       size_t buffer_size)
{
  int written =
    oc_endpoint_flags_to_scheme(endpoint->flags, buffer, buffer_size);
  if (written < 0) {
    return -1;
  }
  int len = written;
  buffer += written;
  buffer_size -= (size_t)written;
  written =
    oc_endpoint_address_and_port_to_cstring(endpoint, buffer, buffer_size);
  if (written < 0) {
    return -1;
  }
  return len + written;
}

int
oc_endpoint_to_string(const oc_endpoint_t *endpoint, oc_string_t *endpoint_str)
{
  if (!endpoint || !endpoint_str) {
    return -1;
  }

  oc_string64_t ep_str;
  if (!oc_endpoint_to_string64(endpoint, &ep_str)) {
    return -1;
  }
  oc_new_string(endpoint_str, oc_string(ep_str), oc_string_len(ep_str));
  return 0;
}

bool
oc_endpoint_to_string64(const oc_endpoint_t *endpoint,
                        oc_string64_t *endpoint_str)
{
  if (!endpoint || !endpoint_str) {
    return false;
  }
  memset(endpoint_str, 0, sizeof(oc_string64_t));
  int written = oc_endpoint_to_cstring(endpoint, oc_string(*endpoint_str),
                                       OC_ARRAY_SIZE(endpoint_str->ptr));
  if (written < 0) {
    return false;
  }
  endpoint_str->size = (size_t)written + 1;
  return true;
}

int
oc_endpoint_port(const oc_endpoint_t *endpoint)
{
  assert(endpoint != NULL);
  if ((endpoint->flags & IPV6) != 0) {
    return endpoint->addr.ipv6.port;
  }
#ifdef OC_IPV4
  if ((endpoint->flags & IPV4) != 0) {
    return endpoint->addr.ipv4.port;
  }
#endif /* OC_IPV4 */
  return -1;
}

#ifdef OC_IPV4
static void
oc_parse_ipv4_address(const char *address, size_t len, oc_endpoint_t *endpoint)
{
  uint8_t *addr = endpoint->addr.ipv4.address;
  size_t str_idx = 0;
  size_t addr_idx = 0;
  while (addr_idx < OC_IPV4_ADDRLEN && str_idx < len) {
    char *next_seg;
    addr[addr_idx++] = (uint8_t)strtoul(&address[str_idx], &next_seg, 10);
    if (next_seg && addr_idx < OC_IPV4_ADDRLEN) {
      str_idx += next_seg - &address[str_idx] + 1;
    }
  }
}
#endif /* OC_IPV4 */

static uint8_t
hex_to_bin(const char *hex, size_t len)
{
  uint8_t b = 0;
  for (size_t i = 0; i < len; ++i) {
    uint8_t h = hex[i];
    switch (h) {
    case '0':
      break;
    case '1':
      b |= 0x01;
      break;
    case '2':
      b |= 0x02;
      break;
    case '3':
      b |= 0x03;
      break;
    case '4':
      b |= 0x04;
      break;
    case '5':
      b |= 0x05;
      break;
    case '6':
      b |= 0x06;
      break;
    case '7':
      b |= 0x07;
      break;
    case '8':
      b |= 0x08;
      break;
    case '9':
      b |= 0x09;
      break;
    case 'a':
    case 'A':
      b |= 0x0a;
      break;
    case 'b':
    case 'B':
      b |= 0x0b;
      break;
    case 'c':
    case 'C':
      b |= 0x0c;
      break;
    case 'd':
    case 'D':
      b |= 0x0d;
      break;
    case 'e':
    case 'E':
      b |= 0x0e;
      break;
    case 'f':
    case 'F':
      b |= 0x0f;
      break;
    default:
      b |= h;
    }
    if (len > 1 && i < len - 1) {
      b <<= 4;
    }
  }

  return b;
}

static bool
oc_parse_ipv6_address(const char *address, size_t len, oc_endpoint_t *endpoint)
{
  uint8_t addr[OC_IPV6_ADDRLEN];
  memset(addr, 0, sizeof(addr));
  size_t str_idx = 0;
  size_t addr_idx = 0;
  long split = -1;
  size_t seg_len = 0;
  while (addr_idx < OC_IPV6_ADDRLEN - 1 && str_idx < len) {
    if (split == -1 && strncmp(&address[str_idx], "::", 2) == 0) {
      split = (long)addr_idx;
      str_idx += 2;
    }
    seg_len = len - str_idx;
    const char *next_seg =
      (const char *)memchr(&address[str_idx], ':', seg_len);
    if (next_seg) {
      seg_len = next_seg - &address[str_idx];
    }
    switch (seg_len) {
    case 4: {
      addr[addr_idx++] = hex_to_bin(&address[str_idx], 2);
      str_idx += 2;
      addr[addr_idx++] = hex_to_bin(&address[str_idx], 2);
      str_idx += 2;
    } break;
    case 3: {
      addr[addr_idx++] = hex_to_bin(&address[str_idx], 1);
      str_idx += 1;
      addr[addr_idx++] = hex_to_bin(&address[str_idx], 2);
      str_idx += 2;
    } break;
    case 2: {
      addr[addr_idx++] = 0;
      addr[addr_idx++] = hex_to_bin(&address[str_idx], 2);
      str_idx += 2;
    } break;
    case 1: {
      addr[addr_idx++] = 0;
      addr[addr_idx++] = hex_to_bin(&address[str_idx], 1);
      str_idx += 1;
    } break;
    case 0: {
      str_idx++;
    } break;
    default:
      return false;
    }
  }
  if (split != -1) {
    long i = (long)(addr_idx - 1);
    addr_idx = OC_IPV6_ADDRLEN - 1;
    while (i >= split) {
      // clang-format off
      GCC_IGNORE_WARNING_START
      GCC_IGNORE_WARNING("-Wstringop-overflow")
      addr[addr_idx] = addr[i];
      addr[i] = 0;
      GCC_IGNORE_WARNING_END
      i--;
      addr_idx--;
    }
  }
  memcpy(endpoint->addr.ipv6.address, addr, sizeof(addr));
  return true;
}

typedef struct endpoint_uri_t
{
  transport_flags scheme_flags;
  const char *address;
  size_t address_len;
  size_t host_len; // length of only the host part of the address
  const char *uri; // path part of the address (ie. part from the first "/")
  size_t uri_len;
  uint16_t port;
} endpoint_uri_t;

static int
parse_endpoint_flags(const oc_string_t *endpoint_str)
{
  const char *ep = oc_string(*endpoint_str);
  size_t ep_len = oc_string_len(*endpoint_str);
#ifdef OC_TCP
  if (ep_len > OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS_TCP) &&
      memcmp(OC_SCHEME_COAPS_TCP, ep, OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS_TCP)) ==
        0) {
    return TCP | SECURED;
  }
  if (ep_len > OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP_TCP) &&
      memcmp(OC_SCHEME_COAP_TCP, ep, OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP_TCP)) ==
        0) {
    return TCP;
  }
#endif /* OC_TCP */
  if (ep_len > OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS) &&
      memcmp(OC_SCHEME_COAPS, ep, OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS)) == 0) {
    return SECURED;
  }
  if (ep_len > OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP) &&
      memcmp(OC_SCHEME_COAP, ep, OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP)) == 0) {
    return 0;
  }
  return -1;
}

static bool
parse_endpoint_uri(const oc_string_t *endpoint_str,
                   endpoint_uri_t *endpoint_uri, bool parse_uri)
{
  const char *ep = oc_string(*endpoint_str);
  int flags = parse_endpoint_flags(endpoint_str);
  if (flags == -1) {
    OC_ERR("failed to parse scheme flags from endpoint address %s",
           ep != NULL ? ep : "");
    return false;
  }

  oc_string_view_t scheme = endpoint_flags_to_scheme(flags);
  const char *address = ep + scheme.length;
  size_t ep_len = oc_string_len(*endpoint_str);
  size_t address_len = ep_len - (address - ep);

  const char *u = (const char *)memchr(address, '/', address_len);
  const char *uri = NULL;
  size_t uri_len = 0;
  if (parse_uri && u != NULL) {
    uri = u;
    uri_len = address_len - (u - address);
  }

  /* Extract the port # if available */
  const char *p = NULL;
  /* If IPv6 address, look for port after ] */
  if (address[0] == '[') {
    p = (const char *)memchr(address, ']', address_len);
    if (p == NULL) {
      return false;
    }
    /* A : that ever follows ] must precede a port */
    p = (const char *)memchr(p, ':', address_len - (p - address + 1));
  } else {
    /* IPv4 address or hostname; the first : must precede a port */
    p = (const char *)memchr(address, ':', address_len);
  }

  size_t host_len = address_len;
  uint16_t port = 0;
  if (p != NULL) {
    /* Move from ':' to digits */
    const char *d = p + 1;
    /* Validate port */
    size_t port_len = u != NULL ? (size_t)(u - d) : address_len - (d - address);
    for (size_t i = 0; i < port_len; ++i) {
      if (d[i] < '0' || d[i] > '9') {
        OC_ERR("invalid port subcomponent in address(%s)", address);
        return false;
      }
    }

    /* Extract port # from string */
    port = (uint16_t)strtoul(d, NULL, 10);
    host_len = p - address;
  } else {
    /* Port not specified; assume 5683 for an unsecured ep and 5684 for
     * a secured ep
     */
    if ((flags & SECURED) != 0) {
      port = 5684;
    } else {
      port = 5683;
    }
    if (u != NULL) {
      host_len = u - address;
    }
  }

  endpoint_uri->scheme_flags = flags;
  endpoint_uri->address = address;
  endpoint_uri->address_len = address_len;
  endpoint_uri->host_len = host_len;
  endpoint_uri->uri = uri;
  endpoint_uri->uri_len = uri_len;
  endpoint_uri->port = port;
  return true;
}

#if defined(OC_DNS_LOOKUP) && (defined(OC_DNS_LOOKUP_IPV6) || defined(OC_IPV4))
static bool
dns_lookup(const char *domain, oc_string_t *addr, transport_flags flags)
{
#ifdef OC_IPV4
  if (oc_dns_lookup(domain, addr, flags | IPV4) == 0) {
    return true;
  }
#endif /* OC_IPV4 */
#ifdef OC_DNS_LOOKUP_IPV6
  if (oc_dns_lookup(domain, addr, flags | IPV6) == 0) {
    return true;
  }
#endif /* OC_DNS_LOOKUP_IPV6 */
  return false;
}
#endif /* OC_DNS_LOOKUP && (OC_DNS_LOOKUP_IPV6 || OC_IPV4) */

static int
oc_parse_endpoint_string(const oc_string_t *endpoint_str,
                         oc_endpoint_t *endpoint, oc_string_t *uri)
{
  endpoint_uri_t ep_uri;
  memset(&ep_uri, 0, sizeof(endpoint_uri_t));
  if (!parse_endpoint_uri(endpoint_str, &ep_uri, uri != NULL)) {
    return -1;
  }

  const char *address = ep_uri.address;
  size_t host_len = ep_uri.host_len;
#ifdef OC_DNS_LOOKUP
  oc_string_t ipaddress;
  memset(&ipaddress, 0, sizeof(oc_string_t));
#endif /* OC_DNS_LOOKUP */
  if (('A' <= address[host_len - 1] && 'Z' >= address[host_len - 1]) ||
      ('a' <= address[host_len - 1] && 'z' >= address[host_len - 1])) {
#if defined(OC_DNS_LOOKUP) && (defined(OC_DNS_LOOKUP_IPV6) || defined(OC_IPV4))
#define MAX_HOST_LEN 254
    if (host_len > MAX_HOST_LEN) {
      // https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4
      OC_ERR("invalid domain length(%zu) of address(%s)", host_len, address);
      return -1;
    }
    char domain[MAX_HOST_LEN + 1];
    strncpy(domain, address, host_len);
    domain[host_len] = '\0';
    if (!dns_lookup(domain, &ipaddress, ep_uri.scheme_flags)) {
      OC_ERR("failed to resolve domain(%s)", domain);
      return -1;
    }

    address = oc_string(ipaddress);
    host_len = oc_string_len(ipaddress);
#else  /* !OC_DNS_LOOKUP || (!OC_DNS_LOOKUP_IPV6 && !OC_IPV4) */
    OC_ERR("cannot resolve address(%s): dns resolution disabled", address);
    return -1;
#endif /* OC_DNS_LOOKUP && (OC_DNS_LOOKUP_IPV6 || OC_IPV4) */
  }

  if (host_len > 1 && address[0] == '[' && address[host_len - 1] == ']') {
    if (!oc_parse_ipv6_address(&address[1], host_len - 2, endpoint)) {
      OC_ERR("cannot resolve address(%s): cannot parse ipv6 address", address);
      return -1;
    }
    endpoint->flags = ep_uri.scheme_flags | IPV6;
    endpoint->addr.ipv6.port = ep_uri.port;
  }
#ifdef OC_IPV4
  else {
    endpoint->flags = ep_uri.scheme_flags | IPV4;
    endpoint->addr.ipv4.port = ep_uri.port;
    oc_parse_ipv4_address(address, host_len, endpoint);
  }
#else /* OC_IPV4 */
  else {
#ifdef OC_DNS_LOOKUP
    oc_free_string(&ipaddress);
#endif /* OC_DNS_LOOKUP */
    return -1;
  }
#endif /* !OC_IPV4 */
#ifdef OC_DNS_LOOKUP
  oc_free_string(&ipaddress);
#endif /* OC_DNS_LOOKUP */

  /* Extract a uri path if requested and available */
  if (uri != NULL && ep_uri.uri != NULL) {
    oc_new_string(uri, ep_uri.uri, ep_uri.uri_len);
  }

  return 0;
}

int
oc_string_to_endpoint(const oc_string_t *endpoint_str, oc_endpoint_t *endpoint,
                      oc_string_t *uri)
{
  if (endpoint_str == NULL || endpoint == NULL) {
    return -1;
  }
  memset(endpoint, 0, sizeof(oc_endpoint_t));
  return oc_parse_endpoint_string(endpoint_str, endpoint, uri);
}

int
oc_endpoint_string_parse_path(const oc_string_t *endpoint_str,
                              oc_string_t *path)
{
  if (endpoint_str == NULL || path == NULL) {
    return -1;
  }

#define SCHEME_SEPARATOR "://"
#define SCHEME_SEPARATOR_LEN (sizeof(SCHEME_SEPARATOR) - 1)
  const char *address = strstr(oc_string(*endpoint_str), SCHEME_SEPARATOR);
  if (address == NULL) {
    return -1;
  }
  // move past scheme
  address += SCHEME_SEPARATOR_LEN;

  size_t len =
    oc_string_len(*endpoint_str) - (address - oc_string(*endpoint_str));

  // the smallest possible address is '0' anything smaller is invalid.
  if (len < 1) {
    return -1;
  }
  /* Extract a uri path if available */
  const char *path_start = (const char *)memchr(address, '/', len);
  if (path_start == NULL) {
    // no path found return error
    return -1;
  }

  const char *query_start = (const char *)memchr(
    (address + (path_start - address)), '?', (len - (path_start - address)));
  if (query_start != NULL) {
    oc_new_string(path, path_start, (query_start - path_start));
  } else {
    oc_new_string(path, path_start, (len - (path_start - address)));
  }
  return 0;
}

int
oc_ipv6_endpoint_is_link_local(const oc_endpoint_t *endpoint)
{
  if (!endpoint || !(endpoint->flags & IPV6)) {
    return -1;
  }
  if (endpoint->addr.ipv6.address[0] == 0xfe &&
      endpoint->addr.ipv6.address[1] == 0x80) {
    return 0;
  }
  return -1;
}

int
oc_endpoint_compare_address(const oc_endpoint_t *ep1, const oc_endpoint_t *ep2)
{
  if (!ep1 || !ep2) {
    return -1;
  }

  if ((ep1->flags & ep2->flags) & IPV6) {
    if (memcmp(ep1->addr.ipv6.address, ep2->addr.ipv6.address, 16) == 0) {
      return 0;
    }
    return -1;
  }
#ifdef OC_IPV4
  if ((ep1->flags & ep2->flags) & IPV4) {
    if (memcmp(ep1->addr.ipv4.address, ep2->addr.ipv4.address, 4) == 0) {
      return 0;
    }
    return -1;
  }
#endif /* OC_IPV4 */
  // TODO: Add support for other endpoint types
  return -1;
}

int
oc_endpoint_compare(const oc_endpoint_t *ep1, const oc_endpoint_t *ep2)
{
  if (!ep1 || !ep2) {
    return -1;
  }

  if ((ep1->flags & ~(MULTICAST | ACCEPTED)) !=
        (ep2->flags & ~(MULTICAST | ACCEPTED)) ||
      ep1->device != ep2->device) {
    return -1;
  }
  if (ep1->flags & IPV6) {
    if (memcmp(ep1->addr.ipv6.address, ep2->addr.ipv6.address, 16) == 0 &&
        ep1->addr.ipv6.port == ep2->addr.ipv6.port) {
      return 0;
    }
    return -1;
  }
#ifdef OC_IPV4
  else if (ep1->flags & IPV4) {
    if (memcmp(ep1->addr.ipv4.address, ep2->addr.ipv4.address, 4) == 0 &&
        ep1->addr.ipv4.port == ep2->addr.ipv4.port) {
      return 0;
    }
    return -1;
  }
#endif /* OC_IPV4 */
  // TODO: Add support for other endpoint types
  return -1;
}

bool
oc_endpoint_is_empty(const oc_endpoint_t *endpoint)
{
  oc_endpoint_t empty;
  memset(&empty, 0, sizeof(oc_endpoint_t));
  return memcmp(&empty, endpoint, sizeof(oc_endpoint_t)) == 0; // NOLINT(bugprone-suspicious-memory-comparison)
}

void
oc_endpoint_copy(oc_endpoint_t *dst, const oc_endpoint_t *src)
{
  memcpy(dst, src, sizeof(oc_endpoint_t));
  dst->next = NULL;
}

int
oc_endpoint_list_copy(oc_endpoint_t **dst, const oc_endpoint_t *src)
{
  assert(dst != NULL);
  if (src == NULL) {
    return 0;
  }

  oc_endpoint_t *head = oc_new_endpoint();
  if (head == NULL) {
    OC_ERR("cannot allocate endpoint list head");
    return -1;
  }
  int count = 0;
  oc_endpoint_t *ep = head;
  while (src != NULL) {
    oc_endpoint_copy(ep, src);
    ++count;
    src = src->next;
    if (src != NULL) {
      ep->next = oc_new_endpoint();
      if (ep->next == NULL) {
        OC_ERR("cannot allocate endpoint list item");
        goto oc_endpoint_list_copy_err;
      }
      ep = ep->next;
    }
  }
  *dst = head;
  return count;

oc_endpoint_list_copy_err:
  oc_endpoint_list_free(head);
  return -1;
}

void
oc_endpoint_list_free(oc_endpoint_t *eps)
{
  while (eps != NULL) {
    oc_endpoint_t *ep_next = eps->next;
    oc_free_endpoint(eps);
    eps = ep_next;
  }
}

#ifdef OC_CLIENT
void
oc_endpoint_set_local_address(oc_endpoint_t *ep, unsigned interface_index)
{
  oc_endpoint_t *e = oc_connectivity_get_endpoints(ep->device);
  transport_flags conn = (ep->flags & IPV6) ? IPV6 : IPV4;
  while (e) {
    if ((e->flags & conn) && e->interface_index == interface_index) {
      memcpy(&ep->addr_local, &e->addr, sizeof(e->addr));
      return;
    }
    e = e->next;
  }
}
#endif /* OC_CLIENT */

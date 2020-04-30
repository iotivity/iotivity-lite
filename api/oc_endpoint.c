/*
// Copyright (c) 2017 Intel Corporation
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

#include "oc_endpoint.h"
#include "oc_core_res.h"
#include "port/oc_connectivity.h"
#include "port/oc_network_events_mutex.h"
#include "util/oc_memb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define OC_SCHEME_COAP "coap://"
#define OC_SCHEME_COAPS "coaps://"
#define OC_SCHEME_COAP_TCP "coap+tcp://"
#define OC_SCHEME_COAPS_TCP "coaps+tcp://"

#define OC_IPV6_ADDRSTRLEN (46)
#define OC_IPV4_ADDRSTRLEN (16)
#define OC_IPV6_ADDRLEN (16)
#define OC_IPV4_ADDRLEN (4)

OC_MEMB(oc_endpoints_s, oc_endpoint_t, OC_MAX_NUM_ENDPOINTS);

oc_endpoint_t *
oc_new_endpoint(void)
{
#ifndef OC_DYNAMIC_ALLOCATION
  oc_network_event_handler_mutex_lock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_endpoint_t *endpoint = oc_memb_alloc(&oc_endpoints_s);
#ifndef OC_DYNAMIC_ALLOCATION
  oc_network_event_handler_mutex_unlock();
#endif /* !OC_DYNAMIC_ALLOCATION */
  return endpoint;
}

void
oc_free_endpoint(oc_endpoint_t *endpoint)
{
  if (endpoint) {
    oc_memb_free(&oc_endpoints_s, endpoint);
  }
}

void
oc_endpoint_set_di(oc_endpoint_t *endpoint, oc_uuid_t *di)
{
  if (endpoint && di) {
    memcpy(endpoint->di.id, di->id, 16);
  }
}

#ifdef OC_IPV4
static void
oc_ipv4_endpoint_to_string(oc_endpoint_t *endpoint, oc_string_t *endpoint_str)
{
  if (!endpoint || !endpoint_str) {
    return;
  }
  char ip[OC_IPV4_ADDRSTRLEN + 6];
  uint8_t *addr = endpoint->addr.ipv4.address;
  sprintf(ip, "%u.%u.%u.%u:%u", addr[0], addr[1], addr[2], addr[3],
          endpoint->addr.ipv4.port);
#ifdef OC_TCP
  if (endpoint->flags & TCP) {
    if (endpoint->flags & SECURED) {
      oc_concat_strings(endpoint_str, OC_SCHEME_COAPS_TCP, ip);
    } else {
      oc_concat_strings(endpoint_str, OC_SCHEME_COAP_TCP, ip);
    }
  } else
#endif
    if (endpoint->flags & SECURED) {
    oc_concat_strings(endpoint_str, OC_SCHEME_COAPS, ip);
  } else {
    oc_concat_strings(endpoint_str, OC_SCHEME_COAP, ip);
  }
}
#endif /* OC_IPV4 */

static void
oc_ipv6_endpoint_to_string(oc_endpoint_t *endpoint, oc_string_t *endpoint_str)
{
  if (!endpoint || !endpoint_str) {
    return;
  }
  uint8_t *addr = endpoint->addr.ipv6.address;
  char ip[OC_IPV6_ADDRSTRLEN + 8];
  int addr_idx = 0, str_idx = 0, start_zeros = 0, last_zeros = OC_IPV6_ADDRLEN,
      num_zeros = 0, max_zeros_start = 0, max_zeros_num = 0;
  ip[str_idx++] = '[';
  while (addr_idx < OC_IPV6_ADDRLEN) {
    if (addr_idx % 2 == 0 && addr[addr_idx] == 0 && addr[addr_idx + 1] == 0) {
      if (last_zeros != addr_idx - 2) {
        start_zeros = str_idx;
        num_zeros = 0;
      }
      last_zeros = addr_idx;
      num_zeros += 2;
      addr_idx += 2;
    } else {
      if (num_zeros > max_zeros_num) {
        max_zeros_num = num_zeros;
        max_zeros_start = start_zeros;
      }
      if (addr_idx > 0 && addr_idx <= 14) {
        ip[str_idx++] = ':';
      }
    next_octet:
      if (addr_idx % 2 == 0 && addr[addr_idx] == 0) {
        /* Skip zero octet */
      } else if ((addr_idx % 2 == 0 ||
                  (addr_idx > 0 && addr[addr_idx - 1]) == 0) &&
                 addr[addr_idx] <= 0x0f) {
        snprintf(&ip[str_idx++], 2, "%x", addr[addr_idx]);
      } else {
        snprintf(&ip[str_idx], 3, "%02x", addr[addr_idx]);
        str_idx += 2;
      }
      addr_idx++;
      if (addr_idx % 2 != 0) {
        goto next_octet;
      }
    }
  }
  if (num_zeros > max_zeros_num) {
    max_zeros_start = start_zeros;
  }
  if (last_zeros == OC_IPV6_ADDRLEN - 2) {
    ip[str_idx++] = ':';
  }
  int i = str_idx;
  while (max_zeros_start != 0 && i > max_zeros_start) {
    ip[i] = ip[i - 1];
    i--;
  }
  if (max_zeros_start != 0) {
    sprintf(&ip[str_idx + 1], "]:%u", endpoint->addr.ipv6.port);
  } else {
    sprintf(&ip[str_idx], "]:%u", endpoint->addr.ipv6.port);
  }
#ifdef OC_TCP
  if (endpoint->flags & TCP) {
    if (endpoint->flags & SECURED) {
      oc_concat_strings(endpoint_str, OC_SCHEME_COAPS_TCP, ip);
    } else {
      oc_concat_strings(endpoint_str, OC_SCHEME_COAP_TCP, ip);
    }
  } else
#endif
    if (endpoint->flags & SECURED) {
    oc_concat_strings(endpoint_str, OC_SCHEME_COAPS, ip);
  } else {
    oc_concat_strings(endpoint_str, OC_SCHEME_COAP, ip);
  }
}

int
oc_endpoint_to_string(oc_endpoint_t *endpoint, oc_string_t *endpoint_str)
{
  if (!endpoint || !endpoint_str)
    return -1;

  if (endpoint->flags & IPV6) {
    oc_ipv6_endpoint_to_string(endpoint, endpoint_str);
  }
#ifdef OC_IPV4
  else if (endpoint->flags & IPV4) {
    oc_ipv4_endpoint_to_string(endpoint, endpoint_str);
  }
#endif /* OC_IPV4 */
  else {
    return -1;
  }
  return 0;
}

#ifdef OC_IPV4
static void
oc_parse_ipv4_address(const char *address, size_t len, oc_endpoint_t *endpoint)
{
  if (!address || !endpoint) {
    return;
  }
  uint8_t *addr = endpoint->addr.ipv4.address;
  size_t str_idx = 0, addr_idx = 0;
  char *next_seg;
  while (addr_idx < OC_IPV4_ADDRLEN && str_idx < len) {
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
  size_t n = 0;
  uint8_t h, b = 0;
low_nibble:
  h = hex[n];
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
  if (n == 0 && len > 1) {
    b <<= 4;
    n = 1;
    goto low_nibble;
  }
  return b;
}

static void
oc_parse_ipv6_address(const char *address, size_t len, oc_endpoint_t *endpoint)
{
  if (!address || !endpoint) {
    return;
  }
  uint8_t *addr = endpoint->addr.ipv6.address;
  memset(addr, 0, OC_IPV6_ADDRLEN);
  int str_idx = 0, addr_idx = 0, split = -1;
  size_t seg_len = 0;
  while (addr_idx < OC_IPV6_ADDRLEN - 1 && str_idx < (int)len) {
    if (split == -1 && strncmp(&address[str_idx], "::", 2) == 0) {
      split = addr_idx;
      str_idx += 2;
    }
    seg_len = len - str_idx;
    const char *next_seg = memchr(&address[str_idx], ':', seg_len);
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
      break;
    }
  }
  if (split != -1) {
    int i = addr_idx - 1;
    addr_idx = OC_IPV6_ADDRLEN - 1;
    while (i >= split) {
      addr[addr_idx] = addr[i];
      addr[i] = 0;
      i--;
      addr_idx--;
    }
  }
}

static int
oc_parse_endpoint_string(oc_string_t *endpoint_str, oc_endpoint_t *endpoint,
                         oc_string_t *uri)
{
  if (!endpoint_str || !endpoint)
    return -1;

  const char *address = NULL;
  endpoint->device = 0;
  endpoint->flags = 0;
  size_t len = oc_string_len(*endpoint_str);
#ifdef OC_TCP
  if (len > strlen(OC_SCHEME_COAPS_TCP) &&
      memcmp(OC_SCHEME_COAPS_TCP, oc_string(*endpoint_str),
             strlen(OC_SCHEME_COAPS_TCP)) == 0) {
    address = oc_string(*endpoint_str) + strlen(OC_SCHEME_COAPS_TCP);
    endpoint->flags = TCP | SECURED;
  } else if (len > strlen(OC_SCHEME_COAP_TCP) &&
             memcmp(OC_SCHEME_COAP_TCP, oc_string(*endpoint_str),
                    strlen(OC_SCHEME_COAP_TCP)) == 0) {
    address = oc_string(*endpoint_str) + strlen(OC_SCHEME_COAP_TCP);
    endpoint->flags = TCP;
  } else
#endif
    if (len > strlen(OC_SCHEME_COAPS) &&
        memcmp(OC_SCHEME_COAPS, oc_string(*endpoint_str),
               strlen(OC_SCHEME_COAPS)) == 0) {
    address = oc_string(*endpoint_str) + strlen(OC_SCHEME_COAPS);
    endpoint->flags = SECURED;
  } else if (len > strlen(OC_SCHEME_COAP) &&
             memcmp(OC_SCHEME_COAP, oc_string(*endpoint_str),
                    strlen(OC_SCHEME_COAP)) == 0) {
    address = oc_string(*endpoint_str) + strlen(OC_SCHEME_COAP);
  } else {
    return -1;
  }

  len = oc_string_len(*endpoint_str) - (address - oc_string(*endpoint_str));

  /* Extract a uri path if requested and available */
  const char *u = NULL;
  u = memchr(address, '/', len);
  if (uri) {
    if (u) {
      oc_new_string(uri, u, (len - (u - address)));
    }
  }

  /* Extract the port # if avilable */
  const char *p = NULL;
  /* If IPv6 address, look for port after ] */
  if (address[0] == '[') {
    p = memchr(address, ']', len);
    if (!p) {
      return -1;
    }
    /* A : that ever follows ] must precede a port */
    p = memchr(p, ':', len - (p - address + 1));
  } else {
    /* IPv4 address or hostname; the first : must precede a port */
    p = memchr(address, ':', len);
  }

  uint16_t port = 0;
  if (p) {
    /* Extract port # from string */
    port = (uint16_t)strtoul(p + 1, NULL, 10);
  } else {
    /* Port not specified; assume 5683 for an unsecured ep and 5684 for
     * a secured ep
     */
    if (endpoint->flags & SECURED) {
      port = 5684;
    } else {
      port = 5683;
    }
    if (u != NULL) {
      p = u;
    } else {
      p = address + len;
    }
  }
  /* At this point 'p' points to the location immediately following
   * the last character of the address
   */
  size_t address_len = p - address;
#ifdef OC_DNS_LOOKUP
  oc_string_t ipaddress;
  memset(&ipaddress, 0, sizeof(oc_string_t));
#endif /* OC_DNS_LOOKUP */
  if (('A' <= address[address_len - 1] && 'Z' >= address[address_len - 1]) ||
      ('a' <= address[address_len - 1] && 'z' >= address[address_len - 1])) {
#ifdef OC_DNS_LOOKUP
    if (address_len > 254) {
      // https://www.rfc-editor.org/rfc/rfc1035.html#section-2.3.4
      return -1;
    }
    char domain[255];
    strncpy(domain, address, address_len);
    domain[address_len] = '\0';
#ifdef OC_DNS_LOOKUP_IPV6
    if (oc_dns_lookup(domain, &ipaddress, endpoint->flags | IPV6) != 0) {
#endif /* OC_DNS_LOOKUP_IPV6 */
      if (oc_dns_lookup(domain, &ipaddress, endpoint->flags | IPV4) != 0) {
        return -1;
      }
#ifdef OC_DNS_LOOKUP_IPV6
    }
#endif /* OC_DNS_LOOKUP_IPV6 */
    address = oc_string(ipaddress);
    address_len = oc_string_len(ipaddress);
#else  /* OC_DNS_LOOKUP */
    return -1;
#endif /* !OC_DNS_LOOKUP */
  }

  if (address[0] == '[' && address[address_len - 1] == ']') {
    endpoint->flags |= IPV6;
    endpoint->addr.ipv6.port = port;
    oc_parse_ipv6_address(&address[1], address_len - 2, endpoint);
  }
#ifdef OC_IPV4
  else {
    endpoint->flags |= IPV4;
    endpoint->addr.ipv4.port = port;
    oc_parse_ipv4_address(address, address_len, endpoint);
  }
#else /* OC_IPV4 */
  else {
#ifdef OC_DNS_LOOKUP
    if (oc_string_len(ipaddress) > 0)
      oc_free_string(&ipaddress);
#endif /* OC_DNS_LOOKUP */
    return -1;
  }
#endif /* !OC_IPV4 */
#ifdef OC_DNS_LOOKUP
  if (oc_string_len(ipaddress) > 0)
    oc_free_string(&ipaddress);
#endif /* OC_DNS_LOOKUP */
  return 0;
}

int
oc_string_to_endpoint(oc_string_t *endpoint_str, oc_endpoint_t *endpoint,
                      oc_string_t *uri)
{
  if (endpoint && endpoint_str) {
    memset(endpoint, 0, sizeof(oc_endpoint_t));
    return oc_parse_endpoint_string(endpoint_str, endpoint, uri);
  }
  return -1;
}

int
oc_endpoint_string_parse_path(oc_string_t *endpoint_str, oc_string_t *path)
{
  if (!endpoint_str) {
    return -1;
  }
  if (!path) {
    return -1;
  }

  const char *address = NULL;

  address = strstr(oc_string(*endpoint_str), "://");
  if (!address) {
    return -1;
  }
  // 3 is string length of "://"
  address += 3;

  size_t len =
    oc_string_len(*endpoint_str) - (address - oc_string(*endpoint_str));

  // the smallest possible address is '0' anything smaller is invalid.
  if (len < 1) {
    return -1;
  }
  /* Extract a uri path if available */
  const char *path_start = NULL;
  const char *query_start = NULL;

  path_start = memchr(address, '/', len);

  if (!path_start) {
    // no path found return error
    return -1;
  }

  query_start = memchr((address + (path_start - address)), '?',
                       (len - (path_start - address)));
  if (query_start) {
    oc_new_string(path, path_start, (query_start - path_start));
  } else {
    oc_new_string(path, path_start, (len - (path_start - address)));
  }
  return 0;
}

int
oc_ipv6_endpoint_is_link_local(oc_endpoint_t *endpoint)
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
  if (!ep1 || !ep2)
    return -1;

  if ((ep1->flags & ep2->flags) & IPV6) {
    if (memcmp(ep1->addr.ipv6.address, ep2->addr.ipv6.address, 16) == 0) {
      return 0;
    }
    return -1;
  }
#ifdef OC_IPV4
  else if ((ep1->flags & ep2->flags) & IPV4) {
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
  if (!ep1 || !ep2)
    return -1;

  if ((ep1->flags & ~MULTICAST) != (ep2->flags & ~MULTICAST) ||
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

void
oc_endpoint_copy(oc_endpoint_t *dst, oc_endpoint_t *src)
{
  if (dst && src) {
    memcpy(dst, src, sizeof(oc_endpoint_t));
    dst->next = NULL;
  }
}

void
oc_endpoint_list_copy(oc_endpoint_t **dst, oc_endpoint_t *src)
{
  if (dst && src) {
    oc_endpoint_t *ep = oc_new_endpoint();
    *dst = ep;
    while (src && ep) {
      oc_endpoint_copy(ep, src);
      src = src->next;
      if (src) {
        ep->next = oc_new_endpoint();
        ep = ep->next;
      }
    }
  }
}

#ifdef OC_CLIENT
void
oc_endpoint_set_local_address(oc_endpoint_t *ep, int interface_index)
{
  if (!ep) {
    return;
  }
  oc_endpoint_t *e = oc_connectivity_get_endpoints(ep->device);
  enum transport_flags conn = (ep->flags & IPV6) ? IPV6 : IPV4;
  while (e) {
    if ((e->flags & conn) && e->interface_index == interface_index) {
      memcpy(&ep->addr_local, &e->addr, sizeof(union dev_addr));
      return;
    }
    e = e->next;
  }
}
#endif /* OC_CLIENT */

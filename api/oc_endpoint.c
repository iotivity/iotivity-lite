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
OC_LIST(oc_endpoints);

void
oc_init_endpoint_list(void)
{
  oc_list_init(oc_endpoints);
}

oc_endpoint_t *
oc_get_endpoint_list(void)
{
  return oc_list_head(oc_endpoints);
}

int
oc_add_endpoint_to_list(oc_endpoint_t *endpoint)
{
  oc_endpoint_t *ep = oc_new_endpoint();
  if (ep != NULL) {
    memcpy(ep, endpoint, sizeof(oc_endpoint_t));
    ep->priority = 1;
    oc_list_add(oc_endpoints, ep);
    return 0;
  }
  return -1;
}

void
oc_free_endpoint_list(void)
{
  oc_endpoint_t *ep = (oc_endpoint_t *)oc_list_head(oc_endpoints), *next;
  while (ep != NULL) {
    next = ep->next;
    oc_memb_free(&oc_endpoints_s, ep);
    ep = next;
  }
  oc_init_endpoint_list();
}

oc_endpoint_t *
oc_new_endpoint(void)
{
  oc_endpoint_t *endpoint = oc_memb_alloc(&oc_endpoints_s);
  if (endpoint) {
    memset(endpoint, 0, sizeof(oc_endpoint_t));
  }
  return endpoint;
}

void
oc_free_endpoint(oc_endpoint_t *endpoint)
{
  oc_memb_free(&oc_endpoints_s, endpoint);
}

#ifdef OC_IPV4
static void
oc_ipv4_endpoint_to_string(oc_endpoint_t *endpoint, oc_string_t *endpoint_str)
{
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
    next_octect:
      if (addr_idx % 2 == 0 && addr[addr_idx] == 0) {
        /* Skip zero octect */
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
        goto next_octect;
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
  uint8_t *addr = endpoint->addr.ipv6.address;
  memset(addr, 0, OC_IPV6_ADDRLEN);
  int str_idx = 0, addr_idx = 0, split = -1, seg_len = 0;
  while (addr_idx < OC_IPV6_ADDRLEN - 2 && str_idx < (int)len) {
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
  endpoint->flags = 0;
#ifdef OC_TCP
  if (memcmp(OC_SCHEME_COAPS_TCP, oc_string(*endpoint_str),
             strlen(OC_SCHEME_COAPS_TCP)) == 0) {
    endpoint->flags = TCP | SECURED;
  } else if (memcmp(OC_SCHEME_COAP_TCP, oc_string(*endpoint_str),
                    strlen(OC_SCHEME_COAP_TCP)) == 0) {
    endpoint->flags = TCP;
  } else
#endif
  if (memcmp(OC_SCHEME_COAPS, oc_string(*endpoint_str),
             strlen(OC_SCHEME_COAPS)) == 0) {
    endpoint->flags = SECURED;
  } else if (memcmp(OC_SCHEME_COAP, oc_string(*endpoint_str),
                    strlen(OC_SCHEME_COAP)) == 0) {
    /* Do nothing */
  } else {
    return -1;
  }
  int len = oc_string_len(*endpoint_str);
  const char *p = strrchr(oc_string(*endpoint_str), ':');
  char *u = 0;
  if (p) {
    p += 1;
    uint16_t port = (uint16_t)strtoul(p, (char **)&u, 10);
    if (u && (u - oc_string(*endpoint_str)) < len) {
      oc_new_string(uri, u, (len - (u - oc_string(*endpoint_str))));
    }

    const char *address = memchr(oc_string(*endpoint_str), '/', len);
    address += 2;
    int address_len = (p - address - 1);
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
#else  /* OC_IPV4 */
    else {
      return -1;
    }
#endif /* !OC_IPV4 */
    return 0;
  }
  return -1;
}

int
oc_string_to_endpoint(oc_string_t *endpoint_str, oc_endpoint_t *endpoint,
                      oc_string_t *uri)
{
  return oc_parse_endpoint_string(endpoint_str, endpoint, uri);
}

int
oc_ipv6_endpoint_is_link_local(oc_endpoint_t *endpoint)
{
  if (!(endpoint->flags & IPV6)) {
    return -1;
  }
  if (endpoint->addr.ipv6.address[0] == 0xfe &&
      endpoint->addr.ipv6.address[1] == 0x80) {
    return 0;
  }
  return -1;
}

int
oc_endpoint_compare_address(oc_endpoint_t *ep1, oc_endpoint_t *ep2)
{
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
oc_endpoint_compare(oc_endpoint_t *ep1, oc_endpoint_t *ep2)
{
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

/****************************************************************************
 *
 * Copyright (c) 2025 plgd.dev s.r.o.
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

#include "netif.h"

#ifdef OC_NETWORK_MONITOR
#include "api/oc_network_events_internal.h"
#include "oc_network_monitor.h"
#include "port/oc_log_internal.h"
#include "util/oc_list.h"
#include "util/oc_memb.h"
#endif /* OC_NETWORK_MONITOR */

#include <esp_idf_version.h>
#include <esp_netif.h>
#include <net/if.h>

#ifdef OC_NETWORK_MONITOR

/**
 * Structure to manage interface list.
 */
typedef struct ip_interface
{
  struct ip_interface *next;
  int if_index;
} ip_interface_t;

OC_LIST(ip_interface_list);
OC_MEMB(ip_interface_s, ip_interface_t, OC_MAX_IP_INTERFACES);

OC_LIST(oc_network_interface_cb_list);
OC_MEMB(oc_network_interface_cb_s, oc_network_interface_cb_t,
        OC_MAX_NETWORK_INTERFACE_CBS);

static ip_interface_t *
get_ip_interface(int target_index)
{
  ip_interface_t *if_item = oc_list_head(ip_interface_list);
  while (if_item != NULL && if_item->if_index != target_index) {
    if_item = if_item->next;
  }
  return if_item;
}

bool
oc_netif_add_ip_interface(int target_index)
{
  if (get_ip_interface(target_index))
    return false;

  ip_interface_t *new_if = oc_memb_alloc(&ip_interface_s);
  if (!new_if) {
    OC_ERR("interface item alloc failed");
    return false;
  }
  new_if->if_index = target_index;
  oc_list_add(ip_interface_list, new_if);
  OC_DBG("New interface added: %d", new_if->if_index);
  return true;
}

static bool
oc_netif_iterate_add_new_ip_interfaces(esp_netif_t *netif, void *)
{
  oc_netif_add_ip_interface(esp_netif_get_netif_impl_index(netif));
  return true;
}

bool
oc_netif_check_new_ip_interfaces(void)
{
  return oc_netif_iterate_interfaces(oc_netif_iterate_add_new_ip_interfaces,
                                     NULL) == ESP_OK;
}

bool
oc_netif_remove_ip_interface(int target_index)
{
  ip_interface_t *if_item = get_ip_interface(target_index);
  if (!if_item) {
    return false;
  }

  oc_list_remove(ip_interface_list, if_item);
  oc_memb_free(&ip_interface_s, if_item);
  OC_DBG("Removed from ip interface list: %d", target_index);
  return true;
}

void
remove_all_ip_interface(void)
{
  ip_interface_t *if_item = oc_list_head(ip_interface_list), *next;
  while (if_item != NULL) {
    next = if_item->next;
    oc_list_remove(ip_interface_list, if_item);
    oc_memb_free(&ip_interface_s, if_item);
    if_item = next;
  }
}

static void
remove_all_network_interface_cbs(void)
{
  oc_network_interface_cb_t *cb_item =
                              oc_list_head(oc_network_interface_cb_list),
                            *next;
  while (cb_item != NULL) {
    next = cb_item->next;
    oc_list_remove(oc_network_interface_cb_list, cb_item);
    oc_memb_free(&oc_network_interface_cb_s, cb_item);
    cb_item = next;
  }
}

int
oc_add_network_interface_event_callback(interface_event_handler_t cb)
{
  if (!cb)
    return -1;

  oc_network_interface_cb_t *cb_item =
    oc_memb_alloc(&oc_network_interface_cb_s);
  if (!cb_item) {
    OC_ERR("network interface callback item alloc failed");
    return -1;
  }

  cb_item->handler = cb;
  oc_list_add(oc_network_interface_cb_list, cb_item);
  return 0;
}

int
oc_remove_network_interface_event_callback(interface_event_handler_t cb)
{
  if (!cb)
    return -1;

  oc_network_interface_cb_t *cb_item =
    oc_list_head(oc_network_interface_cb_list);
  while (cb_item != NULL && cb_item->handler != cb) {
    cb_item = cb_item->next;
  }
  if (!cb_item) {
    return -1;
  }
  oc_list_remove(oc_network_interface_cb_list, cb_item);

  oc_memb_free(&oc_network_interface_cb_s, cb_item);
  return 0;
}

void
handle_network_interface_event_callback(oc_interface_event_t event)
{
  if (oc_list_length(oc_network_interface_cb_list) > 0) {
    oc_network_interface_cb_t *cb_item =
      oc_list_head(oc_network_interface_cb_list);
    while (cb_item) {
      cb_item->handler(event);
      cb_item = cb_item->next;
    }
  }
}

#endif /* OC_NETWORK_MONITOR */

#ifdef OC_TCP

static bool
netif_match_inferface(esp_netif_t *netif, void *user_data)
{
  struct sockaddr_storage *addr = (struct sockaddr_storage *)user_data;
  if (addr->ss_family == AF_INET) {
    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
      return false;
    }
    struct sockaddr_in *b = (struct sockaddr_in *)addr;
    return b->sin_addr.s_addr == ip_info.ip.addr;
  }

  // match IPv6 address
  if (addr->ss_family == AF_INET6) {
    struct sockaddr_in6 *b = (struct sockaddr_in6 *)addr;
    esp_ip6_addr_t if_ip6[LWIP_IPV6_NUM_ADDRESSES];
    int num = esp_netif_get_all_ip6(netif, if_ip6);
    for (int i = 0; i < num; ++i) {
      if (ip6_addr_isany(&if_ip6[i]) || ip6_addr_isloopback(&if_ip6[i])) {
        continue;
      }
      return memcmp(&if_ip6[i].addr, b->sin6_addr.s6_addr, 16) == 0;
    }
    return false;
  }

  return false;
}

#endif /* OC_TCP */

#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 4, 0)

typedef struct
{
  oc_netif_iterate_interfaces_fn_t fn;
  void *user_data;
} oc_netif_iterate_interfaces_t;

static esp_err_t
netif_iterate_interfaces(void *data)
{
  oc_netif_iterate_interfaces_t *ctx = (oc_netif_iterate_interfaces_t *)data;
  for (esp_netif_t *esp_netif = esp_netif_next_unsafe(NULL); esp_netif != NULL;
       esp_netif = esp_netif_next_unsafe(esp_netif)) {
    if (!ctx->fn(esp_netif, ctx->user_data)) {
      break;
    }
  }
  return ESP_OK;
}

esp_err_t
oc_netif_iterate_interfaces(oc_netif_iterate_interfaces_fn_t fn,
                            void *user_data)
{
  oc_netif_iterate_interfaces_t ctx = {
    .fn = fn,
    user_data = user_data,
  };
  return esp_netif_tcpip_exec(netif_iterate_interfaces, &ctx);
}

#ifdef OC_TCP

static bool
netif_match_active_inferface(esp_netif_t *netif, void *user_data)
{
  if (!esp_netif_is_netif_up(netif)) {
    return true;
  }
  return netif_match_inferface(netif, user_data);
}

int
oc_netif_get_interface_index(int sock)
{
  struct sockaddr_storage addr;
  socklen_t socklen = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }

  esp_netif_t *netif = esp_netif_find_if(netif_match_active_inferface, &addr);
  if (netif == NULL) {
    return 0;
  }
  return esp_netif_get_netif_impl_index(netif);
}

#endif /* OC_TCP */

#else /* ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(5, 4, 0) */

esp_err_t
oc_netif_iterate_interfaces(oc_netif_iterate_interfaces_fn_t fn,
                            void *user_data)
{
  for (esp_netif_t *esp_netif = esp_netif_next(NULL); esp_netif != NULL;
       esp_netif = esp_netif_next(esp_netif)) {
    if (!fn(esp_netif, user_data)) {
      break;
    }
  }
  return ESP_OK;
}

#ifdef OC_TCP

typedef struct
{
  struct sockaddr_storage *addr;
  int index;
} match_interface_data_t;

static bool
netif_iterate_match_inferface(esp_netif_t *netif, void *user_data)
{
  if (!esp_netif_is_netif_up(netif)) {
    return true;
  }
  match_interface_data_t *mid = (match_interface_data_t *)user_data;
  if (!netif_match_inferface(netif, mid->addr)) {
    return true;
  }
  mid->index = esp_netif_get_netif_impl_index(netif);
  return false;
}

int
oc_netif_get_interface_index(int sock)
{
  struct sockaddr_storage addr;
  socklen_t socklen = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &socklen) == -1) {
    OC_ERR("obtaining socket information %d", errno);
    return -1;
  }

  match_interface_data_t mid = {
    .addr = &addr,
    .index = -1,
  };
  esp_err_t err =
    oc_netif_iterate_interfaces(netif_iterate_match_inferface, &mid);
  if (err != ESP_OK) {
    OC_ERR("failed iterating network interfaces: %d", err);
    return -1;
  }
  return mid.index;
}

#endif /* OC_TCP */

#endif /*  ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 4, 0) */

void
oc_netif_deinit(void)
{
#ifdef OC_NETWORK_MONITOR
  remove_all_ip_interface();
  remove_all_network_interface_cbs();
#endif /* OC_NETWORK_MONITOR */
}

/*
// Copyright (c) 2018 Samsung Electronics France SAS
// Copyright (c) 2018 Intel Corporation
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

#include "ipcontext.h"
#ifdef OC_TCP
#include "tcpadapter.h"
#endif
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "port/oc_assert.h"
#include "port/oc_connectivity.h"


void
oc_network_event_handler_mutex_init(void)
{
  oc_abort(__func__);
}

void
oc_network_event_handler_mutex_lock(void)
{
  oc_abort(__func__);
}

void
oc_network_event_handler_mutex_unlock(void)
{
  oc_abort(__func__);
}

void oc_network_event_handler_mutex_destroy(void) {
  oc_abort(__func__);
}

static ip_context_t *
get_ip_context_for_device(size_t device)
{
  (void)device;
  oc_abort(__func__);
  return NULL;
}

#ifdef OC_IPV4
static int add_mcast_sock_to_ipv4_mcast_group(int mcast_sock,
                                              const struct in_addr *local,
                                              int interface_index) {
  (void) mcast_sock;
  (void) local;
  (void) interface_index;
  oc_abort(__func__);
  return 0;
}
#endif /* OC_IPV4 */

static int add_mcast_sock_to_ipv6_mcast_group(int mcast_sock,
                                              int interface_index) {

  (void) mcast_sock;
  (void) interface_index;
  oc_abort(__func__);
  return 0;
}

static int configure_mcast_socket(int mcast_sock, int sa_family) {
  int ret = 0;
  (void) mcast_sock;
  (void) sa_family;
  oc_abort(__func__);
  return ret;
}

/* Called after network interface up/down events.
 * This function reconfigures IPv6/v4 multicast sockets for
 * all logical devices.
 */
static int process_interface_change_event(void) {
  int ret = 0;
  oc_abort(__func__);
  return ret;
}


static void *network_event_thread(void *data) {
  (void) data;
  oc_abort(__func__);
  return NULL;
}

static void
get_interface_addresses(unsigned char family, uint16_t port, bool secure,
                        bool tcp)
{
  (void) family;
  (void) port;
  (void) secure;
  (void) tcp;
  oc_abort(__func__);
}

oc_endpoint_t *
oc_connectivity_get_endpoints(size_t device)
{
  (void)device;
  oc_abort(__func__);
  return NULL;
}

int
oc_send_buffer(oc_message_t *message)
{
  (void)message;
  oc_abort(__func__);
  return -1;
}

#ifdef OC_CLIENT
void
oc_send_discovery_request(oc_message_t *message)
{
  (void) message;
  oc_abort(__func__);
}
#endif /* OC_CLIENT */

#ifdef OC_IPV4
static int
connectivity_ipv4_init(ip_context_t *dev)
{
  oc_abort(__func__);
  return 0;
}
#endif

int
oc_connectivity_init(size_t device)
{
  (void)device;
  oc_abort(__func__);
  return -1;
}

void
oc_connectivity_shutdown(size_t device)
{
  (void)device;
  oc_abort(__func__);
}


#ifdef OC_TCP
void
oc_connectivity_end_session(oc_endpoint_t *endpoint)
{

  (void) endpoint;
  oc_abort(__func__);
}
#endif /* OC_TCP */

#ifdef OC_DNS_LOOKUP
int
oc_dns_lookup(const char *domain, oc_string_t *addr, enum transport_flags flags)
{
  if (!domain || !addr || !flags) {
    OC_ERR("Error of input parameters");
    return -1;
  }

  oc_abort(__func__);

  return 0;
}
#endif /* OC_DNS_LOOKUP */

bool
oc_get_mac_addr(unsigned char *mac)
{
  (void) mac;
  oc_abort(__func__);
  return true;
}


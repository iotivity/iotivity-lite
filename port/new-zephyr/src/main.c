/*
// Copyright (c) 2016 Intel Corporation
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

#include "oc_api.h"

#include <string.h>

#include <zephyr.h>
#include <sys/printk.h>
#include <esp_wifi.h>
#include <esp_timer.h>
#include <esp_event.h>
#include <esp_system.h>

#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_mgmt.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(esp32_wifi_sta, LOG_LEVEL_DBG);

static struct net_mgmt_event_callback dhcp_cb;

static struct k_sem block;
static bool light_state = false;

static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_set_custom_device_property(purpose, "desk lamp");
}

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Kishen's light", "1.0", "1.0",
                       set_device_custom_property, NULL);
  return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)user_data;
  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, light_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  PRINT("Light state %d\n", light_state);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t iface_mask,
           void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  PRINT("POST_light:\n");
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      PRINT("value: %d\n", state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_OK);
  light_state = state;
}

static void
put_light(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)iface_mask;
  (void)user_data;
  post_light(request, iface_mask, user_data);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("lightbulb", "/light/1", 1, 0);
  oc_resource_bind_resource_type(res, "oic.r.light");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_add_resource(res);
}

static void
signal_event_loop(void)
{
  k_sem_give(&block);
}

static void handler_cb(struct net_mgmt_event_callback *cb,
		    uint32_t mgmt_event, struct net_if *iface)
{
	if (mgmt_event != NET_EVENT_IPV4_DHCP_BOUND) {
		return;
	}

	char buf[NET_IPV4_ADDR_LEN];

	LOG_INF("Your address: %s",
		log_strdup(net_addr_ntop(AF_INET,
				   &iface->config.dhcpv4.requested_ip,
				   buf, sizeof(buf))));
	LOG_INF("Lease time: %u seconds",
			iface->config.dhcpv4.lease_time);
	LOG_INF("Subnet: %s",
		log_strdup(net_addr_ntop(AF_INET,
					&iface->config.ip.ipv4->netmask,
					buf, sizeof(buf))));
	LOG_INF("Router: %s",
		log_strdup(net_addr_ntop(AF_INET,
						&iface->config.ip.ipv4->gw,
						buf, sizeof(buf))));
}

oc_event_callback_retval_t
heap_dbg(void *v)
{
  LOG_INF("heap size:%d\n", esp_get_free_heap_size());
  return OC_EVENT_CONTINUE;
}


void main(void)
{
    static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

  k_sem_init(&block, 0, 1);
  oc_set_min_app_data_size(128);
  oc_set_max_app_data_size(8000);
  heap_dbg(NULL);
	if (oc_main_init(&handler) < 0)
		return;

	oc_clock_time_t next_event;
  oc_set_delayed_callback(NULL, heap_dbg, 1);

	net_mgmt_init_event_callback(&dhcp_cb, handler_cb,
				     NET_EVENT_IPV4_DHCP_BOUND);
	net_mgmt_add_event_callback(&dhcp_cb);
	struct net_if *iface = net_if_get_default();
	if (!iface) {
		LOG_ERR("wifi interface not available");
		return;
	}

	net_dhcpv4_start(iface);

	if (!IS_ENABLED(CONFIG_ESP32_WIFI_STA_AUTO)) {
		wifi_config_t wifi_config = {
			.sta = {
				.ssid = CONFIG_ESP32_WIFI_SSID,
				.password = CONFIG_ESP32_WIFI_PASSWORD,
			},
		};

		esp_err_t ret = esp_wifi_set_mode(WIFI_MODE_STA);

		ret |= esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config);
		ret |= esp_wifi_connect();
		if (ret != ESP_OK) {
			LOG_ERR("connection failed");
			return;
		}
	}



	while (true) {
		next_event = oc_main_poll();
		if (next_event == 0) {
			next_event = K_TICKS_FOREVER;
			k_sem_take(&block, K_FOREVER);
		} else {
			next_event -= oc_clock_time();
			k_sem_take(&block, Z_TIMEOUT_MS(next_event));
		}
	}

	oc_main_shutdown();
}
/******************************************************************
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
 ******************************************************************/

#include "debug_print.h"
#include "oc_api.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_esp.h"
#include "oc_log.h"
#include "oc_pki.h"
#include "util/oc_features.h"

#ifdef OC_SOFTWARE_UPDATE
#include "oc_swupdate.h"
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_HAS_FEATURE_PLGD_HAWKBIT
#include "hawkbit.h"
#endif /* OC_HAS_FEATURE_PLGD_HAWKBIT */

#include "driver/gpio.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif_ip_addr.h"
#include "esp_sntp.h"
#include "lwip/ip6_addr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>

#define EXAMPLE_WIFI_SSID CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS CONFIG_WIFI_PASSWORD
#define BLINK_GPIO ((gpio_num_t)CONFIG_BLINK_GPIO)

static EventGroupHandle_t wifi_event_group;

static const int IPV4_CONNECTED_BIT = BIT0;
static const int IPV6_CONNECTED_BIT = BIT1;

static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_cv = PTHREAD_COND_INITIALIZER;
static bool light_state = false;

static const char *TAG = "iotivity server";
static const char *device_name = "esp32";

static void
set_device_custom_property(void *data)
{
  (void)data;
  oc_set_custom_device_property(purpose, "desk lamp");
  oc_set_custom_device_property(sv, oc_esp_get_application_version());
}

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  if (ret != 0) {
    return ret;
  }
  ret = oc_add_device("/oic/d", "oic.d.light", device_name, "ocf.1.0.0",
                      "ocf.res.1.0.0", set_device_custom_property, NULL);
  if (ret != 0) {
    return ret;
  }
  return 0;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  OC_PRINTF("GET_light:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, light_state);
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
  OC_PRINTF("Light state %d\n", light_state);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)user_data;
  (void)interface;
  OC_PRINTF("POST_light:\n");
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_PRINTF("key: %s ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      OC_PRINTF("value: %d\n", state);
      gpio_set_level(BLINK_GPIO, state);
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  light_state = state;
}

static void
register_light(size_t device)
{
  oc_resource_t *res = oc_new_resource("lightbulb", "/light/1", 1, device);
  oc_resource_bind_resource_type(res, "oic.r.light");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_add_resource(res);
#ifdef OC_CLOUD
  oc_cloud_add_resource(res);
#endif /* OC_CLOUD */
}

static void
register_resources(void)
{
  register_light(0);
#ifdef OC_HAS_FEATURE_PLGD_HAWKBIT
  hawkbit_resource_register(0);
#endif /* OC_HAS_FEATURE_PLGD_HAWKBIT */
}

static void
signal_event_loop(void)
{
  pthread_mutex_lock(&g_mutex);
  pthread_cond_signal(&g_cv);
  pthread_mutex_unlock(&g_mutex);
}

static void
sta_start(void *esp_netif, esp_event_base_t event_base, int32_t event_id,
          void *event_data)
{
  esp_wifi_connect();
}

static void
sta_disconnected(void *esp_netif, esp_event_base_t event_base, int32_t event_id,
                 void *event_data)
{
  esp_wifi_connect();
  xEventGroupClearBits(wifi_event_group, IPV4_CONNECTED_BIT);
  xEventGroupClearBits(wifi_event_group, IPV6_CONNECTED_BIT);
}

static void
sta_connected(void *esp_netif, esp_event_base_t event_base, int32_t event_id,
              void *event_data)
{
  esp_netif_create_ip6_linklocal((esp_netif_t *)esp_netif);
}

static void
got_ip(void *esp_netif, esp_event_base_t event_base, int32_t event_id,
       void *event_data)
{
  xEventGroupSetBits(wifi_event_group, IPV4_CONNECTED_BIT);
}

static void
got_ip6(void *esp_netif, esp_event_base_t event_base, int32_t event_id,
        void *event_data)
{
  xEventGroupSetBits(wifi_event_group, IPV6_CONNECTED_BIT);
}

esp_netif_t *sta_netif = NULL;

static void
initialise_wifi(void)
{
  esp_err_t err = esp_event_loop_create_default();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE) {
    ESP_ERROR_CHECK(err);
  }
  ESP_ERROR_CHECK(esp_netif_init());
  char *desc;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  esp_netif_inherent_config_t esp_netif_config =
    ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
  // Prefix the interface description with the module TAG
  // Warning: the interface desc is used in tests to capture actual connection
  // details (IP, gw, mask)
  asprintf(&desc, "%s: %s", TAG, esp_netif_config.if_desc);
  esp_netif_config.if_desc = desc;
  esp_netif_config.route_prio = 128;
  sta_netif = esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);
  free(desc);
  ESP_ERROR_CHECK(esp_wifi_set_default_wifi_sta_handlers());

  wifi_event_group = xEventGroupCreate();
  ESP_ERROR_CHECK(esp_event_handler_register(
    WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, sta_disconnected, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START,
                                             sta_start, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(
    WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, sta_connected, sta_netif));
  ESP_ERROR_CHECK(
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, got_ip, NULL));
  ESP_ERROR_CHECK(
    esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, got_ip6, NULL));

  wifi_config_t wifi_config = {
    .sta =
      {
        .ssid = EXAMPLE_WIFI_SSID,
        .password = EXAMPLE_WIFI_PASS,
      },
  };
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
}

#ifdef OC_CLOUD
static void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  OC_PRINTF("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    OC_PRINTF("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    OC_PRINTF("\t\t-Token Expiry: ");
    if (ctx) {
      OC_PRINTF("%d\n", oc_cloud_get_token_expiry(ctx));
    } else {
      OC_PRINTF("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    OC_PRINTF("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    OC_PRINTF("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    OC_PRINTF("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    OC_PRINTF("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    OC_PRINTF("\t\t-Refreshed Token\n");
  }
}
#endif /* OC_CLOUD */

void
factory_presets_cb_new(size_t device, void *data)
{
  OC_PRINTF("factory_presets_cb: %d\n", (int)device);

  gpio_set_level(BLINK_GPIO, false);
  gpio_reset_pin(BLINK_GPIO);
  gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

  oc_device_info_t *dev = oc_core_get_device_info(device);
  oc_free_string(&dev->name);
  oc_new_string(&dev->name, device_name, strlen(device_name));
  (void)data;
}

#ifdef APP_DEBUG

oc_event_callback_retval_t
heap_dbg(void *v)
{
  OC_PRINTF("heap size:%" PRIu32 "\n", esp_get_free_heap_size());
  return OC_EVENT_CONTINUE;
}

#endif /* APP_DEBUG */

static void
initialize_sntp(void)
{
  ESP_LOGI(TAG, "Initializing SNTP");
  esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);

/*
 * If 'NTP over DHCP' is enabled, we set dynamic pool address
 * as a 'secondary' server. It will act as a fallback server in case that
 * address provided via NTP over DHCP is not accessible
 */
#if LWIP_DHCP_GET_NTP_SRV && SNTP_MAX_SERVERS > 1
  esp_sntp_setservername(1, "pool.ntp.org");

#if LWIP_IPV6 &&                                                               \
  SNTP_MAX_SERVERS > 2 // statically assigned IPv6 address is also possible
  ip_addr_t ip6;
  if (ipaddr_aton("2a01:3f7::1", &ip6)) { // ipv6 ntp source "ntp.netnod.se"
    esp_sntp_setserver(2, &ip6);
  }
#endif /* LWIP_IPV6 */

#else /* LWIP_DHCP_GET_NTP_SRV && (SNTP_MAX_SERVERS > 1) */
  // otherwise, use DNS address from a pool
  esp_sntp_setservername(0, CONFIG_SNTP_TIME_SERVER);

  esp_sntp_setservername(
    1,
    "pool.ntp.org"); // set the secondary NTP server (will be
                     // used only if SNTP_MAX_SERVERS > 1)
#endif

  esp_sntp_set_sync_mode(SNTP_SYNC_MODE_SMOOTH);
  esp_sntp_init();

  ESP_LOGI(TAG, "List of configured NTP servers:");

  for (uint8_t i = 0; i < SNTP_MAX_SERVERS; ++i) {
    if (esp_sntp_getservername(i)) {
      ESP_LOGI(TAG, "server %d: %s", i, esp_sntp_getservername(i));
    } else {
      // we have either IPv4 or IPv6 address, let's print it
      char buff[IPADDR_STRLEN_MAX];
      ip_addr_t const *ip = esp_sntp_getserver(i);
      if (ipaddr_ntoa_r(ip, buff, IPADDR_STRLEN_MAX) != NULL)
        ESP_LOGI(TAG, "server %d: %s", i, buff);
    }
  }
}

static void
obtain_time(void)
{
#if defined(LWIP_DHCP_GET_NTP_SRV) && LWIP_DHCP_GET_NTP_SRV
  esp_sntp_servermode_dhcp(1); // accept NTP offers from DHCP server, if any
#endif
  initialize_sntp();
  // wait for time to be set
  int retry = 0;
  const int retry_count = 15;
  while (esp_sntp_get_sync_status() == SNTP_SYNC_STATUS_RESET &&
         ++retry < retry_count) {
    ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry,
             retry_count);
    vTaskDelay(2000 / portTICK_PERIOD_MS);
  }
}

#define STACK_SIZE (8 * 1024)

// Structure that will hold the TCB of the task being created.
static StaticTask_t xTaskBuffer;

// Buffer that the task being created will use as its stack.  Note this is
// an array of StackType_t variables.  The size of StackType_t is dependent on
// the RTOS port.
static StackType_t xStack[STACK_SIZE];

#ifdef OC_HAS_FEATURE_PLGD_HAWKBIT
static oc_swupdate_cb_t hawkbit_swupdate_impl = {
  .validate_purl = hawkbit_validate_purl,
  .check_new_version = hawkbit_check_new_version,
  .download_update = hawkbit_download_update,
  .perform_upgrade = hawkbit_perform_upgrade,
};
#endif /* OC_HAS_FEATURE_PLGD_HAWKBIT  */

static void
server_main(void *pvParameter)
{
  (void)pvParameter;
  ESP_LOGI(TAG, "iotivity server task started(version=%s)",
           oc_esp_get_application_version());
  // wait to fetch IPv4 && ipv6 address
  EventBits_t waitBits = IPV6_CONNECTED_BIT;
#ifdef OC_IPV4
  waitBits |= IPV4_CONNECTED_BIT;
#endif /* OC_IPV4 */
  xEventGroupWaitBits(wifi_event_group, waitBits, false, true, portMAX_DELAY);

#ifdef OC_IPV4
  esp_netif_ip_info_t ip4_info;
  memset(&ip4_info, 0, sizeof(ip4_info));
  if (esp_netif_get_ip_info(sta_netif, &ip4_info) != ESP_OK) {
    print_error("get IPv4 address failed");
  } else {
    char buf[32];
    ESP_LOGI(TAG, "got IPv4 addr: %s",
             esp_ip4addr_ntoa(&(ip4_info.ip), buf, sizeof(buf)));
  }
#endif /* OC_IPV4 */
  esp_ip6_addr_t ip6_addr;
  memset(&ip6_addr, 0, sizeof(ip6_addr));
  if (esp_netif_get_ip6_linklocal(sta_netif, &ip6_addr) != ESP_OK) {
    print_error("get IPv6 address failed");
  } else {
    ESP_LOGI(TAG, "got IPv6 addr: " IPV6STR, IPV62STR(ip6_addr));
  }

  obtain_time();

  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources };

#ifdef OC_SECURITY
#ifdef OC_STORAGE
  if (oc_storage_config("storage") != 0) {
    ESP_LOGE(TAG, "cannot create storage");
  }
#endif /* OC_STORAGE */
  oc_set_factory_presets_cb(factory_presets_cb_new, NULL);

  oc_set_max_app_data_size(CONFIG_MBEDTLS_SSL_IN_CONTENT_LEN);
#else  /* !OC_SECURITY */
  oc_set_max_app_data_size(10000);
#endif /* OC_SECURITY */

  if (oc_main_init(&handler) < 0) {
    return;
  }

#ifdef OC_CLOUD
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx != NULL) {
    oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
  }
#endif /* OC_CLOUD */
#ifdef OC_HAS_FEATURE_PLGD_HAWKBIT
  oc_swupdate_set_impl(&hawkbit_swupdate_impl);
  if (hawkbit_init() != 0) {
    goto finish;
  }
#endif /* OC_HAS_FEATURE_PLGD_HAWKBIT */

#ifdef APP_DEBUG
  oc_set_delayed_callback(NULL, heap_dbg, 1);
#endif /* APP_DEBUG */

  while (true) {
    oc_clock_time_t next_event = oc_main_poll();
    pthread_mutex_lock(&g_mutex);
    if (oc_main_needs_poll()) {
      pthread_mutex_unlock(&g_mutex);
      continue;
    }
    if (next_event == 0) {
      pthread_cond_wait(&g_cv, &g_mutex);
    } else {
      struct timespec ts = oc_clock_time_to_timespec(next_event);
      pthread_cond_timedwait(&g_cv, &g_mutex, &ts);
    }
    pthread_mutex_unlock(&g_mutex);
  }

#ifdef OC_HAS_FEATURE_PLGD_HAWKBIT
finish:
  hawkbit_free();
#endif /* OC_HAS_FEATURE_PLGD_HAWKBIT */
  oc_main_shutdown();
}

static TaskHandle_t xHandle = NULL;

#ifdef __cplusplus
extern "C" {
#endif

void
app_main(void)
{
  if (nvs_flash_init() != ESP_OK) {
    print_error("nvs_flash_init failed");
  }
  gpio_reset_pin(BLINK_GPIO);
  gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

  pthread_cond_init(&g_cv, NULL);

  print_macro_info();

  initialise_wifi();

  // Create the task without using any dynamic memory allocation.
  xHandle = xTaskCreateStatic(
    server_main,   // Function that implements the task.
    "server_main", // Text name for the task.
    STACK_SIZE,    // Stack size in bytes, not words.
    NULL,          // Parameter passed into the task.
    5,             // Priority at which the task is created.
    xStack,        // Array to use as the task's stack.
    &xTaskBuffer); // Variable to hold the task's data structure.
}

#ifdef __cplusplus
}
#endif

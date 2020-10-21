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
#include "oc_pki.h"
#include "oc_core_res.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "debug_print.h"

#include <pthread.h>
#include <stdio.h>
#include <inttypes.h>

#define EXAMPLE_WIFI_SSID CONFIG_WIFI_SSID
#define EXAMPLE_WIFI_PASS CONFIG_WIFI_PASSWORD
#define BLINK_GPIO CONFIG_BLINK_GPIO

static EventGroupHandle_t wifi_event_group;

static const int IPV4_CONNECTED_BIT = BIT0;
static const int IPV6_CONNECTED_BIT = BIT1;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static struct timespec ts;
static int quit = 0;
static bool light_state = false;

static const char *TAG = "iotivity server";
static const char *device_name = "esp32";

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
  ret |= oc_add_device("/oic/d", "oic.d.light", device_name, "ocf.1.0.0",
                       "ocf.res.1.0.0", set_device_custom_property, NULL);
  return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  PRINT("GET_light:\n");
  oc_rep_start_root_object();
  switch (interface)
  {
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
  PRINT("Light state %d\n", light_state);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  (void)interface;
  PRINT("POST_light:\n");
  bool state = false;
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL)
  {
    PRINT("key: %s ", oc_string(rep->name));
    switch (rep->type)
    {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      PRINT("value: %d\n", state);
      gpio_set_level(BLINK_GPIO, state);

      break;

    // case ...
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
  light_state = state;
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("lightbulb", "/light/1", 1, 0);
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
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}

/*
static void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}
*/

static void sta_start(void *esp_netif, esp_event_base_t event_base,
                      int32_t event_id, void *event_data)
{
  esp_wifi_connect();
}

static void sta_disconnected(void *esp_netif, esp_event_base_t event_base,
                             int32_t event_id, void *event_data)
{
  esp_wifi_connect();
  xEventGroupClearBits(wifi_event_group, IPV4_CONNECTED_BIT);
  xEventGroupClearBits(wifi_event_group, IPV6_CONNECTED_BIT);
}

static void sta_connected(void *esp_netif, esp_event_base_t event_base,
                          int32_t event_id, void *event_data)
{
  esp_netif_create_ip6_linklocal(esp_netif);
}

static void got_ip(void *esp_netif, esp_event_base_t event_base,
                   int32_t event_id, void *event_data)
{
  xEventGroupSetBits(wifi_event_group, IPV4_CONNECTED_BIT);
}

static void got_ip6(void *esp_netif, esp_event_base_t event_base,
                    int32_t event_id, void *event_data)
{
  xEventGroupSetBits(wifi_event_group, IPV6_CONNECTED_BIT);
}

static void initialise_wifi(void)
{
  esp_err_t err = esp_event_loop_create_default();
  if (err != ESP_OK && err != ESP_ERR_INVALID_STATE)
  {
    ESP_ERROR_CHECK(err);
  }
  ESP_ERROR_CHECK(esp_netif_init());
  char *desc;
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

  esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_WIFI_STA();
  // Prefix the interface description with the module TAG
  // Warning: the interface desc is used in tests to capture actual connection details (IP, gw, mask)
  asprintf(&desc, "%s: %s", TAG, esp_netif_config.if_desc);
  esp_netif_config.if_desc = desc;
  esp_netif_config.route_prio = 128;
  esp_netif_t *netif = esp_netif_create_wifi(WIFI_IF_STA, &esp_netif_config);
  free(desc);
  ESP_ERROR_CHECK(esp_wifi_set_default_wifi_sta_handlers());

  wifi_event_group = xEventGroupCreate();
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, sta_disconnected, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_START, sta_start, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_CONNECTED, sta_connected, netif));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, got_ip, NULL));
  ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_GOT_IP6, got_ip6, NULL));

  wifi_config_t wifi_config = {
      .sta = {
          .ssid = EXAMPLE_WIFI_SSID,
          .password = EXAMPLE_WIFI_PASS,
      },
  };
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
  ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
  ESP_ERROR_CHECK(esp_wifi_start());
}

static void
cloud_status_handler(oc_cloud_context_t *ctx, oc_cloud_status_t status,
                     void *data)
{
  (void)data;
  PRINT("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED)
  {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY)
  {
    PRINT("\t\t-Token Expiry: ");
    if (ctx)
    {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    }
    else
    {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE)
  {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN)
  {
    PRINT("\t\t-Logged In\n");
  }
  if (status & OC_CLOUD_LOGGED_OUT)
  {
    PRINT("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED)
  {
    PRINT("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN)
  {
    PRINT("\t\t-Refreshed Token\n");
  }
}

void factory_presets_cb_new(size_t device, void *data)
{
  gpio_reset_pin(BLINK_GPIO);
  gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

  oc_device_info_t *dev = oc_core_get_device_info(device);
  oc_free_string(&dev->name);
  oc_new_string(&dev->name, device_name, strlen(device_name));
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  PRINT("factory_presets_cb: %d\n", (int)device);

  const char *cert = "-----BEGIN CERTIFICATE-----\n"
                     "MIIEFDCCA7qgAwIBAgIJAI0K+3tTsk4eMAoGCCqGSM49BAMCMFsxDDAKBgNVBAoM\n"
                     "A09DRjEiMCAGA1UECwwZS3lyaW8gVGVzdCBJbmZyYXN0cnVjdHVyZTEnMCUGA1UE\n"
                     "AwweS3lyaW8gVEVTVCBJbnRlcm1lZGlhdGUgQ0EwMDAyMB4XDTIwMDQxNDE3MzMy\n"
                     "NloXDTIwMDUxNDE3MzMyNlowYTEMMAoGA1UECgwDT0NGMSIwIAYDVQQLDBlLeXJp\n"
                     "byBUZXN0IEluZnJhc3RydWN0dXJlMS0wKwYDVQQDDCQyYjI1ODQ4Mi04ZDZhLTQ5\n"
                     "OTEtOGQ2OS0zMTAxNDE5ODE2NDYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARZ\n"
                     "H0LnMEg5BR41xctwQMPoNwa0ERVB1J9WWUvdrKq4GVkX/HwPUGvViISpmIS0GM8z\n"
                     "Ky2IjHm+rMrc4oSTfyX0o4ICXzCCAlswCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMC\n"
                     "A4gwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMBBgorBgEEAYLefAEGMB0G\n"
                     "A1UdDgQWBBTS5/x0htLNUYt8JoL82HU2rkjuWDAfBgNVHSMEGDAWgBQZc2oEGgsH\n"
                     "cE9TeVM2h/wMunyuCzCBlgYIKwYBBQUHAQEEgYkwgYYwXQYIKwYBBQUHMAKGUWh0\n"
                     "dHA6Ly90ZXN0cGtpLmt5cmlvLmNvbS9vY2YvY2FjZXJ0cy9CQkU2NEY5QTdFRTM3\n"
                     "RDI5QTA1RTRCQjc3NTk1RjMwOEJFNDFFQjA3LmNydDAlBggrBgEFBQcwAYYZaHR0\n"
                     "cDovL3Rlc3RvY3NwLmt5cmlvLmNvbTBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8v\n"
                     "dGVzdHBraS5reXJpby5jb20vb2NmL2NybHMvQkJFNjRGOUE3RUUzN0QyOUEwNUU0\n"
                     "QkI3NzU5NUYzMDhCRTQxRUIwNy5jcmwwGAYDVR0gBBEwDzANBgsrBgEEAYORVgAB\n"
                     "AjBhBgorBgEEAYORVgEABFMwUTAJAgECAgEAAgEAMDYMGTEuMy42LjEuNC4xLjUx\n"
                     "NDE0LjAuMC4xLjAMGTEuMy42LjEuNC4xLjUxNDE0LjAuMC4yLjAMBUxpdGUxDAVM\n"
                     "aXRlMTAqBgorBgEEAYORVgEBBBwwGgYLKwYBBAGDkVYBAQAGCysGAQQBg5FWAQEB\n"
                     "MDAGCisGAQQBg5FWAQIEIjAgDA4xLjMuNi4xLjQuMS43MQwJRGlzY292ZXJ5DAMx\n"
                     "LjAwCgYIKoZIzj0EAwIDSAAwRQIgedG7zHeLh9YzM0bU3DQBnKDRIFnJHiDayyuE\n"
                     "8pVfJOQCIQCo/llZOZD87IHzsyxEfXm/QhkTNA5WJOa7sjF2ngQ1/g==\n"
                     "-----END CERTIFICATE-----\n";

  const char *key = "-----BEGIN EC PARAMETERS-----\n"
                    "BggqhkjOPQMBBw==\n"
                    "-----END EC PARAMETERS-----\n"
                    "-----BEGIN EC PRIVATE KEY-----\n"
                    "MHcCAQEEIBF8S8rq+h8EnykDcCpAyvMam+u3D9i/5oYF5owt/+SnoAoGCCqGSM49\n"
                    "AwEHoUQDQgAEWR9C5zBIOQUeNcXLcEDD6DcGtBEVQdSfVllL3ayquBlZF/x8D1Br\n"
                    "1YiEqZiEtBjPMystiIx5vqzK3OKEk38l9A==\n"
                    "-----END EC PRIVATE KEY-----\n";
  const char *inter_ca = "-----BEGIN CERTIFICATE-----\n"
                         "MIIC+jCCAqGgAwIBAgIJAPObjMBXKhG1MAoGCCqGSM49BAMCMFMxDDAKBgNVBAoM\n"
                         "A09DRjEiMCAGA1UECwwZS3lyaW8gVGVzdCBJbmZyYXN0cnVjdHVyZTEfMB0GA1UE\n"
                         "AwwWS3lyaW8gVEVTVCBST09UIENBMDAwMjAeFw0xODExMzAxODEyMTVaFw0yODEx\n"
                         "MjYxODEyMTVaMFsxDDAKBgNVBAoMA09DRjEiMCAGA1UECwwZS3lyaW8gVGVzdCBJ\n"
                         "bmZyYXN0cnVjdHVyZTEnMCUGA1UEAwweS3lyaW8gVEVTVCBJbnRlcm1lZGlhdGUg\n"
                         "Q0EwMDAyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvA+Gn3ofRpH40XuVppBR\n"
                         "f78mDtfclOkBd7/32yQcmK2LQ0wm/uyl2cyeABPuN6NFcR9+LYkXZ5P4Ovy9R43Q\n"
                         "vqOCAVQwggFQMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB0G\n"
                         "A1UdDgQWBBQZc2oEGgsHcE9TeVM2h/wMunyuCzAfBgNVHSMEGDAWgBQoSOTlJ1jZ\n"
                         "CO4JNOSxuz1ZZh/I9TCBjQYIKwYBBQUHAQEEgYAwfjBVBggrBgEFBQcwAoZJaHR0\n"
                         "cDovL3Rlc3Rwa2kua3lyaW8uY29tL29jZi80RTY4RTNGQ0YwRjJFNEY4MEE4RDE0\n"
                         "MzhGNkExQkE1Njk1NzEzRDYzLmNydDAlBggrBgEFBQcwAYYZaHR0cDovL3Rlc3Rv\n"
                         "Y3NwLmt5cmlvLmNvbTBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vdGVzdHBraS5r\n"
                         "eXJpby5jb20vb2NmLzRFNjhFM0ZDRjBGMkU0RjgwQThEMTQzOEY2QTFCQTU2OTU3\n"
                         "MTNENjMuY3JsMAoGCCqGSM49BAMCA0cAMEQCHwXkRYd+u5pOPH544wBmBRJz/b0j\n"
                         "ppvUIHx8IUH0CioCIQDC8CnMVTOC5aIoo5Yg4k7BDDNxbRQoPujYes0OTVGgPA==\n"
                         "-----END CERTIFICATE-----\n";

  const char *root_ca = "-----BEGIN CERTIFICATE-----\n"
                        "MIIB3zCCAYWgAwIBAgIJAPObjMBXKhGyMAoGCCqGSM49BAMCMFMxDDAKBgNVBAoM\n"
                        "A09DRjEiMCAGA1UECwwZS3lyaW8gVGVzdCBJbmZyYXN0cnVjdHVyZTEfMB0GA1UE\n"
                        "AwwWS3lyaW8gVEVTVCBST09UIENBMDAwMjAeFw0xODExMzAxNzMxMDVaFw0yODEx\n"
                        "MjcxNzMxMDVaMFMxDDAKBgNVBAoMA09DRjEiMCAGA1UECwwZS3lyaW8gVGVzdCBJ\n"
                        "bmZyYXN0cnVjdHVyZTEfMB0GA1UEAwwWS3lyaW8gVEVTVCBST09UIENBMDAwMjBZ\n"
                        "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABGt1sU2QhQcK/kflKSF9TCrvKaDckLWd\n"
                        "ZoyvP6z0OrqNdtBscZgVYsSHMQZ1R19wWxsflvNr8bMVW1K3HWMkpsijQjBAMA8G\n"
                        "A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBQoSOTlJ1jZ\n"
                        "CO4JNOSxuz1ZZh/I9TAKBggqhkjOPQQDAgNIADBFAiAlMUwgVeL8d5W4jZdFJ5Zg\n"
                        "clk7XT66LNMfGkExSjU1ngIhANOvTmd32A0kEtIpHbiKA8+RFDCPJWjN4loxrBC7\n"
                        "v0JE\n"
                        "-----END CERTIFICATE-----\n";

  int ee_credid = oc_pki_add_mfg_cert(0, (const unsigned char *)cert, strlen(cert),
                                      (const unsigned char *)key, strlen(key));
  if (ee_credid < 0)
  {
    PRINT("ERROR installing manufacturer EE cert\n");
    return;
  }

  int subca_credid = oc_pki_add_mfg_intermediate_cert(0, ee_credid, (const unsigned char *)inter_ca, strlen(inter_ca));

  if (subca_credid < 0)
  {
    PRINT("ERROR installing intermediate CA cert\n");
    return;
  }

  int rootca_credid =
      oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)root_ca, strlen(root_ca));
  if (rootca_credid < 0)
  {
    PRINT("ERROR installing root cert\n");
    return;
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, ee_credid);
#endif /* OC_SECURITY && OC_PKI */
}

oc_event_callback_retval_t heap_dbg(void *v)
{
  printf("heap size:%d\n", esp_get_free_heap_size());
  return OC_EVENT_CONTINUE;
}

#define STACK_SIZE 20000

// Structure that will hold the TCB of the task being created.
static StaticTask_t xTaskBuffer;

// Buffer that the task being created will use as its stack.  Note this is
// an array of StackType_t variables.  The size of StackType_t is dependent on
// the RTOS port.
static StackType_t xStack[STACK_SIZE];

static void server_main(void *pvParameter)
{
  int init;
  tcpip_adapter_ip_info_t ip4_info = {0};
  struct ip6_addr if_ipaddr_ip6 = {0};
  ESP_LOGI(TAG, "iotivity server task started");
  // wait to fetch IPv4 && ipv6 address
#ifdef OC_IPV4
  xEventGroupWaitBits(wifi_event_group, IPV4_CONNECTED_BIT | IPV6_CONNECTED_BIT, false, true, portMAX_DELAY);
#else
  xEventGroupWaitBits(wifi_event_group, IPV6_CONNECTED_BIT, false, true, portMAX_DELAY);
#endif

#ifdef OC_IPV4
  if (tcpip_adapter_get_ip_info(TCPIP_ADAPTER_IF_STA, &ip4_info) != ESP_OK)
  {
    print_error("get IPv4 address failed");
  }
  else
  {
    ESP_LOGI(TAG, "got IPv4 addr:%s", ip4addr_ntoa(&(ip4_info.ip)));
  }
#endif

  if (tcpip_adapter_get_ip6_linklocal(TCPIP_ADAPTER_IF_STA, &if_ipaddr_ip6) != ESP_OK)
  {
    print_error("get IPv6 address failed");
  }
  else
  {
    ESP_LOGI(TAG, "got IPv6 addr:%s", ip6addr_ntoa(&if_ipaddr_ip6));
  }

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources};

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("storage");
  oc_set_factory_presets_cb(factory_presets_cb_new, NULL);
#endif /* OC_SECURITY */

  oc_set_max_app_data_size(6000);

  init = oc_main_init(&handler);
  if (init < 0)
    return;
#ifdef OC_CLOUD
  oc_cloud_context_t *ctx = oc_cloud_get_context(0);
  if (ctx)
  {
    oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
  }
#endif /* OC_CLOUD */

  oc_set_delayed_callback(NULL, heap_dbg, 1);

  while (quit != 1)
  {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0)
    {
      pthread_cond_wait(&cv, &mutex);
    }
    else
    {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }

  oc_main_shutdown();
  return;
}

static TaskHandle_t xHandle = NULL;

void app_main(void)
{
  if (nvs_flash_init() != ESP_OK)
  {
    print_error("nvs_flash_init failed");
  }
  gpio_reset_pin(BLINK_GPIO);
  gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);

  pthread_cond_init(&cv, NULL);

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

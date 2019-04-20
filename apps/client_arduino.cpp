#include "Ethernet2.h"
#include "serial.h"
#include "oc_api.h"
#include "oc_clock.h"
#include "oc_assert.h"
#include "oc_storage.h"
#include "oc_connectivity.h"
#include "util/oc_process.h"
#include "oc_network_events_mutex.h"

#ifdef __AVR__
#ifdef OC_XMEM
void extRAMinit(void)__attribute__ ((used, naked, section (".init3")));
void extRAMinit(void) {
    // set up the xmem registers
    XMCRB=0;
    XMCRA=1<<SRE;
    DDRD|=_BV(PD7);
    DDRL|=(_BV(PL6)|_BV(PL7));
}
#endif
#endif

OC_PROCESS(sample_client_process, "client");
static int
app_init(void)
{
  int ret = oc_init_platform("Apple", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.phone", "Kishen's IPhone", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

#define MAX_URI_LENGTH (30)
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t *light_server;

static bool state;
static int power;
static oc_string_t name;

static oc_event_callback_retval_t
stop_observe(void *data)
{
  (void)data;
  OC_DBG("Stopping OBSERVE");
  oc_stop_observe(a_light, light_server);
  return OC_EVENT_DONE;
}

static void
observe_light(oc_client_response_t *data)
{
  OC_DBG("OBSERVE_light:");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_DBG("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_DBG("%d", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      OC_DBG("%d", rep->value.integer);
      power = rep->value.integer;
      break;
    case OC_REP_STRING:
      OC_DBG("%s", oc_string(rep->value.string));
      if (oc_string_len(name))
        oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      break;
    }
    rep = rep->next;
  }
}

static void
post2_light(oc_client_response_t *data)
{
  OC_DBG("POST2_light:");
  if (data->code == OC_STATUS_CHANGED)
    OC_DBG("POST response: CHANGED");
  else if (data->code == OC_STATUS_CREATED)
    OC_DBG("POST response: CREATED");
  else
    OC_DBG("POST response code %d", data->code);

  oc_do_observe(a_light, light_server, NULL, &observe_light, LOW_QOS, NULL);
  oc_set_delayed_callback(NULL, &stop_observe, 30);
  OC_DBG("Sent OBSERVE request");
}

static void
post_light(oc_client_response_t *data)
{
  OC_DBG("POST_light:");
  if (data->code == OC_STATUS_CHANGED)
    OC_DBG("POST response: CHANGED");
  else if (data->code == OC_STATUS_CREATED)
    OC_DBG("POST response: CREATED");
  else
    OC_DBG("POST response code %d", data->code);

  if (oc_init_post(a_light, light_server, NULL, &post2_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, true);
    oc_rep_set_int(root, power, 55);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_DBG("Sent POST request");
    else
      OC_DBG("Could not send POST request");
  } else
    OC_DBG("Could not init POST request");
}

static void
put_light(oc_client_response_t *data)
{
  OC_DBG("PUT_light:");

  if (data->code == OC_STATUS_CHANGED)
    OC_DBG("PUT response: CHANGED");
  else
    OC_DBG("PUT response code %d", data->code);

  if (oc_init_post(a_light, light_server, NULL, &post_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, false);
    oc_rep_set_int(root, power, 105);
    oc_rep_end_root_object();
    if (oc_do_post())
      OC_DBG("Sent POST request");
    else
      OC_DBG("Could not send POST request");
  } else
    OC_DBG("Could not init POST request");
}

static void
get_light(oc_client_response_t *data)
{
  OC_DBG("GET_light:");
  oc_rep_t *rep = data->payload;
  while (rep != NULL) {
    OC_DBG("key %s, value ", oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_DBG("%d", rep->value.boolean);
      state = rep->value.boolean;
      break;
    case OC_REP_INT:
      OC_DBG("%d", rep->value.integer);
      power = rep->value.integer;
      break;
    case OC_REP_STRING:
      OC_DBG("%s", oc_string(rep->value.string));
      if (oc_string_len(name))
        oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      break;
    }
    rep = rep->next;
  }

  if (oc_init_put(a_light, light_server, NULL, &put_light, LOW_QOS, NULL)) {
    oc_rep_start_root_object();
    oc_rep_set_boolean(root, state, true);
    oc_rep_set_int(root, power, 15);
    oc_rep_end_root_object();

    if (oc_do_put())
      OC_DBG("Sent PUT request");
    else
      OC_DBG("Could not send PUT request");
  } else
    OC_DBG("Could not init PUT request");
}

static oc_discovery_flags_t
discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
  (void)anchor;
  (void)user_data;
  (void)interfaces;
  (void)bm;
  int i;
  int uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
  for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
    char *t = oc_string_array_get_item(types, i);
    if (strlen(t) == 10 && strncmp(t, "core.light", 10) == 0) {
#ifdef OC_IPV4
#ifdef OC_ESP32 //  this is experimental
      light_server = endpoint;
#else
      light_server = endpoint->next;
#endif
      OC_DBG("IPV4 Resource ");
#else
      light_server = endpoint;
      OC_DBG("IPV6 Resource ");
#endif
      strncpy(a_light, uri, uri_len);
      a_light[uri_len] = '\0';

      OC_DBG("Resource %s hosted at endpoints:", a_light);
      oc_endpoint_t *ep = endpoint;
      while (ep != NULL) {
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }
      oc_do_get(a_light, light_server, NULL, &get_light, LOW_QOS, NULL);

      return OC_STOP_DISCOVERY;
    }
  }
  oc_free_server_endpoints(endpoint);
  return OC_CONTINUE_DISCOVERY;
}
static void
issue_requests(void)
{
  oc_do_ip_discovery("core.light", &discovery, NULL);
}

static void
signal_event_loop(void)
{
  oc_process_post(&sample_client_process, OC_PROCESS_EVENT_TIMER, NULL);
}

OC_PROCESS_THREAD(sample_client_process, ev, data)
{
  (void)data;
  static struct oc_etimer et;
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .requests_entry = issue_requests };
  static oc_clock_time_t next_event;
  oc_set_mtu_size(1024);
  oc_set_max_app_data_size(1024);
  OC_PROCESS_BEGIN();
  OC_DBG("Initializing client for arduino");
  while (ev != OC_PROCESS_EVENT_EXIT) {
    oc_etimer_set(&et, (oc_clock_time_t)next_event);

    if(ev == OC_PROCESS_EVENT_INIT){
      int init = oc_main_init(&handler);
      if (init < 0){
        OC_DBG("Client Init failed!");
        return init;
      }
      OC_DBG("Client process init!");
    }
    else if(ev == OC_PROCESS_EVENT_TIMER){
      next_event = oc_main_poll();
      next_event -= oc_clock_time();
    }
    OC_PROCESS_WAIT_EVENT();
  }
 OC_PROCESS_END();
}

// Arduino Ethernet Shield
uint8_t ConnectToNetwork()
{
  // Note: ****Update the MAC address here with your shield's MAC address****
  uint8_t ETHERNET_MAC[] = {0x90, 0xA2, 0xDA, 0x11, 0x44, 0xA9};
  Ethernet.init(5); // CS Pin for MKRZERO
  uint8_t error = Ethernet.begin(ETHERNET_MAC);
  if (error  == 0)
  {
    OC_ERR("Error connecting to Network: %d", error);
    return -1;
  }
  IPAddress ip = Ethernet.localIP();
  OC_DBG("Connected to Ethernet IP: %d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  return 0;
}

void setup() {
#if defined(__arm__) && defined(__SAMD21G18A__) || defined(__SAM3X8E__)
	Serial.begin(250000);
#else
	Serial.begin(115200);
#endif
#if defined(__SAMD21G18A__)
  while (!Serial) {
  }
#endif
  if (ConnectToNetwork() != 0)
  {
    OC_ERR("Unable to connect to network");
    return;
  }
  delay(500);
#ifdef OC_SECURITY
  oc_storage_config("creds");
#endif /* OC_SECURITY */
  oc_process_start(&sample_client_process, NULL);
  delay(200);
}

void loop() {

  oc_process_run();
}

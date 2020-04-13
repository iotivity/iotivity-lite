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
OC_PROCESS(sample_server_process, "server");
static bool state = false;
int power;
oc_string_t name;

static int
app_init(void)
{
  int ret = oc_init_platform("Intel", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  ++power;

  OC_DBG("GET_light:\n");
  oc_rep_start_root_object();
  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_RW:
    oc_rep_set_boolean(root, state, state);
    oc_rep_set_int(root, power, power);
    oc_rep_set_text_string(root, name, oc_string(name));
    break;
  default:
    break;
  }
  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  OC_DBG("POST_light:\n");
  oc_rep_t *rep = request->request_payload;
  while (rep != NULL) {
    OC_DBG(("key: %s "), oc_string(rep->name));
    switch (rep->type) {
    case OC_REP_BOOL:
      state = rep->value.boolean;
      OC_DBG("value: %d\n", state);
      break;
    case OC_REP_INT:
      power = rep->value.integer;
      OC_DBG("value: %d\n", power);
      break;
    case OC_REP_STRING:
      oc_free_string(&name);
      oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
      break;
    default:
      oc_send_response(request, OC_STATUS_BAD_REQUEST);
      return;
      break;
    }
    rep = rep->next;
  }
  oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
  (void)user_data;
  post_light(request, interface, user_data);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource("Yann's Light", "/a/light", 2, 0);
  oc_resource_bind_resource_type(res, "core.light");
  oc_resource_bind_resource_type(res, "core.brightlight");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_add_resource(res);
}

static void
signal_event_loop(void)
{
  oc_process_post(&sample_server_process, OC_PROCESS_EVENT_TIMER, NULL);
}


OC_PROCESS_THREAD(sample_server_process, ev, data)
{
  (void)data;
  static struct oc_etimer et;
  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources };
  static oc_clock_time_t next_event;
  oc_set_mtu_size(1024);
  oc_set_max_app_data_size(2048);

  OC_PROCESS_BEGIN();

  OC_DBG("Initializing server for arduino");

  while (ev != OC_PROCESS_EVENT_EXIT) {
 	oc_etimer_set(&et, (oc_clock_time_t)next_event);

	if(ev == OC_PROCESS_EVENT_INIT){
		int init = oc_main_init(&handler);
		if (init < 0){
			OC_DBG("Server Init failed!");
			return init;
		}
      	OC_DBG("Server process init!");
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
	uint8_t ETHERNET_MAC[] = {0x92, 0xA1, 0xDA, 0x11, 0x44, 0xA9};
#if defined(__SAMD21G18A__)
  Ethernet.init(5); // CS Pin for MKRZERO
#endif
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
	Serial.begin(115200);
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

#ifdef OC_SECURITY
  oc_storage_config("creds");
#endif /* OC_SECURITY */
	oc_process_start(&sample_server_process, NULL);
  	delay(200);
}

void loop() {
	oc_process_run();
}

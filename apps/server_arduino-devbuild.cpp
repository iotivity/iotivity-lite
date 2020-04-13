/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright 2017-2019 Open Connectivity Foundation
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

/*
 * File for Arduino Due with Wiznet Ethernet board
 */
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


#include "server_devicebuilder.c"


#ifdef OC_SECURITY
void
random_pin_cb(const unsigned char *pin, size_t pin_len, void *data)
{
  (void)data;
  PRINT("\n====================\n");
  PRINT("Random PIN: %.*s\n", (int)pin_len, pin);
  PRINT("====================\n");
}
#endif /* OC_SECURITY */

void
factory_presets_cb(size_t device, void *data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
/* code to include an pki certificate and root trust anchor */
#include "oc_pki.h"
#include "pki_certs.h"
  int credid =
    oc_pki_add_mfg_cert(0, (const unsigned char *)my_cert, strlen(my_cert), (const unsigned char *)my_key, strlen(my_key));
  if (credid < 0) {
    PRINT("ERROR installing manufacturer certificate\n");
  } else {
    PRINT("Successfully installed manufacturer certificate\n");
  }

  if (oc_pki_add_mfg_intermediate_cert(0, credid, (const unsigned char *)int_ca, strlen(int_ca)) < 0) {
    PRINT("ERROR installing intermediate CA certificate\n");
  } else {
    PRINT("Successfully installed intermediate CA certificate\n");
  }

  if (oc_pki_add_mfg_trust_anchor(0, (const unsigned char *)root_ca, strlen(root_ca)) < 0) {
    PRINT("ERROR installing root certificate\n");
  } else {
    PRINT("Successfully installed root certificate\n");
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, credid);
#endif /* OC_SECURITY && OC_PKI */
}

/**
* intializes the global variables
* registers and starts the handler
*/
void
initialize_variables(void)
{
  /* initialize global variables for resource "/binaryswitch" */
  g_binaryswitch_value = false; /* current value of property "value" The status of the switch. */

  /* set the flag for NO oic/con resource. */
  oc_set_con_res_announced(false);

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

/**
* main application.
* intializes the global variables
* registers and starts the handler
* handles (in a loop) the next event.
* An MCU never shuts down.
*/
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

    if (ev == OC_PROCESS_EVENT_INIT) {
      int init = oc_main_init(&handler);
      if (init < 0) {
        OC_DBG("Server Init failed!");
        return init;
      }

      OC_DBG("Server process init!");
    }
    else if (ev == OC_PROCESS_EVENT_TIMER) {
      next_event = oc_main_poll();
      next_event -= oc_clock_time();
    }

    OC_PROCESS_WAIT_EVENT();
  }
 OC_PROCESS_END();
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

  if (ConnectToNetwork() != 0) {
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

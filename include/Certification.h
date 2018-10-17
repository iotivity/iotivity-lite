/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#define RESOURCE_NAME "lightbulb"
#define RESOURCE_URI "/light/"
#define NUM_RESOURCES_TYPES 1
#define Device_TYPE_LIGHT "oic.d.light"
#define RESOURCE_LIGHT_TYPE "core.light"
#define MAX_LIGHT_RESOURCE_COUNT 100
#define NUM_DEVICE 1
#define MAX_STRING 65 
#define FAN_INVISIBLE_URI "/device/fan-invisible"
#define SWITCH_RESOURCE_TYPE "oic.r.switch.binary"
#define LIGHT_COUNT 2
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.3.0, ocf.sh.1.3.0"
#define RESOURCE_1_URI "/binaryswitch"
#define RESOURCE_2_URI "/humidity"
#define RESOURCE_AIR_URI "/AC-binaryswitch"
#define AIR_CON_DEVICE_URI "oic/d"
#define MAX_URI_LENGTH (30)
#define ENGLISH_NAME_VALUE "x.vendor.rt.airconditioner"
#define OBSERVE_PERIODIC 1
#define RESOURCE_INTERFACE 2
#define DEVICE_COUNT 0

static char g_binaryswitch_RESOURCE_URI[] = "/binaryswitch";
static char g_binaryswitch_AIRCON_RESOURCE_INTERFACE[][MAX_STRING] = {"oic.if.a","oic.if.baseline"};

#define PRINTport(endpoint)                                                   \
  do {                                                                         \
    if ((endpoint).flags & IPV4) {                                             \
      PRINT("%d",             \
             (endpoint).addr.ipv4.port);     \
    } else {                                                                   \
      PRINT(                                                                   \
        "%d",                                                             \
         (endpoint).addr.ipv6.port);        \
    }                                                                          \
} while(0)

#define PRINTIPaddr(endpoint)                                                  \
  do {                                                                         \
    if ((endpoint).flags & IPV4) {                                             \
      PRINT("%d.%d.%d.%d", ((endpoint).addr.ipv4.address)[0],             \
            ((endpoint).addr.ipv4.address)[1],                                 \
            ((endpoint).addr.ipv4.address)[2],                                 \
            ((endpoint).addr.ipv4.address)[3]);     \
    } else {                                                                   \
      PRINT(                                                                   \
        "%02x%02x::%02x%02x:%02x%02x:%02x%02x:%"    \
        "02x%"                                                                 \
        "02x",                                                                 \
        ((endpoint).addr.ipv6.address)[0], ((endpoint).addr.ipv6.address)[1],  \
        ((endpoint).addr.ipv6.address)[8], ((endpoint).addr.ipv6.address)[9],  \
        ((endpoint).addr.ipv6.address)[10],                                    \
        ((endpoint).addr.ipv6.address)[11],                                    \
        ((endpoint).addr.ipv6.address)[12],                                    \
        ((endpoint).addr.ipv6.address)[13],                                    \
        ((endpoint).addr.ipv6.address)[14],                                    \
        ((endpoint).addr.ipv6.address)[15]);                                   \
    }                                                                          \
} while(0)


extern int quit;
pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;

extern void register_resources();
extern int app_init(void);
extern void signal_event_loop();
extern void handle_signal();
extern int convert_if_string(char *);
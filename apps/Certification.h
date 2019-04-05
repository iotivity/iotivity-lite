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
#define RESOURCE_LIGHT_TYPE "core.r.light"
#define MAX_LIGHT_RESOURCE_COUNT 100
#define NUM_DEVICE 1
#define MAX_STRING 65
#define LIGHT_INVISIBLE_URI "/device/light-invisible"
#define SWITCH_RESOURCE_TYPE "oic.r.switch.binary"
#define LIGHT_COUNT 2
#define OCF_SPEC_VERSION "ocf.2.0.5"
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
#define CANCEL_SELECTION 0
#define PING_RETRY_COUNT (4)

typedef struct oc_discoverResource_t
{
  struct oc_discoverResource_t *next;
  oc_endpoint_t *endpoint;
  char uri[64];
} oc_discoverResource_t;

const int CALLBACK_WAIT_MIN = 1;
const int CALLBACK_WAIT_MAX = 5;

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
static void createResource();
static void createInvisibleResource();
static void createResourceWithUrl();
static void createManyLightResources();
static oc_collection_t* createGroupResource();
static void deleteAllResources();
static void deleteCreatedGroup();
static void sendPOSTRequest_partialUpdate_userInput();
static void sendPOSTRequest_partialUpdate_userInput_auto_Bin();
static void sendPOSTRequest_partialUpdate_userInput_auto_Hum();
void SendData(char *cmd);
static void findGroup(char *);
static oc_collection_t* updateGroup();
static void updateLocalResourceManually();
static void createSingleAirConResource();
static void handleMenu();
static void selectMenu(int);
static int app_init1();
static void discoverDevice(bool);
static void discoverPlatform(bool);
static void findAllResources();
static void discoverIntrospection();
static void sendGetRequest();
static void sendPutRequestUpdate(void);
static void sendPostRequestUpdate();
static void findResource_UserResType(char *);
static void observe_request();
static void stop_observe();
static int selectResource();
static void waitForCallback();
static void get_platform(oc_client_response_t *data);
static void get_device(oc_client_response_t *data);
static void printEndpointsList();
#ifdef OC_TCP
static void sendPingMessage(uint16_t timeout_seconds);
#endif

#define ASSERT(expr) \
    do { \
        if ((!(expr))) { \
            fprintf(stderr, "%s:%d: %s: Assertion: `" # expr "' failed.\n", \
                __FILE__, __LINE__, __func__); \
            exit(1); \
        } \
    } while (0)

  const unsigned char my_crt[] = {
    0x30, 0x82, 0x03, 0xf8, 0x30, 0x82, 0x03, 0x9e, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x09, 0x00, 0x8d, 0x0a, 0xfb, 0x7b, 0x53, 0xb2, 0x4c, 0xb6,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x30, 0x5b, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x03, 0x4f, 0x43, 0x46, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x19, 0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x65, 0x73,
    0x74, 0x20, 0x49, 0x6e, 0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63,
    0x74, 0x75, 0x72, 0x65, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x1e, 0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x45, 0x53,
    0x54, 0x20, 0x49, 0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61,
    0x74, 0x65, 0x20, 0x43, 0x41, 0x30, 0x30, 0x30, 0x32, 0x30, 0x1e, 0x17,
    0x0d, 0x31, 0x38, 0x31, 0x32, 0x31, 0x33, 0x31, 0x33, 0x33, 0x36, 0x33,
    0x30, 0x5a, 0x17, 0x0d, 0x31, 0x39, 0x30, 0x36, 0x31, 0x31, 0x31, 0x33,
    0x33, 0x36, 0x33, 0x30, 0x5a, 0x30, 0x61, 0x31, 0x0c, 0x30, 0x0a, 0x06,
    0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x4f, 0x43, 0x46, 0x31, 0x22, 0x30,
    0x20, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19, 0x4b, 0x79, 0x72, 0x69,
    0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49, 0x6e, 0x66, 0x72, 0x61,
    0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72, 0x65, 0x31, 0x2d, 0x30,
    0x2b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x24, 0x39, 0x39, 0x30, 0x30,
    0x30, 0x30, 0x31, 0x30, 0x2d, 0x31, 0x31, 0x31, 0x31, 0x2d, 0x31, 0x31,
    0x31, 0x31, 0x2d, 0x31, 0x31, 0x31, 0x31, 0x2d, 0x31, 0x31, 0x31, 0x31,
    0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x30, 0x30, 0x59, 0x30, 0x13,
    0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xe4,
    0xbf, 0xcf, 0x9a, 0x29, 0x2d, 0x91, 0x54, 0x4b, 0x6d, 0x2c, 0x67, 0x38,
    0x7b, 0xe8, 0x7c, 0x58, 0x96, 0x60, 0x40, 0xc7, 0x72, 0xc2, 0x41, 0xb7,
    0x6f, 0xa6, 0x1a, 0x09, 0xe8, 0x85, 0x96, 0xad, 0x02, 0x4c, 0x95, 0xbf,
    0x67, 0x75, 0x24, 0x88, 0x98, 0x3c, 0x2a, 0x9a, 0xdb, 0x95, 0x96, 0x62,
    0x74, 0xce, 0x2d, 0x79, 0xe8, 0x30, 0xfa, 0x4c, 0x4a, 0x97, 0x5e, 0xaf,
    0xb9, 0xb3, 0x5c, 0xa3, 0x82, 0x02, 0x43, 0x30, 0x82, 0x02, 0x3f, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e,
    0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02,
    0x03, 0x88, 0x30, 0x29, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x22, 0x30,
    0x20, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06,
    0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01, 0x06, 0x0a, 0x2b,
    0x06, 0x01, 0x04, 0x01, 0x82, 0xde, 0x7c, 0x01, 0x06, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x46, 0x93, 0xfa, 0xa7,
    0x95, 0xbf, 0xbb, 0x0d, 0x1c, 0x38, 0xc4, 0xce, 0xe7, 0x49, 0x33, 0x16,
    0xe8, 0x59, 0xe9, 0xbe, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0x19, 0x73, 0x6a, 0x04, 0x1a, 0x0b, 0x07,
    0x70, 0x4f, 0x53, 0x79, 0x53, 0x36, 0x87, 0xfc, 0x0c, 0xba, 0x7c, 0xae,
    0x0b, 0x30, 0x81, 0x96, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x01, 0x01, 0x04, 0x81, 0x89, 0x30, 0x81, 0x86, 0x30, 0x5d, 0x06, 0x08,
    0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x51, 0x68, 0x74,
    0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x70, 0x6b, 0x69,
    0x2e, 0x6b, 0x79, 0x72, 0x69, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f,
    0x63, 0x66, 0x2f, 0x63, 0x61, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2f, 0x42,
    0x42, 0x45, 0x36, 0x34, 0x46, 0x39, 0x41, 0x37, 0x45, 0x45, 0x33, 0x37,
    0x44, 0x32, 0x39, 0x41, 0x30, 0x35, 0x45, 0x34, 0x42, 0x42, 0x37, 0x37,
    0x35, 0x39, 0x35, 0x46, 0x33, 0x30, 0x38, 0x42, 0x45, 0x34, 0x31, 0x45,
    0x42, 0x30, 0x37, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x25, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x19, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x6f, 0x63, 0x73, 0x70,
    0x2e, 0x6b, 0x79, 0x72, 0x69, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x30, 0x5f,
    0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x58, 0x30, 0x56, 0x30, 0x54, 0xa0,
    0x52, 0xa0, 0x50, 0x86, 0x4e, 0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f,
    0x74, 0x65, 0x73, 0x74, 0x70, 0x6b, 0x69, 0x2e, 0x6b, 0x79, 0x72, 0x69,
    0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x63, 0x66, 0x2f, 0x63, 0x72,
    0x6c, 0x73, 0x2f, 0x42, 0x42, 0x45, 0x36, 0x34, 0x46, 0x39, 0x41, 0x37,
    0x45, 0x45, 0x33, 0x37, 0x44, 0x32, 0x39, 0x41, 0x30, 0x35, 0x45, 0x34,
    0x42, 0x42, 0x37, 0x37, 0x35, 0x39, 0x35, 0x46, 0x33, 0x30, 0x38, 0x42,
    0x45, 0x34, 0x31, 0x45, 0x42, 0x30, 0x37, 0x2e, 0x63, 0x72, 0x6c, 0x30,
    0x5f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x91, 0x56, 0x01,
    0x00, 0x04, 0x51, 0x30, 0x4f, 0x30, 0x09, 0x02, 0x01, 0x02, 0x02, 0x01,
    0x00, 0x02, 0x01, 0x00, 0x30, 0x36, 0x0c, 0x19, 0x31, 0x2e, 0x33, 0x2e,
    0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x35, 0x31, 0x34, 0x31,
    0x34, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x2e, 0x30, 0x0c, 0x19, 0x31,
    0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x35,
    0x31, 0x34, 0x31, 0x34, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x32, 0x2e, 0x30,
    0x0c, 0x03, 0x43, 0x54, 0x54, 0x0c, 0x05, 0x49, 0x6e, 0x74, 0x65, 0x6c,
    0x30, 0x2a, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x91, 0x56,
    0x01, 0x01, 0x04, 0x1c, 0x30, 0x1a, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04,
    0x01, 0x83, 0x91, 0x56, 0x01, 0x01, 0x00, 0x06, 0x0b, 0x2b, 0x06, 0x01,
    0x04, 0x01, 0x83, 0x91, 0x56, 0x01, 0x01, 0x01, 0x30, 0x30, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0x91, 0x56, 0x01, 0x02, 0x04, 0x22,
    0x30, 0x20, 0x0c, 0x0e, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e,
    0x34, 0x2e, 0x31, 0x2e, 0x37, 0x31, 0x0c, 0x09, 0x44, 0x69, 0x73, 0x63,
    0x6f, 0x76, 0x65, 0x72, 0x79, 0x0c, 0x03, 0x31, 0x2e, 0x30, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48,
    0x00, 0x30, 0x45, 0x02, 0x20, 0x21, 0xac, 0x87, 0x42, 0x81, 0x04, 0x85,
    0x2f, 0x99, 0x38, 0xd1, 0xfb, 0x1f, 0x9c, 0x2e, 0xa7, 0x56, 0xca, 0x58,
    0xb5, 0x89, 0xd4, 0x02, 0x7f, 0x2f, 0x6a, 0x63, 0x91, 0x4e, 0xdf, 0xe8,
    0x5e, 0x02, 0x21, 0x00, 0xd7, 0x0c, 0xc3, 0x66, 0x90, 0xc2, 0x7f, 0xa7,
    0x27, 0x97, 0xc1, 0x0a, 0x24, 0x1b, 0xdc, 0xb8, 0xd4, 0x48, 0xc1, 0xb6,
    0x8f, 0xce, 0xaa, 0x82, 0x0f, 0xb0, 0x3a, 0xd7, 0x41, 0x06, 0x6e, 0x1d
  };

  unsigned char my_key[] = {
    0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20, 0x34, 0x23, 0xa2, 0xf0,
    0x44, 0x8a, 0xe4, 0x4c, 0x8b, 0x21, 0x7e, 0x4c, 0x0d, 0x68, 0x8a,
    0xdc, 0xea, 0x5e, 0xcf, 0xb8, 0x60, 0x0a, 0x97, 0xe3, 0x5a, 0x78,
    0x13, 0xfb, 0x12, 0x48, 0xad, 0x0d, 0xa0, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0xa1, 0x44, 0x03, 0x42,
    0x00, 0x04, 0xe4, 0xbf, 0xcf, 0x9a, 0x29, 0x2d, 0x91, 0x54, 0x4b,
    0x6d, 0x2c, 0x67, 0x38, 0x7b, 0xe8, 0x7c, 0x58, 0x96, 0x60, 0x40,
    0xc7, 0x72, 0xc2, 0x41, 0xb7, 0x6f, 0xa6, 0x1a, 0x09, 0xe8, 0x85,
    0x96, 0xad, 0x02, 0x4c, 0x95, 0xbf, 0x67, 0x75, 0x24, 0x88, 0x98,
    0x3c, 0x2a, 0x9a, 0xdb, 0x95, 0x96, 0x62, 0x74, 0xce, 0x2d, 0x79,
    0xe8, 0x30, 0xfa, 0x4c, 0x4a, 0x97, 0x5e, 0xaf, 0xb9, 0xb3, 0x5c
  };

  unsigned char int_ca[] = {
    0x30, 0x82, 0x02, 0xfa, 0x30, 0x82, 0x02, 0xa1, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x09, 0x00, 0xf3, 0x9b, 0x8c, 0xc0, 0x57, 0x2a, 0x11, 0xb5,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x30, 0x53, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x03, 0x4f, 0x43, 0x46, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x19, 0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x65, 0x73,
    0x74, 0x20, 0x49, 0x6e, 0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63,
    0x74, 0x75, 0x72, 0x65, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x16, 0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x45, 0x53,
    0x54, 0x20, 0x52, 0x4f, 0x4f, 0x54, 0x20, 0x43, 0x41, 0x30, 0x30, 0x30,
    0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x31, 0x33, 0x30, 0x31,
    0x38, 0x31, 0x32, 0x31, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x38, 0x31, 0x31,
    0x32, 0x36, 0x31, 0x38, 0x31, 0x32, 0x31, 0x35, 0x5a, 0x30, 0x5b, 0x31,
    0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x4f, 0x43,
    0x46, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19,
    0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49,
    0x6e, 0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72,
    0x65, 0x31, 0x27, 0x30, 0x25, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x1e,
    0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x49,
    0x6e, 0x74, 0x65, 0x72, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74, 0x65, 0x20,
    0x43, 0x41, 0x30, 0x30, 0x30, 0x32, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xbc, 0x0f, 0x86,
    0x9f, 0x7a, 0x1f, 0x46, 0x91, 0xf8, 0xd1, 0x7b, 0x95, 0xa6, 0x90, 0x51,
    0x7f, 0xbf, 0x26, 0x0e, 0xd7, 0xdc, 0x94, 0xe9, 0x01, 0x77, 0xbf, 0xf7,
    0xdb, 0x24, 0x1c, 0x98, 0xad, 0x8b, 0x43, 0x4c, 0x26, 0xfe, 0xec, 0xa5,
    0xd9, 0xcc, 0x9e, 0x00, 0x13, 0xee, 0x37, 0xa3, 0x45, 0x71, 0x1f, 0x7e,
    0x2d, 0x89, 0x17, 0x67, 0x93, 0xf8, 0x3a, 0xfc, 0xbd, 0x47, 0x8d, 0xd0,
    0xbe, 0xa3, 0x82, 0x01, 0x54, 0x30, 0x82, 0x01, 0x50, 0x30, 0x12, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x08, 0x30, 0x06, 0x01,
    0x01, 0xff, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f,
    0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0x19, 0x73, 0x6a, 0x04,
    0x1a, 0x0b, 0x07, 0x70, 0x4f, 0x53, 0x79, 0x53, 0x36, 0x87, 0xfc, 0x0c,
    0xba, 0x7c, 0xae, 0x0b, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04,
    0x18, 0x30, 0x16, 0x80, 0x14, 0x28, 0x48, 0xe4, 0xe5, 0x27, 0x58, 0xd9,
    0x08, 0xee, 0x09, 0x34, 0xe4, 0xb1, 0xbb, 0x3d, 0x59, 0x66, 0x1f, 0xc8,
    0xf5, 0x30, 0x81, 0x8d, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07,
    0x01, 0x01, 0x04, 0x81, 0x80, 0x30, 0x7e, 0x30, 0x55, 0x06, 0x08, 0x2b,
    0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02, 0x86, 0x49, 0x68, 0x74, 0x74,
    0x70, 0x3a, 0x2f, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x70, 0x6b, 0x69, 0x2e,
    0x6b, 0x79, 0x72, 0x69, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x63,
    0x66, 0x2f, 0x34, 0x45, 0x36, 0x38, 0x45, 0x33, 0x46, 0x43, 0x46, 0x30,
    0x46, 0x32, 0x45, 0x34, 0x46, 0x38, 0x30, 0x41, 0x38, 0x44, 0x31, 0x34,
    0x33, 0x38, 0x46, 0x36, 0x41, 0x31, 0x42, 0x41, 0x35, 0x36, 0x39, 0x35,
    0x37, 0x31, 0x33, 0x44, 0x36, 0x33, 0x2e, 0x63, 0x72, 0x74, 0x30, 0x25,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x86, 0x19,
    0x68, 0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x6f,
    0x63, 0x73, 0x70, 0x2e, 0x6b, 0x79, 0x72, 0x69, 0x6f, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x5a, 0x06, 0x03, 0x55, 0x1d, 0x1f, 0x04, 0x53, 0x30, 0x51,
    0x30, 0x4f, 0xa0, 0x4d, 0xa0, 0x4b, 0x86, 0x49, 0x68, 0x74, 0x74, 0x70,
    0x3a, 0x2f, 0x2f, 0x74, 0x65, 0x73, 0x74, 0x70, 0x6b, 0x69, 0x2e, 0x6b,
    0x79, 0x72, 0x69, 0x6f, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6f, 0x63, 0x66,
    0x2f, 0x34, 0x45, 0x36, 0x38, 0x45, 0x33, 0x46, 0x43, 0x46, 0x30, 0x46,
    0x32, 0x45, 0x34, 0x46, 0x38, 0x30, 0x41, 0x38, 0x44, 0x31, 0x34, 0x33,
    0x38, 0x46, 0x36, 0x41, 0x31, 0x42, 0x41, 0x35, 0x36, 0x39, 0x35, 0x37,
    0x31, 0x33, 0x44, 0x36, 0x33, 0x2e, 0x63, 0x72, 0x6c, 0x30, 0x0a, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00,
    0x30, 0x44, 0x02, 0x1f, 0x05, 0xe4, 0x45, 0x87, 0x7e, 0xbb, 0x9a, 0x4e,
    0x3c, 0x7e, 0x78, 0xe3, 0x00, 0x66, 0x05, 0x12, 0x73, 0xfd, 0xbd, 0x23,
    0xa6, 0x9b, 0xd4, 0x20, 0x7c, 0x7c, 0x21, 0x41, 0xf4, 0x0a, 0x2a, 0x02,
    0x21, 0x00, 0xc2, 0xf0, 0x29, 0xcc, 0x55, 0x33, 0x82, 0xe5, 0xa2, 0x28,
    0xa3, 0x96, 0x20, 0xe2, 0x4e, 0xc1, 0x0c, 0x33, 0x71, 0x6d, 0x14, 0x28,
    0x3e, 0xe8, 0xd8, 0x7a, 0xcd, 0x0e, 0x4d, 0x51, 0xa0, 0x3c
  };

  unsigned char root_ca[] = {
    0x30, 0x82, 0x01, 0xdf, 0x30, 0x82, 0x01, 0x85, 0xa0, 0x03, 0x02, 0x01,
    0x02, 0x02, 0x09, 0x00, 0xf3, 0x9b, 0x8c, 0xc0, 0x57, 0x2a, 0x11, 0xb2,
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    0x30, 0x53, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x03, 0x4f, 0x43, 0x46, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04,
    0x0b, 0x0c, 0x19, 0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x65, 0x73,
    0x74, 0x20, 0x49, 0x6e, 0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63,
    0x74, 0x75, 0x72, 0x65, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04,
    0x03, 0x0c, 0x16, 0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x45, 0x53,
    0x54, 0x20, 0x52, 0x4f, 0x4f, 0x54, 0x20, 0x43, 0x41, 0x30, 0x30, 0x30,
    0x32, 0x30, 0x1e, 0x17, 0x0d, 0x31, 0x38, 0x31, 0x31, 0x33, 0x30, 0x31,
    0x37, 0x33, 0x31, 0x30, 0x35, 0x5a, 0x17, 0x0d, 0x32, 0x38, 0x31, 0x31,
    0x32, 0x37, 0x31, 0x37, 0x33, 0x31, 0x30, 0x35, 0x5a, 0x30, 0x53, 0x31,
    0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x03, 0x4f, 0x43,
    0x46, 0x31, 0x22, 0x30, 0x20, 0x06, 0x03, 0x55, 0x04, 0x0b, 0x0c, 0x19,
    0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x65, 0x73, 0x74, 0x20, 0x49,
    0x6e, 0x66, 0x72, 0x61, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x75, 0x72,
    0x65, 0x31, 0x1f, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x16,
    0x4b, 0x79, 0x72, 0x69, 0x6f, 0x20, 0x54, 0x45, 0x53, 0x54, 0x20, 0x52,
    0x4f, 0x4f, 0x54, 0x20, 0x43, 0x41, 0x30, 0x30, 0x30, 0x32, 0x30, 0x59,
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0x6b, 0x75, 0xb1, 0x4d, 0x90, 0x85, 0x07, 0x0a, 0xfe, 0x47, 0xe5,
    0x29, 0x21, 0x7d, 0x4c, 0x2a, 0xef, 0x29, 0xa0, 0xdc, 0x90, 0xb5, 0x9d,
    0x66, 0x8c, 0xaf, 0x3f, 0xac, 0xf4, 0x3a, 0xba, 0x8d, 0x76, 0xd0, 0x6c,
    0x71, 0x98, 0x15, 0x62, 0xc4, 0x87, 0x31, 0x06, 0x75, 0x47, 0x5f, 0x70,
    0x5b, 0x1b, 0x1f, 0x96, 0xf3, 0x6b, 0xf1, 0xb3, 0x15, 0x5b, 0x52, 0xb7,
    0x1d, 0x63, 0x24, 0xa6, 0xc8, 0xa3, 0x42, 0x30, 0x40, 0x30, 0x0f, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01,
    0x01, 0xff, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff,
    0x04, 0x04, 0x03, 0x02, 0x01, 0x86, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d,
    0x0e, 0x04, 0x16, 0x04, 0x14, 0x28, 0x48, 0xe4, 0xe5, 0x27, 0x58, 0xd9,
    0x08, 0xee, 0x09, 0x34, 0xe4, 0xb1, 0xbb, 0x3d, 0x59, 0x66, 0x1f, 0xc8,
    0xf5, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03,
    0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x25, 0x31, 0x4c, 0x20,
    0x55, 0xe2, 0xfc, 0x77, 0x95, 0xb8, 0x8d, 0x97, 0x45, 0x27, 0x96, 0x60,
    0x72, 0x59, 0x3b, 0x5d, 0x3e, 0xba, 0x2c, 0xd3, 0x1f, 0x1a, 0x41, 0x31,
    0x4a, 0x35, 0x35, 0x9e, 0x02, 0x21, 0x00, 0xd3, 0xaf, 0x4e, 0x67, 0x77,
    0xd8, 0x0d, 0x24, 0x12, 0xd2, 0x29, 0x1d, 0xb8, 0x8a, 0x03, 0xcf, 0x91,
    0x14, 0x30, 0x8f, 0x25, 0x68, 0xcd, 0xe2, 0x5a, 0x31, 0xac, 0x10, 0xbb,
    0xbf, 0x42, 0x44
  };
#include <stdio.h>
#include "oc_api.h"
#include "oc_ri.h"

#define RESOURCE_NAME "lightbulb"
#define RESOURCE_URI "/light/"
#define NUMRESOURCESTYPES 1
#define DEVICE 0
#define RESOURCE_LIGHT_TYPE "core.light"
#define MAX_LIGHT_RESOURCE_COUNT 4
#define NDEVICE 1
#define MAX_STRING 65 
#define FAN_INVISIBLE_URI "/device/fan-invisible"
pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;
void register_resources(void);
//void post_binaryswitch(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
//void get_binaryswitch();
int convert_if_string(char *interface_name);
void register_resources();


/*int g_binaryswitch_nr_resource_interfaces = 4;
char g_binaryswitch_RESOURCE_ENDPOINT[] = "/binaryswitch";// used path for this resource
char g_binaryswitch_RESOURCE_TYPE[][MAX_STRING] = {"oic.r.temperature"}; // rt value (as an array)
char g_binaryswitch_RESOURCE_INTERFACE[][MAX_STRING] = {"oic.if.a","oic.if.baseline"}; // interface if (as an array) 
int g_binaryswitch_nr_resource_types = 1;
  // max size of the strings.
bool g_binaryswitch_value = false;*/

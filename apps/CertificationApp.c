#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>
#include "oc_api.h"
#include <string.h>
#include "Certification.h"

bool result;
bool g_isLightTempResourceCreated = false;
bool g_isLightFanResourceCreated = false;
bool g_isSecuredResourceCreated = false;
bool g_isManyLightCreated = false;
bool g_InvisibleResourceCreated = false;

static void createInvisibleResource();
static void createResourceWithUrl();
static void createSecuredResource();
static void createManyLightResources();
static void createResource();
int Stack_Initialisation();
void handleMenu(int argc,char* argv[]);

void ShowMenu(int argc,char* argv[])
{
    printf("Please Select an option from the menu and press Enter\n" );
    printf("\t\t   0  : Quit IUT Emulator App\n" );
    printf("\t Server Operations:\n" );
    printf("\t\t   1  : Create Normal Resource\n" );
    printf( "2   : Create Invisible Resource\n" );
    printf( "3   : Create Resource With Complete URL\n" );
    printf( "4   : Create Secured Resource\n" );
    printf( "5   : Create %d Light Resources\n",MAX_LIGHT_RESOURCE_COUNT );
    printf( "6   : Create Group Resource\n" );
    printf( "7   : Delete All Resources\n" );
    printf( "8   : Delete Created Group\n" );
    printf("\t Client Operations:\n" );
    printf("\t\t   9  : Find Introspection\n" );
    printf("\t\t   10  : Find Resource using Interface Query\n" );
    printf("\t\t   11  : Find Specific Type Of Resource\n" );
    printf("\t\t   12  : Find All Resources\n" );
    printf("\t\t   13  : Find All Resources using Baseline Query - Unicast\n" );
    printf("\t\t   14  : Find Specific Type Of Resource - Unicast\n" );
    printf("\t\t   15  : Find All Resources - Unicast\n" );
    printf("\t\t   16  : Join Found Resource To The Group\n" );
    printf("\t\t   17  : Send GET Request\n" );
    printf("\t\t   18  : Send GET Request with query\n" );
    printf("\t\t   19  : Send PUT Request - Create Resource\n" );
    printf("\t\t   20  : Send PUT Request - Complete Update\n" );
    printf("\t\t   21  : Send POST Request - Partial Update - Default\n" );
    printf("\t\t   22  : Send POST Request - Partial Update - User Input\n" );
    printf("\t\t   23  : Send POST Request - Create Sub-Ordinate Resource\n" );
    printf("\t\t   24  : Send Delete Request\n" );
    printf("\t\t   25  : Observe Resource - Retrieve Request with Observe\n" );
    printf("\t\t   26  : Cancel Observing Resource\n" );
    printf("\t\t   27  : Cancel Observing Resource Passively\n" );
    printf("\t\t   28  : Discover Device - Unicast\n" );
    printf("\t\t   29  : Discover Device - Multicast\n" );
    printf("\t\t   30  : Discover Platform - Multicast\n" );
    printf("\t\t   31  : Find Group\n" );
    printf("\t\t   32  : Join Found Resource To Found Group\n" );
    printf("\t\t   33  : Update Collection\n" );
    printf("\t\t   34  : Update Local Resource Manually\n" );
    printf("\t\t   35  : Update Local Resource Automatically\n" );
    printf("\t\t   36  : Set Quality of Service - CON(Confirmable)\n" );
    printf("\t\t   37  : Set Quality of Service - NON(Non-Confirmable)\n" );
    printf("\t\t   38  : Reset Secure Storage\n" );
    printf("\t Smart Home Vertical Resource Creation:\n" );
    printf("\t\t   101  : Create Smart TV Device\n" );
    printf("\t\t   102  : Create Air Conditioner Device\n" );
#ifdef __SECURED__
    printf("\t\t   103  : Create Secured Smart TV Device\n" );
    printf("\t\t   104  : Create Secured Air Conditioner Device\n" );
    printf("\t\t   105  : Create Secured Air Conditioner Single Resource\n" );
    printf("\t\t   106  : Create Secured Vendor Defined Resource\n" );
#endif
    printf("\t\t   107  : Create Air Conditioner Single Resource\n" );
    printf("\t\t   108  : Create  Vendor Defined Resource\n" );
    printf("\t\t   109  : Prepare for Wifi Easy Setup\n" );
    printf("\t\t   110  : Publish Created Resources To RD\n" );
    printf("\t\t   111  : Update Published Resources To RD\n" );
    printf("\t\t   112  : Delete Published Resources From RD\n" );
    printf("\t\t   113  : Create Extra Device\n" );
    printf("\t\t   114  : Update Last Error Code\n" );
    printf("\t\t   115  : Create Complex Device For Introspection\n" );
    printf("\t\t   116  : Create Air Purifier Device\n" );
    printf("\t\t   117  : Create Network Monitoring and Maintaince Resources\n" );
    printf("\t\t   118  : Create Sample Batch collection\n" );
    printf("\t\t   119  : Create Cloud Configuration Resource\n" );

    handleMenu(argc,argv);
}

void selectMenu(int choice)
{

  {
    switch(choice){
        case 1:
            createResource();
            break;

        case 2:
            createInvisibleResource();
            break;

        case 3:
            createResourceWithUrl();
            break;

        case 4:
            createSecuredResource();
            break;

        case 5:
            createManyLightResources();
            break;

        case 0:
            exit(0);
            break;

        default:
            printf("Invalid Input. Please input your choice again\n");
  }
}

}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)user_data;
  (void)request;
  (void)interface;

}
/*
calling the register_resources  function of device_builder_server.c
*/
static void createResource()
{
    printf("\ncreateResource called!!\n");
    if (g_isLightTempResourceCreated == false) {
      register_resources();
      result = true;
      if (result == true) {
        printf("Resource created successfully\n");
        g_isLightTempResourceCreated = true;
      }
      else {
        printf("Unable to create light resource\n");
      }
    }
    else {
      printf("LightResource already created");
    }
}
/*
   pasing the invisible resource uri
*/

static void createInvisibleResource()
{
  printf("createInvisibleResource called\n");
      if (g_InvisibleResourceCreated == false) {
        oc_resource_t *res = oc_new_resource(NULL, FAN_INVISIBLE_URI, g_3DPrinter_nr_resource_types, 0);
        oc_resource_set_default_interface(res, OC_IF_RW);
        oc_resource_set_discoverable(res, true);
        oc_resource_set_periodic_observable(res, 1);
        oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
        result = oc_add_resource(res);

        if (result == true) {
          printf("Invisible Light Resource created successfully\n");
          g_isSecuredResourceCreated = true;
        }
        else {
          printf("Unable to create Invisible Light Resource \n");
        }
      }
}

void createResourceWithUrl()
{
    printf("createResourceWithUrl will implement later\n");
}
/*
after creating the resource make the properties as secure
*/

static void createSecuredResource()
{
  bool add_device;
  printf("createSecuredResource called\n");
  if (g_isSecuredResourceCreated == false) {

    oc_resource_t *res = oc_new_resource(NULL, g_3DPrinter_RESOURCE_ENDPOINT, g_3DPrinter_nr_resource_types, 0);
    oc_resource_set_default_interface(res, OC_IF_RW);
    oc_resource_set_discoverable(res, true);
    oc_resource_set_periodic_observable(res, 1);
    oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
    res->properties |= OC_SECURE;
    result = oc_add_resource(res);
    if (result == true) {

      printf("Secure Light Resource created successfully\n");
      g_isSecuredResourceCreated = true;
    }
    else {
      printf("Unable to create Secure Light Resource \n");
    }

    oc_resource_t *res2 = oc_new_resource(NULL, g_AudioControls_RESOURCE_ENDPOINT, g_AudioControls_nr_resource_types, 0);
    oc_resource_set_default_interface(res2, OC_IF_RW);
    oc_resource_set_discoverable(res2, true);
    oc_resource_set_periodic_observable(res2, 1);
    oc_resource_set_request_handler(res2, OC_GET, get_light, NULL);
    res->properties |= OC_SECURE;

    add_device = oc_add_resource(res2);
    if (add_device == true) {

      printf("Secure Light Resource created successfully\n");
      g_isSecuredResourceCreated = true;
    
    }
    else {
           
      printf("Unable to create Secure Light Resource \n");
    
    }
  }
  else {
    printf("Secured Resource already  created!!");
  }
}

/*
Giving input: baseUri
lightCount added in the baseUri

*/

static void createManyLightResources()
{
  printf("createManyLightResources called!!\n");
  char baseUri[20] = "/device/light-";
  int lightCount = 2;
  if(g_isManyLightCreated == false) {

    char uri[20] = "";
    
    for (int i = 0; i < MAX_LIGHT_RESOURCE_COUNT; i++,lightCount++)
        {
            sprintf(uri,"/device/light-%d",lightCount);
            printf("%s\n",baseUri);
            printf("%s\n",uri);

            oc_resource_t *res2 = oc_new_resource(RESOURCE_NAME, uri, NUMRESOURCESTYPES, NDEVICE);
            oc_resource_bind_resource_type(res2, RESOURCE_LIGHT_TYPE);
            oc_resource_bind_resource_interface(res2, OC_IF_BASELINE);
            oc_resource_set_default_interface(res2, OC_IF_RW);
            oc_resource_set_discoverable(res2, true);
            oc_resource_set_periodic_observable(res2, 1);
            oc_resource_set_request_handler(res2, OC_GET, get_light, NULL);
            int add_device = oc_add_resource(res2);

            if (add_device == true) {

                printf("Light Resource created successfully with uri:\n");
                g_isManyLightCreated = true;
            }
            else {
                
              printf("Unable to create Light resource with uri");
            }
        }
    }
    else {
      printf("Many Light Resources already created!!");
    }
}

int main(int argc,char* argv[])
{

  int stack_init = Stack_Initialisation();
  if(stack_init < 0) {

    printf("Stack Initialisation is not happened");
  }
  else {
    printf("stack Initialisation is happened properly");

  }
  if (argc > 1) {
    printf("\nCreating resource\n");

  }
  else if (argv == 0){

    exit(1);
  }
  else {
    
    printf("Inavlid option");

  }

    ShowMenu(argc,argv);
    return 0;
}

int Stack_Initialisation()
{
   int init;
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);

  static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       };

  oc_clock_time_t next_event;

#ifdef OC_SECURITY
  oc_storage_config("./device_builder_server_creds");
#endif /* OC_SECURITY */

  init = oc_main_init(&handler);
  if (init < 0)
    return init;

  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    } else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
  oc_main_shutdown();
  return 0;
}

void handleMenu(int argc,char* argv[])
{
  int choice;
  do {
    if (scanf("%d",&choice)){

        printf("\n");
        selectMenu(choice);
        ShowMenu(0,NULL);
    }
    else {
        printf(" Wrong Input type of argument, should be number!");

    }
  } while(choice);

  if(argc > 1) {

      printf("\nCreating resource\n");

  }
  else if (argv == 0){

      exit(1);

  }
  else {
          
      printf("Inavlid option");
  }
}

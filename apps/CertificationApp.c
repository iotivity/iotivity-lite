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
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "oc_api.h"
#include <string.h>
#include "Certification.h"
#include "oc_collection.h"

static bool g_addInvisibleResource = false;
static bool g_isTempResourceCreated = false;
static bool g_isManyLightCreated = false;
static bool g_isInvisibleResourceCreated = false;
static bool g_createResourceWithURL = false;
static bool g_isAirConDeviceCreated = false;

static void createResource();
static void createInvisibleResource();
static void createResourceWithUrl();
static void createManyLightResources();
static oc_resource_t* createGroupResource();
static void deleteAllResources();
static void deleteCreatedGroup();
static void findGroup(char *);
static void createSingleAirConResource();
void handleMenu();
void selectMenu(int);

#define RESOURCE_1_URI "/binaryswitch"
#define RESOURCE_2_URI "/humidity"
oc_resource_t* collectionPointer;

/*It display the available options */
void showMenu(int argc, char* argv[])
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
    printf("\t\t   31  : Find Group\n" );
    printf("\t\t   107  : Create Air Conditioner Single Resource\n" );

    int choice;

    if (argc > 4) {
        for (int i = 5; i < argc; i++) {
                choice = atoi(argv[i]);
                selectMenu(choice);
        }
    }
}

/*Perform the selected operation*/
void selectMenu(int choice)
{
    switch(choice) {
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
            printf("Bydefault Resource created in Secure mode");
            break;

        case 5:
            createManyLightResources();
            break;

        case 6:
            collectionPointer = createGroupResource();
            break;

        case 7:
            deleteAllResources();
            break;

        case 8:
            deleteCreatedGroup();
            break;

        case 31: ;
            unsigned int count = 25;//number of bytes allocated to 'collection_uri_input' using malloc
            char* collection_uri_input = malloc((size_t)count);
            printf("\nPlease enter the group URI\n");
            int scanf_returnValue = scanf("%s",collection_uri_input);
            if(scanf_returnValue == 1){
               findGroup(collection_uri_input);
            }
            else printf("Failed to read URI");
            break;

        case 107:
            createSingleAirConResource();
            break;

        case 0:
            exit(0);
            break;

        default:
            printf("Invalid Input. Please input your choice again\n");
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

    if (g_isTempResourceCreated == false) {
        register_resources();
        printf("Resource created successfully\n");
        g_isTempResourceCreated = true;
    }
    else {
        printf("Resource already created\n");
    }
}

/*
   passing the invisible resource uri
*/
static void createInvisibleResource()
{
    printf("createInvisibleResource called!!\n");

    if (g_isInvisibleResourceCreated == false) {
        oc_resource_t *res = oc_new_resource(NULL, FAN_INVISIBLE_URI, 1, 0);
        oc_resource_set_default_interface(res, OC_IF_RW);
        oc_resource_set_discoverable(res, true);
        oc_resource_set_periodic_observable(res, 1);
        oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
        g_addInvisibleResource = oc_add_resource(res);

        if (g_addInvisibleResource == true) {
            printf("Invisible Light Resource created successfully\n");
            g_isInvisibleResourceCreated = true;
        }
        else {
            printf("Unable to create Invisible Light Resource \n");
        }
    }
    else {
          printf("Resource already created!!\n");
    }
}

/*creating the the resource by using url*/
static void createResourceWithUrl()
{
    printf("Creating Resource with complete URL called!!\n");
    if (g_createResourceWithURL == false) {
        oc_resource_t *res = oc_ri_get_app_resource_by_uri(g_3DPrinter_RESOURCE_ENDPOINT, strlen(g_3DPrinter_RESOURCE_ENDPOINT), 0);
        if (res->uri.ptr == g_3DPrinter_RESOURCE_ENDPOINT) {
            printf("Creating Resource with complete URL already created\n");
            g_createResourceWithURL = true;
        }
    }
    else {
        printf("Resource with complete URL already created!!\n");
    }
}

/*
input is baseUri,lightCount added in the baseUri
*/
static void createManyLightResources()
{
    printf("createManyLightResources called!!\n");

    bool  add_LightResource;
    char baseUri[20] = "/device/light-";
    int lightCount = LIGHT_COUNT;
    char uri[20] = "";

    if (g_isManyLightCreated == false) {

        for (int i = 0; i < MAX_LIGHT_RESOURCE_COUNT; i++, lightCount++) {
            sprintf(uri,"/device/light-%d", lightCount);
            printf("%s\n",baseUri);
            printf("%s\n",uri);

            oc_resource_t *res = oc_new_resource(RESOURCE_NAME, uri, NUM_RESOURCES_TYPES, NUM_DEVICE);
            oc_resource_bind_resource_type(res, RESOURCE_LIGHT_TYPE);
            oc_resource_bind_resource_interface(res, OC_IF_BASELINE);
            oc_resource_set_default_interface(res, OC_IF_RW);
            oc_resource_set_discoverable(res, true);
            oc_resource_set_periodic_observable(res, 1);
            oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
            add_LightResource = oc_add_resource(res);

            if (add_LightResource == true) {

                printf("Light Resource created successfully with uri:\n");
                g_isManyLightCreated = true;
            }
            else {
                printf("Unable to create Light resource with uri\n");
            }
        }
    }
    else {
      printf("Many Light Resources already created!!\n");
    }
}

static oc_resource_t* createGroupResource(){

 oc_resource_t *resource_one = oc_ri_get_app_resource_by_uri(RESOURCE_1_URI, strlen(RESOURCE_1_URI),0);
 oc_resource_t *resource_two = oc_ri_get_app_resource_by_uri(RESOURCE_2_URI, strlen(RESOURCE_2_URI),0);

 #if defined(OC_COLLECTIONS)

  const char* collection_name = "Example Collection ";
  const char* collection_uri = "/example/collection";

  oc_resource_t *new_collection = oc_new_collection(collection_name, collection_uri, 2, 0);

  if(new_collection != NULL)
  printf("\nNew collection: %s\n",new_collection->name.ptr);

  oc_resource_bind_resource_type(new_collection, "oic.wk.col");
  oc_resource_set_discoverable(new_collection, true);


  oc_link_t *link_one = oc_new_link(resource_one);
  oc_collection_add_link(new_collection, link_one);

  oc_link_t *link_two = oc_new_link(resource_two);
  oc_collection_add_link(new_collection, link_two);

  oc_add_collection(new_collection);

 #endif /* OC_COLLECTIONS */

  return new_collection;

}

static void deleteAllResources()
{
    printf("deteAllResources called!!\n");
    
    oc_resource_t *res = oc_ri_get_app_resources();

    while(res)
    {
        oc_ri_delete_resource(res);
        res = oc_ri_get_app_resources();
    }

    if (res == NULL) {
        printf("All Resources Deleted\n");
    }

    g_isManyLightCreated = false;
    g_addInvisibleResource = false;
    g_isTempResourceCreated = false;
    g_createResourceWithURL = false;
    g_isAirConDeviceCreated = false;
}

static void deleteCreatedGroup(){

oc_collection_free((oc_collection_t*)collectionPointer);
printf("\nCollection deleted\n");

}

static void findGroup(char* uri_input){

  printf("\nFind Group option chosen\n");

  printf("\nparameter passed: %s\n",uri_input);

  oc_collection_t* tempCollection = oc_get_collection_by_uri(uri_input, strlen(uri_input), 0);

  if(tempCollection == NULL)
    printf("\nGroup does not exist\n");
  else
    printf("\nGroup found. Collection name is %s\n\n", tempCollection->name.ptr);

}

static void
get_airconditioner(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
    (void)user_data;
    (void)request;
    (void)interface;

}

/*using the  uri creating the air conditioner resource*/
static void createSingleAirConResource()
{

    printf("Creating AirCon Device Resources!!\n");

    bool add_device;
    int ret;

    if (g_isAirConDeviceCreated == false) {
        ret = oc_init_platform("x.com.vendor.device.eco.power", NULL, NULL);
        ret |= oc_add_device(Device_TYPE_LIGHT, "None", "Binary Switch",
                             OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION,
                             NULL, NULL);

        oc_resource_t *res = oc_new_resource(ENGLISH_NAME_VALUE, AC_SWITCH_URI, NUM_RESOURCES_TYPES, NUM_DEVICE);
        oc_resource_bind_resource_type(res, SWITCH_RESOURCE_TYPE);
        oc_resource_set_default_interface(res, OC_IF_RW);
        oc_resource_bind_resource_interface(res, OC_IF_BASELINE|OC_IF_A);
        oc_resource_set_discoverable(res, true);
        oc_resource_set_periodic_observable(res, 1);
        oc_resource_set_request_handler(res, OC_GET, get_airconditioner, NULL);
        add_device = oc_add_resource(res);

        if (add_device == true) {
            printf("AirCon Binary Switch Resource created successfully\n");
            g_isAirConDeviceCreated = true;
        }
        else {
            printf("Unable to create AirCon Binary Switch resource\n");
        }
    }
    else
    {
        printf("Already Smart Home Air Conditioner Device Resource is created!!\n");
    }
}

/**
* handle Ctrl-C
* @param signal the captured signal
*/
void handleSignalCb(int signal)
{
    (void)signal;
    quit = 1;
}

int main(int argc, char* argv[])
{
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handleSignalCb;
    sigaction(SIGINT, &sa, NULL);

    int init;
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
            if (argc > 1) {
                int optionSelected = atoi(argv[1]);
                if (optionSelected == 1) {
                    printf("Using CON Server :same thing we will implement later");
                }
                else if (optionSelected == 0) {
                    printf("Using NON Server") ;
                }
                else {
                printf("Supplied quality of service is invalid. Using default server type: NON");
                }
            }
            else {
                printf("No QoS supplied. Using default: NON");
            }
            if (argc > 2) {
                int optionSelected = atoi(argv[2]);

                if (optionSelected == 6) {
                    printf("Using IP version: IPv6: same thing we will implement later");
                }
               else if (optionSelected == 4) {
                   printf("Using IP version: IPv4: same thing we will implement later");
               }
               else {
                    printf("Invalid input argument. Using default: IPv6");
               }
            }
            else {
                printf("No IP version supplied. Using default: IPv6");
            }
            if (argc > 3) {
                printf("Samething we will implement later");
            }
            if (argc > 4) {
                printf("same thing we will implement later");


            }
            /*Show the available options*/
            showMenu(argc, argv);

            /* Take the input from user and do the selected operation*/
            handleMenu();

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

void handleMenu()
{
    int choice;
    do {
           if (scanf("%d", &choice)) {
               printf("\n");
               if (!quit) {
                  selectMenu(choice);
                  showMenu(0, NULL);
               }
            }
    } while(choice && (quit == 0));
}

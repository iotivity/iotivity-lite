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

static bool addInvisibleResource;
static bool addCreateResource;
static bool g_DeleteResource = false;
bool g_isTempResourceCreated = false;
bool g_isLightFanResourceCreated = false;
bool g_isManyLightCreated = false;
bool g_InvisibleResourceCreated = false;
static bool g_childHandle = false;
static bool g_isAirConDeviceCreated = false;

static void createResource();
static void createInvisibleResource();
static void createResourceWithUrl();
static void createManyLightResources();
static void deleteAllResources();
static void createSingleAirConResource();
void WaitForUserInput();
void selectMenu(int);

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
    printf("\t\t   107  : Create Air Conditioner Single Resource\n" );
    if (argc > 1) {
        for (int i = 5; i < argc; i++)
            {
                int choice = atoi(argv[i]);
                selectMenu(choice);
            }
    }
}

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

        case 7:
            deleteAllResources();
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
        addCreateResource = true;
        if (addCreateResource == true) {
            printf("Resource created successfully\n");
            g_isTempResourceCreated = true;
        }
        else {
            printf("Unable to create light resource\n");
        }
    }
    else {
        printf("LightResource already created\n");
    }
}
/*
   passing the invisible resource uri
*/

static void createInvisibleResource()
{
    printf("createInvisibleResource called\n");
    if (g_InvisibleResourceCreated == false) {
        oc_resource_t *res = oc_new_resource(NULL, FAN_INVISIBLE_URI, 1, 0);
        oc_resource_set_default_interface(res, OC_IF_RW);
        oc_resource_set_discoverable(res, true);
        oc_resource_set_periodic_observable(res, 1);
        oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
        addInvisibleResource = oc_add_resource(res);

        if (addInvisibleResource == true) {
            printf("Invisible Light Resource created successfully\n");
            g_InvisibleResourceCreated = true;
        }
        else {
            printf("Unable to create Invisible Light Resource \n");
        }
    }
    else {
          printf("Resource already created!!\n");
    }
}

/*using the url creating the the resource*/

static void createResourceWithUrl()
{
    printf("Creating Resource with complete URL called\n");
    if (g_childHandle == false) {
        oc_resource_t *res = oc_ri_get_app_resource_by_uri(g_3DPrinter_RESOURCE_ENDPOINT, strlen(g_3DPrinter_RESOURCE_ENDPOINT), 0);
        if (res->uri.ptr == g_3DPrinter_RESOURCE_ENDPOINT) {
            printf("Creating Resource with complete URL created successfully\n");
            g_childHandle = true;
        }
    }
    else {
        printf("Resource with complete URL already created!!\n");
    }
}
/*
Giving input: baseUri
lightCount added in the baseUri

*/

static void createManyLightResources()
{
    bool  g_lightIsAddResource;
    printf("createManyLightResources called!!\n");
    char baseUri[20] = "/device/light-";
    int lightCount = LIGHT_COUNT;
    if (g_isManyLightCreated == false) {

        char uri[20] = "";

        for (int i = 0; i < MAX_LIGHT_RESOURCE_COUNT; i++, lightCount++) {
            sprintf(uri,"/device/light-%d", lightCount);
            printf("%s\n",baseUri);
            printf("%s\n",uri);

            oc_resource_t *res = oc_new_resource(RESOURCE_NAME, uri, NUM_RESOURCES_TYPES, NDEVICE);
            oc_resource_bind_resource_type(res, RESOURCE_LIGHT_TYPE);
            oc_resource_bind_resource_interface(res, OC_IF_BASELINE);
            oc_resource_set_default_interface(res, OC_IF_RW);
            oc_resource_set_discoverable(res, true);
            oc_resource_set_periodic_observable(res, 1);
            oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
            g_lightIsAddResource = oc_add_resource(res);

            if (g_lightIsAddResource == true) {

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

/*
Resources created by selecting option 1 are not being deleted at the moment
*/
static void deleteAllResources()
{
    printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'deleteAllResources' called<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
    
    oc_resource_t *res = oc_ri_get_app_resources();
    while(res)
    {
        oc_ri_delete_resource(res);
        res = oc_ri_get_app_resources();
        g_DeleteResource = true;
    }
    if (g_DeleteResource == true) {

       printf("Resource  deleted successfully\n");
    }
    else {
        printf("Resource is already Deleted\n");
    }
    g_isManyLightCreated = false;
    addInvisibleResource = false;
    g_isTempResourceCreated = false;
    g_childHandle = false;
    g_isAirConDeviceCreated = false;
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
    bool add_device;
    printf("Creating AirCon Device Resources!!\n");
    if (g_isAirConDeviceCreated == false) {
        int ret = oc_init_platform("x.com.vendor.device.eco.power", NULL, NULL);
            ret |= oc_add_device(Device_TYPE_LIGHT, "None", "Binary Switch",
                       "ocf.1.0.0", // icv value
                       "ocf.res.1.3.0, ocf.sh.1.3.0",  // dmv value
                       NULL, NULL);

        oc_resource_t *res2 = oc_new_resource(ENGLISH_NAME_VALUE, AC_SWITCH_URI, NUM_RESOURCES_TYPES, NDEVICE);
        oc_resource_bind_resource_type(res2, SWITCH_RESOURCE_TYPE);
        oc_resource_set_default_interface(res2, OC_IF_RW);
        oc_resource_bind_resource_interface(res2, OC_IF_BASELINE|OC_IF_A);
        oc_resource_set_discoverable(res2, true);
        oc_resource_set_periodic_observable(res2, 1);
        oc_resource_set_request_handler(res2, OC_GET, get_airconditioner, NULL);
        add_device = oc_add_resource(res2);

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
        printf("Already Smart Home Air Conditioner Device Resources are  created!!\n");
    }
}

void stackTerminateHandle_Signal(int signal)
{
    (void)signal;
    quit = 1;
}

int main(int argc,char* argv[])
{
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = stackTerminateHandle_Signal;
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

            ShowMenu(argc, argv);
            WaitForUserInput();

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

void WaitForUserInput()
{
    int choice;
    do {
           if (scanf("%d", &choice)) {
               printf("\n");
               if (!quit) {
                  selectMenu(choice);
                  ShowMenu(0, NULL);
               }
            }
       } while(choice && (quit == 0));
}
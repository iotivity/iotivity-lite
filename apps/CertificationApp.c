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
#include <ctype.h>
#include "oc_api.h"
#include <string.h>
#include "Certification.h"
#include "oc_collection.h"
#include "oc_rep.h"
#include "oc_pki.h"

#ifdef OC_CLIENT
#include "oc_client_state.h"
#endif

OC_LIST(discoverResource);
OC_MEMB(discoverResource_m, oc_discoverResource_t, MAX_NUM_RES);

static bool g_addInvisibleResource = false;
static bool g_isTempResourceCreated = false;
static bool g_isManyLightCreated = false;
static bool g_isInvisibleResourceCreated = false;
static bool g_createResourceWithURL = false;
static bool g_isAirConDeviceCreated = false;
static bool g_binaryswitch_valuecb = false;
static char postRequestUri[MAX_URI_LENGTH];
static oc_endpoint_t *postRequestEndpoint = NULL;
static char observeUri[MAX_URI_LENGTH];
static oc_endpoint_t *observeEndpoint = NULL;
static char putRequestUri[MAX_URI_LENGTH];
static oc_endpoint_t *putRequestEndpoint = NULL;
static bool light_state = false;

static char g_binaryswitch_RESOURCE_PROPERTY_NAME_value[] = "value";
static char* UserResourceType_input = NULL;
static char a_light[MAX_URI_LENGTH];
static oc_endpoint_t set_ep;
static int g_securityType;

static bool discoverDev = false;
static bool discoverDeviceInfo = false;
static bool discoverPlatformInfo= false;
static bool g_hasCallbackArrived = false;
#ifdef OC_TCP
static size_t ping_count = 0;
static uint16_t ping_timeout = 1;
#endif
static oc_string_t name;
static bool state;
static int power;

static oc_endpoint_t *light_server;
static oc_collection_t* collectionPointer;
static oc_qos_t g_qos = LOW_QOS;
static unsigned int uri_size = 25;

pthread_mutex_t mutex;
pthread_mutex_t app_mutex;
/*It display the available options */
void showMenu(int argc, char* argv[])
{
    int choice;

    printf("\n\t-----------------------------------------------------\n");
    printf("\tPlease Select an option from the menu and press Enter\n" );
    printf("\t-----------------------------------------------------\n");
    printf("\t\t0   : Quit Certification App\n" );
    printf("\n\tServer Operations:\n" );
    printf("\t\t1   : Create Normal Resource\n" );
    printf("\t\t2   : Create Invisible Resource\n" );
    printf("\t\t3   : Create Resource With Complete URL\n" );
    printf("\t\t4   : Create Secured Resource\n" );
    printf("\t\t5   : Create %d Light Resources\n",MAX_LIGHT_RESOURCE_COUNT );
    printf("\t\t6   : Create Group Resource\n" );
    printf("\t\t7   : Delete All Resources\n" );
    printf("\t\t8   : Delete Created Group\n" );
    printf("\n\tClient Operations:\n" );
    printf("\t\t9   : Find Introspection\n" );
    printf("\t\t11  : Find specific type of resource\n" );
    printf("\t\t12  : Find All Resources\n" );
    printf("\t\t17  : Send GET Request\n" );
    printf("\t\t20  : Send PUT Request - Complete Update\n");
    printf("\t\t21  : Send POST Request - Partial Update - Default\n");
    printf("\t\t22  : Send POST Request - Partial Update - User Input\n" );
    printf("\t\t25  : Observe Resource - Retrieve Request with Observe\n" );
    printf("\t\t26  : Cancel Observing Resource\n" );
    printf("\t\t28  : Discover Device - Unicast\n");
    printf("\t\t29  : Discover Device - Multicast\n");
    printf("\t\t30  : Discover Platform - Multicast\n");
    printf("\t\t31  : Find Group\n" );
    printf("\t\t33  : Update Group\n" );
    printf("\t\t34  : Update Local Resource Manually\n" );
    printf("\t\t36  : Set Quality of Service - CON(Confirmable)\n" );
    printf("\t\t37  : Set Quality of Service - NON(Non-Confirmable)\n" );
    printf("\t\t40  : Send Ping Message\n");
    printf("\t\t107 : Create Air Conditioner Single Resource\n" );

    if (argc > 4) {
        for (int i = 5; i < argc; i++) {
                choice = atoi(argv[i]);
                selectMenu(choice);
        }
    }
}

void free_buffer(oc_discoverResource_t *cb1)
{
    oc_free_server_endpoints(cb1->endpoint);
    oc_memb_free(&discoverResource_m, cb1);
}

/*To clear allocated endpoint during discovery*/
void  free_all_buffer()
{
    oc_discoverResource_t *cb_free = (oc_discoverResource_t *) oc_list_pop (discoverResource);
    while (cb_free != NULL) {
        free_buffer(cb_free);
        cb_free = (oc_discoverResource_t *) oc_list_pop (discoverResource);
    }
}

/*Perform the selected operation*/
void selectMenu(int choice)
{
    bool isMulticast;
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
            printf("By default resource gets created in Secure mode");
            break;

        case 5:
            createManyLightResources();
            break;

        case 6:
            if(g_isTempResourceCreated == true)
                collectionPointer = createGroupResource();
            else
                printf("\n!!!!!Please create resource first!!!!!\n");
            break;

        case 7:
            deleteAllResources();
            break;

        case 8:
            deleteCreatedGroup();
            break;

        case 9:
            discoverIntrospection();
            break;

        case 11:
            printf("Please type the Resource Type to find, then press Enter: ");
            unsigned int count_restype = 25;
            UserResourceType_input = malloc((size_t)count_restype);
            int numResTypes = scanf("%s", UserResourceType_input);
            if (numResTypes) {
                printf("\nuserResourceType entered is %s\n",UserResourceType_input );
                findResource_UserResType(UserResourceType_input);
            }
            free(UserResourceType_input);
            break;

        case 12:
            findAllResources();
            break;

        case 17:
            sendGetRequest();
            break;
        case 20:
            sendPutRequestUpdate();
            break;
        case 21:
            sendPostRequestUpdate();
            break;

        case 22:
            sendPOSTRequest_partialUpdate_userInput();
            break;

        case 25:
            observe_request();
            break;

        case 26:
            stop_observe();
            break;

        case 28:
            isMulticast = false;
            discoverDevice(isMulticast);
            break;

        case 29:
            isMulticast = true;
            discoverDevice(isMulticast);
            break;
        case 30:
            isMulticast = true;
            discoverPlatform(isMulticast);
            break;

        case 31:
            printf("\nPlease enter the group URI\n");
            /* 'uri_size' specifies the number of bytes allocated to 'char* collection_uri_input'
            using malloc */
            char* collection_uri_input = malloc((size_t)uri_size);
            int scanf_returnValue = scanf("%s", collection_uri_input);
            if(scanf_returnValue == 1) {
               findGroup(collection_uri_input);
            }
            else
               printf("Failed to read URI");
            break;

        case 33:
            printf("Update Group option chosen\n");
            printf("\nEnter the URI of group to be updated\n");
            /* 'uri_size' specifies the number of bytes allocated to 'char* collection_uri_input2'
            using malloc */
            char* collection_uri_input2 = malloc((size_t)uri_size);
            int scanf_returnValue2 = scanf("%s", collection_uri_input2);
            if(scanf_returnValue2 == 1){
               collectionPointer = updateGroup(collection_uri_input2);
            }
            else
               printf("Failed to read URI");
            break;

        case 34:
            printf("'Update local resource maually' chosen\n");
            printf("Please enter the URI of resource to be updated manually\n");
            char* resource_uri_input = malloc((size_t)uri_size);
            int scanf_returnValue3 = scanf("%s", resource_uri_input);
            if(scanf_returnValue3 == 1){
               printf("\nResource URI read is as follows: %s\n", resource_uri_input);
               if(g_isTempResourceCreated == true)
               updateLocalResourceManually(resource_uri_input);
               else
               printf("\n!!!!!Please create resource first!!!!!\n");
            }
            else
               printf("Failed to read URI");
            break;

        case 36:
            g_qos = HIGH_QOS;
            printf("CON type message selected for client\n");
            break;

        case 37:
            g_qos = LOW_QOS;
            printf("NON type message selected for client\n");
            break;
        #ifdef OC_TCP
        case 40:
            ping_count = 0;
            ping_timeout = 1;
            printf("Send PING\n");
            sendPingMessage(ping_timeout);
            break;
        #endif
        case 107:
            createSingleAirConResource();
            break;

        case 0:
            oc_free_string(&name);
            free_all_buffer();
            oc_collection_free(collectionPointer);
            oc_main_shutdown();
            pthread_mutex_destroy(&mutex);
            pthread_mutex_destroy(&app_mutex);
            exit(0);
            break;

        default:
            printf("Invalid Input. Please input your choice again\n");
    }
}

void waitInSecond(int seconds)
{
    sleep(seconds);
}

/*To sleep for few second to get data from network*/
void waitForCallback()
{
    int elapsedSecond = 0;
    while (g_hasCallbackArrived == false)
    {
        waitInSecond(CALLBACK_WAIT_MIN);
        elapsedSecond++;
        if (elapsedSecond > CALLBACK_WAIT_MAX)
        {
            break;
        }
    }
}

/*calling the register_resources  function of device_builder_server.c*/
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

/*Get call back for many light resource function*/
static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
    (void)user_data;
    PRINT("GET_light:\n");
    oc_rep_start_root_object();
    switch (interface) {
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

/* passing the invisible resource uri*/
static void createInvisibleResource()
{
    PRINT("createInvisibleResource called!!\n");

    if (g_isInvisibleResourceCreated == false) {
        oc_resource_t *res = oc_new_resource(NULL, LIGHT_INVISIBLE_URI, 1, 0);
        oc_resource_bind_resource_type(res, "core.light");
        oc_resource_bind_resource_interface(res, OC_IF_RW);
        oc_resource_set_default_interface(res, OC_IF_RW);
        oc_resource_set_discoverable(res, false);
        oc_resource_set_periodic_observable(res, 1);
        oc_resource_set_request_handler(res, OC_GET, get_light, NULL);

        g_addInvisibleResource = oc_add_resource(res);

        if (g_addInvisibleResource == true) {
            PRINT("Invisible Light Resource created successfully\n");
            g_isInvisibleResourceCreated = true;
        }
        else {
            PRINT("Unable to create Invisible Light Resource \n");
        }
    }
    else {
          PRINT("Resource already created!!\n");
    }
}

/*creating the the resource by using url*/
static void createResourceWithUrl()
{
    printf("Creating Resource with complete URL called!!\n");
    if (g_isTempResourceCreated == false) {
        PRINT(" \n First Create resource and then choose this option \n ");
    }
    else {
        printf("Resource with complete URL already created!!\n");
    }
}

static void postRequestClientCb(oc_client_response_t *data) {
    PRINT("postRequestClientCb:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("POST response OK\n");
    else
        PRINT("POST response code %d\n", data->code);
}

/*Sending post command for selected Resource*/
static void sendPostRequestUpdate() 
{
    PRINT("postRequestResource:\n");
    int selection = selectResource();

    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            strncpy(postRequestUri, cb->uri, strlen(cb->uri));
            postRequestUri[strlen(cb->uri)] = '\0';
            postRequestEndpoint = cb->endpoint;
            if (oc_init_post(postRequestUri, postRequestEndpoint, NULL, &postRequestClientCb,
                     g_qos, NULL)) {
                oc_rep_start_root_object();
                oc_rep_set_boolean(root, state, true);
                oc_rep_end_root_object();
                if (oc_do_post())
                    PRINT("Sent POST request\n");
                else
                    PRINT("Could not send POST\n");
            } 
            else
                PRINT("Could not init POST\n");
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}

/*Discovrering the resource registered */
oc_discovery_flags_t discovery(const char *di, const char *uri,
        oc_string_array_t types, oc_interface_mask_t interfaces,
        oc_endpoint_t *endpoint, oc_resource_properties_t bm, void *user_data) {
    (void) di;
    (void) interfaces;
    (void) user_data;
    (void) bm;
    int i;
    
    oc_discoverResource_t *l = (oc_discoverResource_t *) oc_memb_alloc (&discoverResource_m);
    int uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
    PRINT("\n discovery: %s", uri);
    for (i = 0; i < (int) oc_string_array_get_allocated_size(types); i++) {
       char *t = oc_string_array_get_item(types, i);
        if (strlen(t) > 0) {

            light_server = endpoint;
            strncpy(a_light, uri, uri_len);
            a_light[uri_len] = '\0';
            oc_endpoint_t *ep = endpoint;
            strncpy(l->uri, uri, strlen(uri));
            l->uri[strlen(uri)] = '\0';
            l->endpoint = endpoint;
            oc_list_add(discoverResource, l);
            while (ep != NULL) {
                PRINT("\nIP address: \n");
                PRINTIPaddr(*ep);
                PRINT("\nPort:\n");
                PRINTport(*ep);
                PRINT("\n");
                ep = ep->next;
            }
            g_hasCallbackArrived = true;
            PRINT("Resource %s hosted at endpoints:\n", uri);
            return OC_CONTINUE_DISCOVERY;
        }
    }
    return OC_STOP_DISCOVERY;
}

static oc_discovery_flags_t
defined_uri_discovery(const char *anchor, const char *uri, oc_string_array_t types,
          oc_interface_mask_t iface_mask, oc_endpoint_t *endpoint,
          oc_resource_properties_t bm, void *user_data)
{
    (void)anchor;
    (void)user_data;
    (void)iface_mask;
    (void)bm;
    int i;
    int uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
    for (i = 0; i < (int)oc_string_array_get_allocated_size(types); i++) {
        char *t = oc_string_array_get_item(types, i);
        if (strcmp("oic.wk.introspection", t) == 0 || strcmp(UserResourceType_input, t) == 1)  {
            light_server = endpoint;
            strncpy(a_light, uri, uri_len);
            a_light[uri_len] = '\0';
            g_hasCallbackArrived = true;
            PRINT("Resource %s hosted at endpoints:\n", a_light);
            oc_endpoint_t *ep = endpoint;
            while (ep != NULL) {
                PRINTipaddr(*ep);
                PRINT("\n");
                ep = ep->next;
            }
        return OC_STOP_DISCOVERY;
        }
    }
    oc_free_server_endpoints(endpoint);
    return OC_CONTINUE_DISCOVERY;
}

/*calling the discovery function*/
static void findAllResources()
{
    printf("Find All Resources called\n");
    g_hasCallbackArrived = false;
    free_all_buffer();
    discoverDev = oc_do_ip_discovery(NULL, &discovery, NULL);
    waitForCallback();
}

/*calling  discovery function for particular res type*/
static void findResource_UserResType(char *userResourceType)
{
    printf("\nfindResource_UserResType called, user input is %s\n", userResourceType);
    bool discoverResourcetype = false;
    g_hasCallbackArrived = false;
    if (userResourceType!=NULL) {
        PRINT("call discovery!!\n");
        discoverResourcetype = oc_do_ip_discovery (userResourceType, &defined_uri_discovery, NULL );
        waitForCallback();
    }
    if (discoverResourcetype == true) {
        PRINT("userResourceType Discovered\n");
    }
    else {
        PRINT("userResourceType is not Discovered");
    }
}

static void
get_response(oc_client_response_t *data)
{
    PRINT("GET_light:\n");
    if (data->code == OC_STATUS_CHANGED)
       PRINT("GET response: CHANGED\n");
    else if (data->code == OC_STATUS_CREATED)
        PRINT("GET response: CREATED\n");
    else
        PRINT("GET response code %d\n", data->code);
    g_hasCallbackArrived = true;
}

/*select particular resource which discoverd using discovery function*/
static int  selectResource()
{
    int selection = -1;
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int len = oc_list_length(discoverResource);
    PRINT("\n Discovery.... Please select resource no. and press Enter: \n");
    PRINT("\t\t option : 0\t Cancel\n");
    for (int i = 1; i <= len+1; i++) {
        if (cb != NULL) {
            PRINT("\t\t option : %d\t", i);
            PRINT("resource URI:%s \t", cb->uri);
            PRINT("endpoint:");
            oc_endpoint_t *endpoint = cb->endpoint;
            PRINTipaddr(*endpoint);
            PRINT("\n");
            cb = cb->next;
        }
    }
    if (scanf("%d", &selection)) {
        PRINT("Selcted input for choice %d\n", selection);
        if (selection < 0 || selection > len+1) {
            PRINT("Invalid choice and Please choice the option from the menu \n");
            if (scanf("%d", &selection)) {
                PRINT("Select input from choice %d\n", selection);
            }
        }
    }
    return selection;
}

/*sending get request for selected resource*/
static void sendGetRequest()
{
    PRINT("SEND GET request is called\n ");
    int selection = selectResource();
    g_hasCallbackArrived = false;
    char discoverUri[MAX_URI_LENGTH];
    oc_endpoint_t *endpoint = NULL;
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            strncpy(discoverUri, cb->uri, strlen(cb->uri));
            discoverUri[strlen(cb->uri)] = '\0';
            endpoint = cb->endpoint;
            oc_do_get(discoverUri, endpoint, NULL, &get_response, g_qos, NULL);
            waitForCallback();
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}

static void
post_observe(oc_client_response_t *data)
{
  PRINT("post_observe:\n");
  if (data->code == OC_STATUS_CHANGED)
    PRINT("POST response OK\n");
  else
    PRINT("POST response code %d\n", data->code);
}

static void
observe_response(oc_client_response_t *data)
{

    PRINT("OBSERVE_light:\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL) {
        PRINT("key %s, value ", oc_string(rep->name));
        switch (rep->type) {
            case OC_REP_BOOL:
                PRINT("%d\n", rep->value.boolean);
                light_state = rep->value.boolean;
                break;
            default:
                break;
        }
        rep = rep->next;
    }

    if (oc_init_post(observeUri, observeEndpoint, NULL, &post_observe, g_qos, NULL)) {
        oc_rep_start_root_object();
        oc_rep_set_boolean(root, state, !light_state);
        oc_rep_end_root_object();
        if (oc_do_post())
            PRINT("Sent POST request\n");
        else
            PRINT("Could not send POST\n");
    } 
    else
        PRINT("Could not init POST\n");
        g_hasCallbackArrived = true;
}

/*sending the observe request  for selected resource*/
static void
observe_request(void)
{
    int selection = selectResource();
    g_hasCallbackArrived = false;
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            strncpy(observeUri, cb->uri, strlen(cb->uri));
            observeUri[strlen(cb->uri)] = '\0';
            observeEndpoint = cb->endpoint;
            oc_do_observe(observeUri, observeEndpoint, NULL, &observe_response, g_qos, NULL);
            waitForCallback();
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}

/*sending stop observe request for selected resource*/
static void
stop_observe(void)
{
    int selection = selectResource();
    g_hasCallbackArrived = false;
    char stopObserveUri[MAX_URI_LENGTH];
    oc_endpoint_t *stopObserveUriEndpoint = NULL;

    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            strncpy(stopObserveUri, cb->uri, strlen(cb->uri));
            stopObserveUri[strlen(cb->uri)] = '\0';
            stopObserveUriEndpoint = cb->endpoint;
            oc_stop_observe(stopObserveUri, stopObserveUriEndpoint);
            waitForCallback();
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}

static oc_event_callback_retval_t
putStopObserverequest(void *data)
{
    (void)data;
    PRINT("Stopping OBSERVE\n");
    oc_stop_observe(putRequestUri, putRequestEndpoint);
    return OC_EVENT_DONE;
}

static void
putObserveRequestClientCb(oc_client_response_t *data)
{
  
    PRINT("OBSERVE_light:\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL) {
        PRINT("key %s, value ", oc_string(rep->name));
        switch (rep->type) {
            case OC_REP_BOOL:
                PRINT("%d\n", rep->value.boolean);
                state = rep->value.boolean;
                break;
            case OC_REP_INT:
                PRINT("%d\n", rep->value.integer);
                power = rep->value.integer;
                break;
            case OC_REP_STRING:
                PRINT("%s\n", oc_string(rep->value.string));
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
putPostRequestClientCb (oc_client_response_t *data)
{
    PRINT("POST_light:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("POST response: CHANGED\n");
    else if (data->code == OC_STATUS_CREATED)
        PRINT("POST response: CREATED \n");
    else
        PRINT("POST response code %d\n", data->code);

    oc_do_observe(putRequestUri, putRequestEndpoint, NULL, &putObserveRequestClientCb, g_qos, NULL);
    oc_set_delayed_callback(NULL, &putStopObserverequest, 30);
    PRINT("Sent OBSERVE request\n");
}

static void
putRequestClientCb (oc_client_response_t *data)
{
    PRINT("PUT_light:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("PUT response: CHANGED\n");
    else
        PRINT("PUT response code %d\n", data->code);

    if (oc_init_post(putRequestUri, putRequestEndpoint, NULL, &putPostRequestClientCb, g_qos, NULL)) {
        oc_rep_start_root_object();
        oc_rep_set_boolean(root, state, false);
        oc_rep_end_root_object();
        if (oc_do_post())
            PRINT("Sent POST request\n");
        else
            PRINT("Could not send POST request\n");
    } else
          PRINT("Could not init POST request\n");
}

static void
getPutRequestClientCb (oc_client_response_t *data)
{
    PRINT("getPutRequestClientCb:\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL) {
        PRINT("key %s, value ", oc_string(rep->name));
        switch (rep->type) {
            case OC_REP_BOOL:
                PRINT("%d\n", rep->value.boolean);
                state = rep->value.boolean;
                break;
            case OC_REP_INT:
                PRINT("%d\n", rep->value.integer);
                power = rep->value.integer;
                break;
            case OC_REP_STRING:
                PRINT("%s\n", oc_string(rep->value.string));
                if (oc_string_len(name))
                    oc_free_string(&name);
                    oc_new_string(&name, oc_string(rep->value.string),
                    oc_string_len(rep->value.string));
                break;
            default:
                break;
        }
        rep = rep->next;
        g_hasCallbackArrived = true;
    }

    PRINT("get_put:\n");
    if (oc_init_put(putRequestUri, putRequestEndpoint, NULL, &putRequestClientCb, g_qos, NULL)) {
        oc_rep_start_root_object();
        oc_rep_set_boolean(root, state, true);
        oc_rep_end_root_object();

    if (oc_do_put())
        PRINT("Sent PUT request\n");
    else
        PRINT("Could not send PUT request\n");
    } else
        PRINT("Could not init PUT request\n");
}

/*sending put request to create resource*/
static void sendPutRequestUpdate()
{
    PRINT("sendPutRequestUpdate\n");
    int selection = selectResource();
    g_hasCallbackArrived = false;
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            strncpy(putRequestUri, cb->uri, strlen(cb->uri));
            putRequestUri[strlen(cb->uri)] = '\0';
            putRequestEndpoint = cb->endpoint;
            oc_do_get(putRequestUri, putRequestEndpoint, NULL, &getPutRequestClientCb, g_qos, NULL); 
            waitForCallback();
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}

/*getting the device information wich registered in network*/
static void
get_device (oc_client_response_t *data)
{
    PRINT("GET_device:\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL) {
        switch (rep->type) {
            case OC_REP_STRING:
                if ((oc_string_len(rep->name) == 3 &&
                    memcmp(oc_string(rep->name), "pid", 3) == 0) ||
                    (oc_string_len(rep->name) == 3 &&
                    memcmp(oc_string(rep->name), "dmv", 3) == 0) ||
                    (oc_string_len(rep->name) == 3 &&
                    memcmp(oc_string(rep->name), "icv", 3) == 0) ||
                    (oc_string_len(rep->name) == 2 &&
                    memcmp(oc_string(rep->name), "di", 2) == 0)) {
                    PRINT("key: %s, value: %s\n", oc_string(rep->name),
                    oc_string(rep->value.string));
                }
                break;
            case OC_REP_STRING_ARRAY:
                if (oc_string_len(rep->name) == 2 &&
                   (memcmp(oc_string(rep->name), "rt", 2) == 0 ||
                    memcmp(oc_string(rep->name), "if", 2) == 0)) {
                    int i;
                    PRINT("key: %s, value: ", oc_string(rep->name));
                    for (i = 0; i < (int)oc_string_array_get_allocated_size(rep->value.array); i++) {
                        PRINT(" %s ", oc_string_array_get_item(rep->value.array, i));
                    }
                    PRINT("\n");
                }
                break;
            default:
                break;
            }
        rep = rep->next;
    }
    g_hasCallbackArrived = true;
}

/*getting the platform information of device register in network*/
static void
get_platform (oc_client_response_t *data)
{
    PRINT("GET_platform:\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL) {
        switch (rep->type) {
            case OC_REP_STRING:
                if ((oc_string_len(rep->name) == 2 &&
                    memcmp(oc_string(rep->name), "pi", 2) == 0) ||
                    (oc_string_len(rep->name) == 4 &&
                    memcmp(oc_string(rep->name), "mnmn", 4) == 0)) {
                    PRINT("key: %s  value: %s\n", oc_string(rep->name),
                    oc_string(rep->value.string));
                }
                break;
            default:
                break;
        }
    rep = rep->next;
    }
    g_hasCallbackArrived = true;
}

/*sending multicast/unicast request to get device informtion */
static void discoverDevice (bool isMulticast)
{
    g_hasCallbackArrived = false;
    if (!discoverDev) {
        if (isMulticast) {
        oc_make_ipv6_endpoint(mcast, IPV6 | DISCOVERY, 5683, 0xff, 0x02, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
        mcast.addr.ipv6.scope = 2;
        oc_endpoint_t set_up;
        set_up = mcast;

        discoverDev = oc_do_ip_discovery_at_endpoint(NULL, &discovery, &set_up,
                                     NULL);
        waitForCallback();

        }
        else {
            discoverDev = oc_do_ip_discovery(NULL, &discovery, NULL);

            waitForCallback();
        }
    }
    else {
        PRINT("Device is already Discovered\n");
    }
    g_hasCallbackArrived = false;
    PRINT("\n Taking the endPoint from discoverDevMul ----------->\n");
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    while (cb != NULL) {
        if (strncmp(cb->uri ,"/oic/d", strlen(cb->uri)) == 1) {
            break;
        }
        cb = cb->next;
    }
    discoverDeviceInfo = oc_do_get("/oic/d", cb->endpoint, "if=oic.if.baseline", &get_device, g_qos,
                                  NULL);
    waitForCallback();

    if (discoverDeviceInfo == true){

        PRINT("\nDevice discovery done successfully\n");
    }
    else {
        PRINT("Device discovery failed\n");
    }

}

/*Sending unicast or multicast request to get platform information*/
static void discoverPlatform(bool isMulticast)
{
    g_hasCallbackArrived = false;
    if (!discoverDev){
        if (!isMulticast) {
            oc_make_ipv6_endpoint(mcast, IPV6 | DISCOVERY, 5683, 0xff, 0x02, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x58);
            mcast.addr.ipv6.scope = 2;
            set_ep = mcast;
            discoverDev = oc_do_ip_discovery_at_endpoint(NULL, &discovery, &set_ep,
                                                             NULL);
            waitForCallback();
        }
        else {

            discoverDev = oc_do_ip_discovery(NULL, &discovery, NULL);
            waitForCallback();

        }
    }
    else {

        PRINT("Device is already Discovered\n");
    }
    g_hasCallbackArrived = false;
    PRINT("\n Taking the endPoint from discoverDevMul ----------->\n");
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
        while (cb != NULL) {
        if ( strncmp(cb->uri ,"/oic/p", strlen(cb->uri)) == 1) {
            break;
        }
        cb = cb->next;
    }

    discoverPlatformInfo = oc_do_get("/oic/p", cb->endpoint, NULL, &get_platform, g_qos,
                                     NULL);
    waitForCallback();

    if (discoverPlatformInfo == true){

        PRINT("Platform discovery done successfully\n");
    }
    else {
        PRINT("Platform discovery failed\n");
    }
}

/*sending discover introspection request */
void discoverIntrospection()
{
    PRINT("Discovering Introspection using Multicast... ");
    g_hasCallbackArrived = false;
    oc_do_ip_discovery("oic.wk.introspection", &defined_uri_discovery, NULL);
    waitForCallback();
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
    (void)user_data;
    (void)interface;
    PRINT("POST_light:\n");    
    bool state = false;
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
        PRINT("key: %s ", oc_string(rep->name));
        switch (rep->type) {
           case OC_REP_BOOL:
               state = rep->value.boolean;
               PRINT("value: %d\n", state);
               break;
           default:
               oc_send_response(request, OC_STATUS_BAD_REQUEST);
               return;
               break;
        }
        rep = rep->next;
    }
    light_state = state;
    oc_send_response(request, OC_STATUS_CHANGED);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
    post_light(request, interface, user_data);
}

/*
input is baseUri,lightCount added in the baseUri
*/
static void createManyLightResources()
{
    PRINT("createManyLightResources called!!\n");

    bool add_LightResource;
    char baseUri[20] = "/light/";
    int  lightCount = LIGHT_COUNT;
    char uri[20] = "";

    if (g_isManyLightCreated == false) {

        for (int i = 0; i < MAX_LIGHT_RESOURCE_COUNT; i++, lightCount++) {
            sprintf(uri,"/light/%d", lightCount);
            PRINT("%s\n",baseUri);
            PRINT("%s\n",uri);

            oc_resource_t *res = oc_new_resource(RESOURCE_NAME, uri, NUM_RESOURCES_TYPES, NUM_DEVICE);
            oc_resource_bind_resource_type(res, RESOURCE_LIGHT_TYPE);
            oc_resource_bind_resource_interface(res, OC_IF_BASELINE);
            oc_resource_set_default_interface(res, OC_IF_RW);
            oc_resource_set_discoverable(res, true);
            oc_resource_set_periodic_observable(res, 1);
            oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
            oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
            oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
            add_LightResource = oc_add_resource(res);

            if (add_LightResource == true) {

                PRINT("Light Resource created successfully with uri:\n");
                g_isManyLightCreated = true;
            }
            else {
                PRINT("Unable to create Light resource with uri:\n");
            }
        }
    }
    else {
      PRINT("Many Light Resources already created!!\n");
    }
}

/* createGroupResource() function creates a collection; also creates links to resources that are to be added
   to the collection and adds them to the collection; resource pointers are obtained from resource URIs */ 
static oc_collection_t* createGroupResource()
{

    oc_resource_t *resource_one = oc_ri_get_app_resource_by_uri(RESOURCE_1_URI, strlen(RESOURCE_1_URI),0);
    oc_resource_t *resource_two = oc_ri_get_app_resource_by_uri(RESOURCE_2_URI, strlen(RESOURCE_2_URI),0);

    const char* collection_name = "Example Collection";
    const char* collection_uri = "/collectionExamplePath";

    oc_resource_t *new_collection = oc_new_collection(collection_name, collection_uri, 2,2,2, 0);

    #if defined(OC_COLLECTIONS)

        if(new_collection != NULL)
            PRINT("New collection created with the following name: %s\n",new_collection->name.ptr);

        oc_resource_bind_resource_type(new_collection, "oic.wk.col");
        oc_resource_set_discoverable(new_collection, true);
        oc_collection_add_supported_rt(new_collection, "oic.r.humidity");
        oc_collection_add_supported_rt(new_collection, "oic.r.switch.binary");
        oc_collection_add_mandatory_rt(new_collection, "oic.r.humidity");
        oc_collection_add_mandatory_rt(new_collection, "oic.r.switch.binary");

        oc_link_t *link_one = oc_new_link(resource_one);
        oc_collection_add_link(new_collection, link_one);

        oc_link_t *link_two = oc_new_link(resource_two);
        oc_collection_add_link(new_collection, link_two);

        oc_add_collection(new_collection);

    #endif /* OC_COLLECTIONS */

    return (oc_collection_t*)new_collection;

}

/*delete All  created resource*/  
static void deleteAllResources()
{
    PRINT("deteAllResources called!!\n");

    oc_resource_t *res = oc_ri_get_app_resources();

    while(res)
    {
        oc_ri_delete_resource(res);
        res = oc_ri_get_app_resources();
    }

    if (res == NULL) {
        PRINT("All Resources Deleted\n");
    }

    g_isManyLightCreated = false;
    g_addInvisibleResource = false;
    g_isTempResourceCreated = false;
    g_createResourceWithURL = false;
    g_isAirConDeviceCreated = false;
    free_all_buffer();
    oc_free_string(&name);
}

static void deleteCreatedGroup()
{

    oc_collection_free(collectionPointer);
    PRINT("\nCollection deleted\n");
}

static void
post_response(oc_client_response_t *data)
{
    PRINT("POST_light_response:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("POST response: CHANGED\n");
    else if (data->code == OC_STATUS_CREATED)
        PRINT("POST response: CREATED\n");
    else
        PRINT("POST response code %d\n", data->code);
}

/*Following function takes input of 'attribute key' and 'attribute value' from user
and sends a POST request */
static void sendPOSTRequest_partialUpdate_userInput()
{
    char key[10];
    long int choice = 0;
    bool wrongKeyEnter = false;
    bool validChoice = false;
    double valueDouble = 0.0;
    int valueInt;
    bool valueBool;
    int selection = selectResource();
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            strncpy(postRequestUri, cb->uri, strlen(cb->uri));
            postRequestUri[strlen(cb->uri)] = '\0';
            postRequestEndpoint = cb->endpoint;
            if (oc_init_post(postRequestUri, postRequestEndpoint, "if=oic.if.baseline", &post_response,
                     HIGH_QOS, NULL)) {
                
                PRINT("Please Enter the Key Value\n");

                do {
                    if (scanf("%s", key)){
                        int key_length;
                        key_length = strlen(key);
                        for (int i = 0; i<key_length; i++) {
                            if (isalpha(key[i])) {
    
                                wrongKeyEnter = true;   
                            }
                            else {
                                PRINT("Please Enter the key again\n");
                                break;
                            }
                        }
                    }

                } while (!wrongKeyEnter);

                PRINT("%s\n", key);
                do {
                    PRINT("Please select attribute data type and press Enter: \n");
                    PRINT("\t\t 1. Integer\n");
                    PRINT("\t\t 2. Double Point - Double Precision\n");
                    PRINT("\t\t 3. Boolean\n");
                    PRINT("\t\t 4. String\n");
                    int input = scanf("%d", &choice);
                    PRINT("input : %d\n", input);

                    if (choice > 0 && choice < 5) {
                        validChoice = true;
                    }
                    else
                        {
                            validChoice = false;
                            PRINT("Invalid input for attribute data type. Please select between 1 and 6 \n");
                    }

                } while (!validChoice);
                PRINT("Please input Attribute Value: ");
                switch (choice)
                    {
                        case 1:
                            if (scanf("%d", &valueInt)) {
                                PRINT("%d\n", valueInt);
                            }
                            break;
                        case 2:
                            if(scanf("%lf", &valueDouble)) {
                                PRINT("%lf\n", valueDouble); 
                                
                            }
                            break;
                        case 3:
                            PRINT("\nPlease provide boolean value(O for False, 1 for True) : ");
                            if (scanf("%d", &valueBool)) {
                                PRINT("%d\n", valueBool);
                                break;
                            }
                    }
                oc_rep_start_root_object();
                switch (choice) {
                    case 1:
                        oc_rep_set_int(root, key, valueInt);
                        break;
                    case 2:
                        oc_rep_set_int(root, key, valueDouble);
                        break;
                    case 3:
                        oc_rep_set_boolean(root, key, valueBool);
                        break;
                    default :
                        break;
                }
                oc_rep_end_root_object();
                if (oc_do_post())
                    PRINT("Sent POST request\n");
                else
                    PRINT("Could not send POST\n");
            } 
            else
                PRINT("Could not init POST\n");
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}

/* Following function takes URI of the collection to be updated, as input. It allows 1. updation of collection 
properties(namely collection type, collection interface and collection path), 2. adding of a resource to the 
collection, 3. removal of a resource from a collection and 4. updation of the properties(namely type, interface 
and path) of a resource in the collection. */

static oc_collection_t* updateGroup(char* uri_input)
{
    oc_collection_t* tempCollection = oc_get_collection_by_uri(uri_input, strlen(uri_input), 0);
    int optionNumber;

    if(tempCollection == NULL){
        PRINT("!!Collection not found!! Collection URI entered may be incorrect OR collection is not created OR both\n");
    }
    else {

        PRINT("\nResources part of '%s' are as follows:\n", tempCollection->name.ptr);

        oc_link_t* resource_links = oc_collection_get_links((oc_resource_t*)tempCollection);
        int count_resource=1;

        while (resource_links != NULL){
            PRINT("Resource %d - URI: '%s'\n", count_resource, resource_links->resource->uri.ptr);
            count_resource++;
            resource_links = resource_links->next;
        }

        PRINT("..................\n");
        PRINT("Update Group Menu:\n");
        PRINT("..................\n");
        PRINT("Choose from below options by entering the option number\n1. Update collection properties\n"
            "2. Add a resource to group\n3. Remove a resource from group\n4. Update a resource's properties\n");

        int scanf_return_value = scanf("%d",&optionNumber);
        if (scanf_return_value)
            PRINT("Option chosen:%d\n",optionNumber);

        switch(optionNumber) {

            case 1:   ;
                int collectionPropertyOptionNumber = -1;

                unsigned int count_case1 = 25;
                char* resource_property_case1 = malloc((size_t)count_case1);

                int collectionInterfaceIntegerValue = 1;

                while (collectionPropertyOptionNumber != 0){
                    case1_label:
                        PRINT("\t\t..................\n");
                        PRINT("\t\tUpdate collection properties:\n");
                        PRINT("\t\t..................\n");
                        PRINT("\t\tChoose from below options by entering the option number\n\t\t1. Update collection type\n"
                             "\t\t2. Update collection interface\n\t\t3. Update collection path\n\t\t0. Exit Update collection Properties\n");

                        int scanf_returnValue_case1 = scanf("%d",&collectionPropertyOptionNumber);
                        if (scanf_returnValue_case1) {
                            if (collectionPropertyOptionNumber == 0) {
                                PRINT("'Exit Update Collection Properties' chosen\n");
                                break;
                            }
                            else if(collectionPropertyOptionNumber == 1) {
                                PRINT("Option 1 chosen.\n");
                                PRINT("Presently, collection type is '%s'\n",tempCollection->types.ptr);
                                PRINT("Please enter new 'collection type'\n");
                                int scanf_returnValue_case1_2 = scanf("%s", resource_property_case1);
                                if (scanf_returnValue_case1_2)
                                    PRINT("\nCollection property read is as follows: %s\n", resource_property_case1);
                                }
                            else if(collectionPropertyOptionNumber == 2) {
                                PRINT("\nOption 2 chosen.\n");
                                PRINT("Presently, interface value is %d\n\n",tempCollection->interfaces);
                                PRINT("Please enter a suitable integer number using the guide below\nto have"
                                   "the required interfaces for the collection\n\n");
                                PRINT("2: corresponds to Baseline(OC_IF_BASELINE) interface\n"
                                   "4: corresponds to Link Lists(OC_IF_LL) interface\n"
                                   "8: corresponds to Batch(OC_IF_B) interface\n"
                                   "16: corresponds to Read-only(OC_IF_R) interface\n"
                                   "32: corresponds to Read-Write(OC_IF_RW) interface\n"
                                   "64: corresponds to Actuator(OC_IF_A) interface\n"
                                   "128: corresponds to Sensor(OC_IF_S) interface\n");
                                PRINT("66(2+64): corresponds to interfaces of Baseline(2) and Actuator(64)\n");
                                PRINT("18(2+16): corresponds to interfaces of Baseline(2) and Read-only(16)\netc.,\n");
                                int scanf_returnValue_case1_3 = scanf("%d",&collectionInterfaceIntegerValue);
                                if (scanf_returnValue_case1_3)
                                    PRINT("Collection Interface Integer Value entered: %d\n", collectionInterfaceIntegerValue);
                            }
                            else if (collectionPropertyOptionNumber == 3) {
                                PRINT("Option 3 chosen.\n");
                                PRINT("Presently, collection URI is '%s'\n",tempCollection->uri.ptr);
                                PRINT("Please enter 'new collection URI'\n");
                                int scanf_returnValue_case1_4 = scanf("%s", resource_property_case1);
                                if (scanf_returnValue_case1_4)
                                    PRINT("\nNew URI read is as follows: %s\n", resource_property_case1);
                                }
                            else {
                                PRINT("!!!!!!!!Invalid option chosen!!!!!!!!\n");
                                goto case1_label;
                            }
                }
                else
                    PRINT("Read from scanf was unsuccessful\n");

                switch(collectionPropertyOptionNumber)
                {
                    case 1:
                        PRINT("\nResource type of collection '%s' before updation: %s\n", tempCollection->name.ptr,
                        tempCollection->types.ptr);
                        tempCollection->types.ptr = resource_property_case1;
                        PRINT("Resource type of collection '%s' after updation: %s\n", tempCollection->name.ptr,
                        tempCollection->types.ptr);
                    break;

                    case 2:
                        PRINT("\nInterface of collection '%s' before updation: %d\n", tempCollection->name.ptr,
                             tempCollection->interfaces);

                        tempCollection->interfaces = collectionInterfaceIntegerValue;

                        PRINT("Interface of collection '%s' after updation: %d\n", tempCollection->name.ptr,
                        tempCollection->interfaces);
                    break;

                    case 3:
                        /* Still working on updating collection path */
                        PRINT("\nURI of collection '%s' before updation: %s\n", tempCollection->name.ptr,
                        tempCollection->uri.ptr);
                        tempCollection->uri.ptr = resource_property_case1;
                        PRINT("URI of collection '%s' after updation: %s\n", tempCollection->name.ptr,
                        tempCollection->uri.ptr);
                    break;

                    default: PRINT("Entered 'default case' of switch statement in 'case 4' of outer switch statement\n");
                    break;
                }
            }
        break;

        case 2: PRINT("\nEnter the URI of the resource to be added to the group '%s'\n", tempCollection->name.ptr);
            unsigned int count_case2 = 25;
            char* resource_uri_case2 = malloc((size_t)count_case2);
            int scanf_returnValue_case2 = scanf("%s", resource_uri_case2);

            if(scanf_returnValue_case2)
                PRINT("");

            oc_resource_t *resource_case2 = oc_ri_get_app_resource_by_uri(resource_uri_case2, strlen(resource_uri_case2),0);

            if(resource_case2 != NULL)
            {
                oc_link_t *link_one = oc_new_link(resource_case2);
                oc_collection_add_link((oc_resource_t*)tempCollection, link_one);
                PRINT("\nLink of resource with URI:'%s' has been added to the group '%s'\n", resource_uri_case2, tempCollection->name.ptr);
            }
            else{
                PRINT("\n!!!!!Resource with above entered URI is not found!!!!!\n");
            }

            PRINT("\nFollowing resources are part of '%s' after addition of resource\n", tempCollection->name.ptr);

            oc_link_t* resource_links_case2 = oc_collection_get_links((oc_resource_t*)tempCollection);
            int count_case2_1=1;

            while(resource_links_case2 != NULL)
            {
                PRINT("Resource %d - URI: '%s'\n", count_case2_1, resource_links_case2->resource->uri.ptr);
                count_case2_1++;
                resource_links_case2 = resource_links_case2->next;
            }

            break;

        case 3: PRINT("\nEnter the URI of the resource to be removed from the group\n");
            unsigned int count_case3 = 25;
            char* resource_uri_case3 = malloc((size_t)count_case3);
            int scanf_returnValue_case3 = scanf("%s", resource_uri_case3);
            if(scanf_returnValue_case3)
                PRINT("\nResource URI read is as follows: %s\n", resource_uri_case3);

            oc_resource_t *resource_case3 = oc_ri_get_app_resource_by_uri(resource_uri_case3, strlen(resource_uri_case3),0);
            if(resource_case3 == NULL)
            PRINT("\n!!!!!Resource with above entered URI is not found!!!!!\n");
            else{
            oc_link_t* resource_links_case3 = oc_collection_get_links((oc_resource_t*)tempCollection);

            while(resource_links_case3 != NULL)
            {
                if(!strcmp(resource_links_case3->resource->uri.ptr, resource_uri_case3))
                {
                    PRINT("\n........Resource(resource link) removed from the group........\n");
                    PRINT("\nLink of resource with uri: '%s' will be removed from '%s'\n", resource_links_case3->resource->uri.ptr,
                        tempCollection->name.ptr);
                    oc_collection_remove_link((oc_resource_t*)tempCollection, resource_links_case3);
                    PRINT("\n........Resource(resource link) removed from the group........\n");
                    PRINT("\n........Resource(resource link) removed from the group........\n");
                    break;
                }
                resource_links_case3 = resource_links_case3->next;
            }
            }
            break;

        case 4: PRINT("Enter the URI of resource whose properties are to be updated\n");
            int resourcePropertyOptionNumber = -1;

            unsigned int count_case4 = 25;
            char* resource_uri_case4 = malloc((size_t)count_case4);
            int scanf_returnValue_case4 = scanf("%s", resource_uri_case4);
            if(scanf_returnValue_case4)
            PRINT("\nResource URI read is as follows: %s\n", resource_uri_case4);

            oc_resource_t *resource_case4 = oc_ri_get_app_resource_by_uri(resource_uri_case4, strlen(resource_uri_case4),0);

            if(resource_case4 == NULL){
                PRINT("!!!!!Resource not found!!!!!\nPlease choose 'Option 33', 'sub-option 4' again and enter approriate URI\n");
            }
            else{

            unsigned int count_case4_2 = 25;
            char* resource_property_case4 = malloc((size_t)count_case4_2);

            int resourceInterfaceIntegerValue = 1;

            while(resourcePropertyOptionNumber != 0)
            {
            case4_label:
                PRINT("\t\t..................\n");
                PRINT("\t\tUpdate resource properties:\n");
                PRINT("\t\t..................\n");
                PRINT("\t\tChoose from below options by entering the option number\n\t\t1. Update resource type\n"
                "\t\t2. Update resource interface\n\t\t3. Update resource path\n\t\t0. Exit Update Resource Properties\n");

                int scanf_returnValue_case4_2 = scanf("%d",&resourcePropertyOptionNumber);
                if(scanf_returnValue_case4_2)
                {
                    if(resourcePropertyOptionNumber == 0)
                    {
                        printf("'Exit Update Resource Properties' chosen\n");
                        break;
                    }
                    else if(resourcePropertyOptionNumber == 1)
                    {
                        PRINT("Option 1 chosen.\n");
                        PRINT("Presently, resource type is '%s'\n",resource_case4->types.ptr);
                        PRINT("Please enter new 'resource type'\n");
                        int scanf_returnValue_case4_3 = scanf("%s", resource_property_case4);
                        if(scanf_returnValue_case4_3)
                        PRINT("\nResource property read is as follows: %s\n", resource_property_case4);
                    }
                    else if(resourcePropertyOptionNumber == 2)
                    {
                        PRINT("\nOption 2 chosen.\n");
                        PRINT("Presently, interface value is %d\n\n",resource_case4->interfaces);
                        PRINT("Please enter a suitable integer number using the guide below\nto have the required interfaces for the resource\n\n");
                        PRINT("2: corresponds to Baseline(OC_IF_BASELINE) interface\n"
                            "4: corresponds to Link Lists(OC_IF_LL) interface\n"
                            "8: corresponds to Batch(OC_IF_B) interface\n"
                            "16: corresponds to Read-only(OC_IF_R) interface\n"
                            "32: corresponds to Read-Write(OC_IF_RW) interface\n"
                            "64: corresponds to Actuator(OC_IF_A) interface\n"
                            "128: corresponds to Sensor(OC_IF_S) interface\n");
                        PRINT("66(2+64): corresponds to interfaces of Baseline(2) and Actuator(64)\n");
                        PRINT("18(2+16): corresponds to interfaces of Baseline(2) and Read-only(16)\netc.,\n");
                        int scanf_returnValue_case4_4 = scanf("%d",&resourceInterfaceIntegerValue);
                        if (scanf_returnValue_case4_4)
                            printf("Resource Interface Integer Value entered: %d\n", resourceInterfaceIntegerValue);

                    }
                    else if (resourcePropertyOptionNumber == 3)
                    {
                        PRINT("Option 3 chosen.\n");
                        PRINT("Presently, resource uri is '%s'\n",resource_case4->uri.ptr);
                        PRINT("Please enter new 'resource URI'\n");
                        int scanf_returnValue_case4_5 = scanf("%s", resource_property_case4);
                        if(scanf_returnValue_case4_5)
                        PRINT("\nNew URI read is as follows: %s\n", resource_property_case4);
                    }
                    else
                    {
                        PRINT("!!!!!!!!Invalid option chosen!!!!!!!!\n");
                        goto case4_label;
                    }
                }
                else
                    PRINT("Read from scanf was unsuccessful\n");

                switch(resourcePropertyOptionNumber)
                {
                    case 1:
                        PRINT("\nResource type of resource '%s' before updation: %s\n",resource_case4->name.ptr,resource_case4->types.ptr);
                        resource_case4->types.ptr = resource_property_case4;
                        PRINT("Resource type of resource '%s' after updation: %s\n", resource_case4->name.ptr,
                        resource_case4->types.ptr);
                        break;

                    case 2:
                        PRINT("\nResource interface of resource '%s' before updation: %d\n", resource_case4->name.ptr,
                        resource_case4->interfaces);

                        resource_case4->interfaces = resourceInterfaceIntegerValue;

                        PRINT("Resource interface of resource '%s' after updation: %d\n", resource_case4->name.ptr,
                        resource_case4->interfaces);
                        break;

                    case 3:
                        PRINT("\nResource URI of resource '%s' before updation: %s\n", resource_case4->name.ptr,
                        resource_case4->uri.ptr);
                        resource_case4->uri.ptr = resource_property_case4;
                        PRINT("Resource URI of resource '%s' after updation: %s\n", resource_case4->name.ptr,
                        resource_case4->uri.ptr);
                        break;

                    default: PRINT("Entered 'default case' of switch statement in 'case 4' of outer switch statement\n");
                        break;
                }
            }
            }
            break;

        default: PRINT("!!!!Invalid Option Entered!!!!\n");
            break;
    }

    }

    return tempCollection;
}

/* Following function takes a resource URI as input and allows for the updation of the resource's 
properties(namely type, interface and path) */
static void updateLocalResourceManually(char* uri_input)
{
    oc_resource_t *resource = oc_ri_get_app_resource_by_uri(uri_input, strlen(uri_input),0);
    if(resource == NULL){
        PRINT("\n!!!!!Resource not found!!!!!\nPlease choose 'Option 34' again and enter approriate URI\n");
        return;
    }
    else{
    unsigned int count_case4_2 = 25;
    char* resource_property_case4 = malloc((size_t)count_case4_2);

    int resourcePropertyOptionNumber = -1;
    int resourceInterfaceIntegerValue = 1;
            while(resourcePropertyOptionNumber != 0)
            {
            case4_label:
                PRINT("\t\t..................\n");
                PRINT("\t\tUpdate resource properties:\n");
                PRINT("\t\t..................\n");
                PRINT("\t\tChoose from below options by entering the option number\n\t\t1. Update resource type\n"
                       "\t\t2. Update resource interface\n\t\t3. Update resource path\n\t\t0. Exit Update Resource Properties\n");

                int scanf_returnValue_case4_2 = scanf("%d",&resourcePropertyOptionNumber);
                if(scanf_returnValue_case4_2)
                {
                    if(resourcePropertyOptionNumber == 0)
                    {
                        PRINT("'Exit Update Resource Properties' chosen\n");
                        break;
                    }
                    else if(resourcePropertyOptionNumber == 1)
                    {
                        PRINT("Option 1 chosen.\n");
                        PRINT("Presently, resource type is '%s'\n",resource->types.ptr);
                        PRINT("Please enter new 'resource type'\n");
                        int scanf_returnValue_case4_3 = scanf("%s", resource_property_case4);
                        if(scanf_returnValue_case4_3)
                        PRINT("\nResource property read is as follows: %s\n", resource_property_case4);
                    }
                    else if(resourcePropertyOptionNumber == 2)
                    {
                        PRINT("\nOption 2 chosen.\n");
                        PRINT("Presently, interface value is %d\n\n",resource->interfaces);
                        PRINT("Please enter a suitable integer number using the guide below\nto have the required interfaces for the resource\n\n");
                        PRINT("2: corresponds to Baseline(OC_IF_BASELINE) interface\n"
                            "4: corresponds to Link Lists(OC_IF_LL) interface\n"
                            "8: corresponds to Batch(OC_IF_B) interface\n"
                            "16: corresponds to Read-only(OC_IF_R) interface\n"
                            "32: corresponds to Read-Write(OC_IF_RW) interface\n"
                            "64: corresponds to Actuator(OC_IF_A) interface\n"
                            "128: corresponds to Sensor(OC_IF_S) interface\n");
                        PRINT("66(2+64): corresponds to interfaces of Baseline(2) and Actuator(64)\n");
                        PRINT("18(2+16): corresponds to interfaces of Baseline(2) and Read-only(16)\netc.,\n");
                        int scanf_returnValue_case4_4 = scanf("%d",&resourceInterfaceIntegerValue);
                        if (scanf_returnValue_case4_4)
                            PRINT("Resource Interface Integer Value entered: %d\n", resourceInterfaceIntegerValue);

                    }
                    else if (resourcePropertyOptionNumber == 3)
                    {
                        PRINT("Option 3 chosen.\n");
                        PRINT("Presently, resource uri is '%s'\n",resource->uri.ptr);
                        PRINT("Please enter new 'resource URI'\n");
                        int scanf_returnValue_case4_5 = scanf("%s", resource_property_case4);
                        if(scanf_returnValue_case4_5)
                        PRINT("\nNew URI read is as follows: %s\n", resource_property_case4);
                    }
                    else
                    {
                        PRINT("!!!!!!!!Invalid option chosen!!!!!!!!\n");
                        goto case4_label;
                    }
                }
                else
                    PRINT("Read from scanf was unsuccessful\n");

                switch(resourcePropertyOptionNumber)
                {
                    case 1: PRINT("\nResource type before updation: %s\n",resource->types.ptr);
                        resource->types.ptr = resource_property_case4;
                        PRINT("Resource type after updation: %s\n",resource->types.ptr);
                        break;

                    case 2:
                        PRINT("\nResource interface before updation: %d\n",resource->interfaces);
                        resource->interfaces = resourceInterfaceIntegerValue;
                        PRINT("Resource interface after updation: %d\n",resource->interfaces);
                        break;

                    case 3:PRINT("\nResource URI before updation: %s\n",resource->uri.ptr);
                        resource->uri.ptr = resource_property_case4;
                        PRINT("Resource URI after updation: %s\n",resource->uri.ptr);
                        break;

                    default: PRINT("Entered 'default case' of switch statement\n");
                        break;
                }
            }
    }
}

/* Following function takes a collection URI as input and obtains the collection's pointer and prints 
the collection name */
static void findGroup(char* uri_input)
{

    PRINT("\nFind Group option chosen\n");

    PRINT("\nparameter passed: %s\n",uri_input);

    oc_collection_t* tempCollection_findGroup = oc_get_collection_by_uri(uri_input, strlen(uri_input), 0);

    if (tempCollection_findGroup == NULL)
        PRINT("\nGroup does not exist\n");
    else
        PRINT("\nGroup found. Collection name is %s\n\n", tempCollection_findGroup->name.ptr);

}

void
get_binaryswitchcb(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
    (void)user_data;  // not used

    PRINT("get_binaryswitch: interface %d\n", interfaces);
    oc_rep_start_root_object();
    switch (interfaces) {
    case OC_IF_BASELINE:
    /* fall through */
    case OC_IF_A:
        PRINT("Adding Baseline info\n" );
        oc_process_baseline_interface(request->resource);
        oc_rep_set_boolean(root, value, g_binaryswitch_valuecb);
        PRINT("   %s : %d\n", g_binaryswitch_RESOURCE_PROPERTY_NAME_value,  g_binaryswitch_valuecb );
        break;
        default:
        break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
}

/*binary switch call back */ 
void
post_binaryswitchcb(oc_request_t *request, oc_interface_mask_t interfaces, void *user_data)
{
    (void)interfaces;
    (void)user_data;
    bool error_state = false;
    PRINT("post_binaryswitch:\n");
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL) {
        PRINT("key: (check) %s ", oc_string(rep->name));
        if (strcmp ( oc_string(rep->name), g_binaryswitch_RESOURCE_PROPERTY_NAME_value) == 0) {
    /*
    value exists in payload
    */
            if (rep->type != OC_REP_BOOL)
                {
                    error_state = true;
                    PRINT ("   property 'value' is not of type bool %d \n", rep->type);
            }
        }
                rep = rep->next;
    }
           if (error_state == false) {
              oc_rep_t *rep = request->request_payload;
              while (rep != NULL) {
                    PRINT("key: (assign) %s ", oc_string(rep->name));
                   /* no error: assign the variables */
                    if (strcmp ( oc_string(rep->name), g_binaryswitch_RESOURCE_PROPERTY_NAME_value)== 0){
                      /* assign value */
                       g_binaryswitch_valuecb = rep->value.boolean;
                    }
                       rep = rep->next;
            }
                      /* set the response */
                      oc_rep_start_root_object();
                      oc_rep_set_boolean(root, value, g_binaryswitch_valuecb);
                      oc_rep_end_root_object();
                      oc_send_response(request, OC_STATUS_CHANGED);
            }
          else {
              /* TODO: add error response, if any */
              oc_send_response(request, OC_STATUS_NOT_MODIFIED);
          }
}

int  app_init1()
 {

    int  ret = oc_init_platform(ENGLISH_NAME_VALUE, NULL, NULL);
    ret |= oc_add_device("oic/d", "oic.d.airconditioner", "AirConditioner",
                             OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION,
                             NULL, NULL);
    return ret;
}


/*using the  uri creating the air conditioner resource*/
static void createSingleAirConResource()
{
    PRINT("Creating AirCon Device Resources!!\n");

    if (g_isAirConDeviceCreated == false) {

        int init;
        static const oc_handler_t handler = {.init = app_init1,
                                       .signal_event_loop = signal_event_loop,
                                       };

        init = oc_main_init(&handler);

        if (init < 0)
            PRINT("Not Able to Intialize the mainHandler");


        oc_resource_t *res = oc_new_resource("AC-binaryswitch", RESOURCE_AIR_URI, RESOURCE_INTERFACE, DEVICE_COUNT);
        oc_resource_bind_resource_type(res,SWITCH_RESOURCE_TYPE);
        for ( int a = 0; a < RESOURCE_INTERFACE; a++ )
            {
                oc_resource_bind_resource_interface(res, convert_if_string(g_binaryswitch_AIRCON_RESOURCE_INTERFACE[a]));
            }
        oc_resource_set_discoverable(res, true);
        oc_resource_set_periodic_observable(res, OBSERVE_PERIODIC);
        oc_resource_set_request_handler(res, OC_GET, get_binaryswitchcb, NULL);
        oc_resource_set_request_handler(res, OC_POST, post_binaryswitchcb, NULL);
        bool add_res = oc_add_resource(res);

        if (add_res == true) {
           PRINT("AirCon Binary Switch Resource created successfully\n");
           g_isAirConDeviceCreated = true;
        }
        else {
            PRINT("Unable to create AirCon Binary Switch resource\n");
        }
    }
    else
    {
        PRINT("Already Smart Home Air Conditioner Device Resource is created!!\n");
    }
}


#ifdef OC_TCP
static void
pong_received_handler(oc_client_response_t *data)
{
  if (data->code == OC_PING_TIMEOUT) {
    PRINT("PING timeout!\n");
    ping_count++;
    if (ping_count > PING_RETRY_COUNT) {
      PRINT("retry over. close connection.\n");
      oc_connectivity_end_session(data->endpoint);
    } else {
      ping_timeout <<= 1;
      PRINT("PING send again.[retry: %d, time: %u]\n", ping_count,
             ping_timeout);
      sendPingMessage(ping_timeout);
    }
  } else {
    PRINT("PONG received:\n");
    PRINTipaddr(*data->endpoint);
    PRINT("\n");
    ping_count = 0;
  }
}
 /* OC_TCP */

static void
sendPingMessage(uint16_t timeout_seconds)
{
    int selection = selectResource();    
    oc_endpoint_t *endpoint = NULL;
    oc_discoverResource_t *cb = (oc_discoverResource_t *) oc_list_head(discoverResource);
    int i = 1;
    while (cb != NULL) {
        if (selection == i) {
            endpoint = cb->endpoint;
            #ifdef OC_TCP
                if (endpoint->flags & TCP) {
                    if (!oc_send_ping(0, endpoint, timeout_seconds, pong_received_handler,NULL)) {
                        PRINT("oc_send_ping failed\n");
                    }
                } 
                else
                #endif /* !OC_TCP */
                {
                    PRINT("PING message is not supported\n");
                }
        }
        else if (selection == CANCEL_SELECTION) {
            break;
        }
        i++;
        cb = cb->next;
    }
}
#endif

/*running the main poll inside the thread function*/
static void *
process_func(void *data)
{
    (void)data;
    oc_clock_time_t next_event;

    while (quit != 1) {
        pthread_mutex_lock(&app_mutex);
        next_event = oc_main_poll();
        pthread_mutex_unlock(&app_mutex);
        pthread_mutex_lock(&mutex);
        if (next_event == 0) {
        /* printf("\nwaiting at process_func \n"); */
            fflush(stdout);
            pthread_cond_wait(&cv, &mutex);
        }
        else {
            ts.tv_sec = (next_event / OC_CLOCK_SECOND);
            ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
            pthread_cond_timedwait(&cv, &mutex, &ts);
        }
        pthread_mutex_unlock(&mutex);
    }
    pthread_exit(0);
}

int main( int argc, char* argv[])
{
    struct sigaction sa;

    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handle_signal;
    sigaction(SIGINT, &sa, NULL);
    oc_set_con_res_announced(false);
    oc_set_mtu_size(4096);
    oc_set_max_app_data_size(16384);

    int init;
    static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop
                                      // .register_resources = register_resources
    #ifdef OC_CLIENT
                                       ,
                                       .requests_entry = 0
    #endif
                                       };


    #ifdef OC_SECURITY
        oc_storage_config("./CertificationApp_creds/");
    #endif /* OC_SECURITY */

    if (pthread_mutex_init(&mutex, NULL) < 0) {
        printf("pthread_mutex_init failed!\n");
        return -1;
    }

    if (pthread_mutex_init(&app_mutex, NULL) < 0) {
        PRINT("pthread_mutex_init failed!\n");
        pthread_mutex_destroy(&mutex);
        return -1;
    }

    init = oc_main_init(&handler);
    if (argc > 1) {
        int optionSelected = atoi(argv[1]);
           if (optionSelected == 1) {
               PRINT("Using CON Server\n");
               g_qos = HIGH_QOS;
            }
            else if (optionSelected == 0) {
                PRINT("Using NON Server\n");
            }
        else {
            PRINT("Invalid input argument. Using default QoS: NON\n");
        }
    }
    else {
        PRINT("No QoS supplied. Using default: NON\n");

    }
    if (argc > 2) {
        int optionSelected = atoi(argv[1]);
           if (optionSelected == 2) {
               printf("option not implemented\n");
           }
    }

    if (argc > 3) {
        int optionSelected = atoi(argv[3]);
        g_securityType = optionSelected % 10;

        if (g_securityType == 3) {
            PRINT("Supported Security Mode: manufacturing certificate\n");
            int credid = oc_pki_add_mfg_cert(0, my_crt, sizeof(my_crt), my_key, sizeof(my_key));

            oc_pki_add_mfg_intermediate_cert(0, credid, int_ca, sizeof(int_ca));

            oc_pki_add_mfg_trust_anchor(0, root_ca, sizeof(root_ca));

            oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, credid);
        }

    }

    if (init < 0)
        return init;
                    pthread_t thread;
    if (pthread_create(&thread, NULL, process_func, NULL) != 0) {
       PRINT("Failed to create main thread\n");
       init = -1;
       goto exit;
    }

    while (quit != 1) {
       showMenu(0, NULL);

       /* Take the input from user and do the selected operation*/
       handleMenu();
    }
    exit:
    oc_free_string(&name);
    free_all_buffer();
    oc_collection_free(collectionPointer); 
    oc_main_shutdown();
    pthread_mutex_destroy(&mutex);
    pthread_mutex_destroy(&app_mutex);

    return 0;
}


/*Entering option no  as choice to execute operation*/
void handleMenu()
{
    char choice[10];
    bool wrongchoice = false;
    int decimal = 0;
    int choiceInt = 0;
    do {
            do {
                if (scanf("%s", choice)) {
                    int choiceLength = strlen(choice);
                    for (int i = 0; i < choiceLength && (quit == 0); i++) {
                        if (isdigit(choice[i])){
                            wrongchoice = false;
                            decimal = 10*decimal +(choice[i] - '0');
                            choiceInt = decimal;

                        }
                        else {
                            printf("Invalid Input. Please select the choice from selctMenu\n");
                            wrongchoice = true;
                            decimal = 0;
                            break;
                        }
                    }
                    decimal = 0;
                }
                 
            } while (wrongchoice && (quit == 0));
                if (!quit) {
                    selectMenu(choiceInt);
                    showMenu(0, NULL);
                }
    } while(choiceInt && (quit == 0));
}

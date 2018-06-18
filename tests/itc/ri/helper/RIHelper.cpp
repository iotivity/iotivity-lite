/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "RIHelper.h"

RIHelper *RIHelper::s_riHelperInstance = NULL;
oc_handler_t RIHelper::s_handler;

bool RIHelper::s_isDiscoverResourceSucessfull = false;
bool RIHelper::s_isObserveResourceSuccessfull = false;
bool RIHelper::s_isRequestSucessfull = false;
bool RIHelper::s_isCollectionRequestSucessfull = false;
bool RIHelper::s_isServerRequestSucessfull = false;
bool RIHelper::s_isRegisterResourceSuccessfull = false;
bool RIHelper::s_isGetResource = false;

bool RIHelper::s_lightState = false;
int RIHelper::s_generalQuit = 0;
char *RIHelper::s_pResourceType = NULL;
oc_resource_t *RIHelper::s_pResource = NULL;
oc_endpoint_t *RIHelper::s_pLightEndpoint = NULL;
oc_endpoint_t *RIHelper::s_pTempServerEndpoint = NULL;
oc_endpoint_t *RIHelper::s_pFridgeServerEndpoint = NULL;
oc_string_t RIHelper::s_lightName;

pthread_mutex_t RIHelper::s_mutex;
pthread_cond_t RIHelper::s_cv;
struct timespec RIHelper::s_ts;

char RIHelper::s_lightUri[MAX_URI_LENGTH];
char RIHelper::s_FridgeServerUri[MAX_URI_LENGTH];
char RIHelper::s_TempServerUri[MAX_URI_LENGTH];

static oc_separate_response_t array_response;
static int large_array[100];

RIHelper::RIHelper()
{
}

RIHelper::~RIHelper()
{
}

RIHelper *RIHelper::getInstance(void)
{
    if (s_riHelperInstance == NULL)
    {
        if (s_riHelperInstance == NULL)
        {
            s_riHelperInstance = new RIHelper();
        }
    }
    return s_riHelperInstance;
}

void RIHelper::setAllVariableFalse()
{
    s_isDiscoverResourceSucessfull = false;
    s_isObserveResourceSuccessfull = false;
    s_isRequestSucessfull = false;
    s_isServerRequestSucessfull = false;
    s_isCollectionRequestSucessfull = false;
    s_isRegisterResourceSuccessfull = false;
}

int RIHelper::createResource()
{
    PRINT("createResource\n");
    int init = 0;
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handleSignalCb;
    sigaction(SIGINT, &sa, NULL);

    s_handler.init = appInitCb;
    s_handler.signal_event_loop = signalEventLoopCb;
    s_handler.register_resources = registerResourcesCb;
    s_handler.requests_entry = issueRequestsCb;

    oc_set_con_res_announced(false);

    init = oc_main_init(&s_handler);

    return init;
}
int RIHelper::waitForEvent()
{
    oc_clock_time_t next_event;
    int countwaittime = 0;

    while (s_generalQuit != 1 && WAITING_TIME != countwaittime)
    {
        PRINT("waitforevent\n");
        next_event = oc_main_poll();
        sleep(1);
        countwaittime++;
    }

}

int RIHelper::initServer()
{
    PRINT("initServer\n");
    int ret = 0;
    s_handler.init = appInitCb;
    s_handler.signal_event_loop = signalEventLoopCb;
    s_handler.register_resources = registerEmptyResourcesCb;

    ret = oc_main_init(&s_handler);
    return ret;
}

int RIHelper::initClient()
{
    PRINT("initClient\n");
    int ret = 0;
    s_handler.init = appInitCb;
    s_handler.signal_event_loop = signalEventLoopCb;
    s_handler.requests_entry = issueRequestsCb;
    ret = oc_main_init(&s_handler);

    return ret;
}

int RIHelper::appInitCb(void)
{
    PRINT("appInitCb\n");

    int ret = oc_init_platform(MANUFACTURE_NAME, NULL, NULL);
    ret |= oc_add_device(DEVICE_URI_LIGHT, DEVICE_TYPE_LIGHT, DEVICE_NAME_LIGHT,
                         OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
    return ret;
}

int RIHelper::appEmptyInitCb(void)
{
    PRINT("appEmptyInitCb\n");
    return 1;
}
void RIHelper::issueEmptyRequestsCb(void)
{
    PRINT("issueEmptyRequestsCb\n");
}

void RIHelper::registerEmptyResourcesCb(void)
{
    PRINT("registerEmptyResourcesCb\n");
}

void RIHelper::signalEventLoopCb(void)
{
    PRINT("signalEventLoopCb\n");
    pthread_mutex_lock(&s_mutex);
    pthread_cond_signal(&s_cv);
    pthread_mutex_unlock(&s_mutex);
}

void RIHelper::issueRequestsCb(void)
{
    PRINT("issueRequestsCb\n");
}

void RIHelper::registerResourcesCb(void)
{
    PRINT("registerResourcesCb\n");

    s_pResource = oc_new_resource(NULL, RESOURCE_URI_LIGHT, 2, 0);
    oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_LIGHT);
    oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_BRIGHT_LIGHT);
    oc_resource_bind_resource_interface(s_pResource, OC_IF_RW);
    oc_resource_set_default_interface(s_pResource, OC_IF_RW);
    oc_resource_set_discoverable(s_pResource, true);
    oc_resource_set_periodic_observable(s_pResource, 1);
    oc_resource_set_request_handler(s_pResource, OC_GET, getLightCb, NULL);
    oc_resource_set_request_handler(s_pResource, OC_PUT, putLightCb, NULL);
    oc_resource_set_request_handler(s_pResource, OC_POST, postLightCb, NULL);
    oc_add_resource(s_pResource);
}
void RIHelper::unRegisterResources(void)
{
    PRINT("unRegisterResources\n");
    oc_delete_resource(s_pResource);
    s_pResource = NULL;
}

void RIHelper::shutDown()
{
    PRINT("shutDown:\n");
    oc_main_shutdown();
}

void RIHelper::getLightCb(oc_request_t *request, oc_interface_mask_t interface,
                          void *user_data)
{
    PRINT("getLightCb:\n");
    (void) user_data;
    oc_rep_start_root_object();
    switch (interface)
    {
        case OC_IF_BASELINE:
            oc_process_baseline_interface(request->resource);
        /* fall through */
        case OC_IF_RW:
            oc_rep_set_boolean(root, state, s_lightState);
            break;
        case OC_IF_A:
            oc_rep_set_boolean(root, rapidFreeze, fridge_state.rapid_freeze);
            oc_rep_set_boolean(root, defrost, fridge_state.defrost);
            oc_rep_set_boolean(root, rapidCool, fridge_state.rapid_cool);
            oc_rep_set_int(root, filter, fridge_state.filter);
        default:
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
    PRINT("Light state %d\n", s_lightState);
    s_isServerRequestSucessfull = true;
    if (!s_isGetResource)
        s_generalQuit = 1;
}

void RIHelper::postLightCb(oc_request_t *request, oc_interface_mask_t interface,
                           void *user_data)
{
    PRINT("postLightCb:\n");
    (void) interface;
    (void) user_data;
    bool state = false;
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL)
    {
        PRINT("key: %s ", oc_string(rep->name));
        switch (rep->type)
        {
            case OC_REP_BOOL:
                state = rep->value.boolean;
                PRINT("value: %d\n", state);
                break;
            case OC_REP_INT:
                if (oc_string_len(rep->name) == 6
                    && memcmp(oc_string(rep->name), "filter", 6) == 0)
                {
                    fridge_state.filter = rep->value.integer;
                    PRINT("value: %d\n", fridge_state.filter);
                }
                else
                {
                    oc_send_response(request, OC_STATUS_BAD_REQUEST);
                    return;
                }
                break;
            default:
                oc_send_response(request, OC_STATUS_BAD_REQUEST);
                return;
                break;
        }
        rep = rep->next;
    }
    oc_send_response(request, OC_STATUS_CHANGED);
    s_lightState = state;
    s_isServerRequestSucessfull = true;
    if (!s_isGetResource)
        s_generalQuit = 1;
}

void RIHelper::putLightCb(oc_request_t *request, oc_interface_mask_t interface,
                          void *user_data)
{
    postLightCb(request, interface, user_data);
}

/** Client Side **/

oc_event_callback_retval_t RIHelper::stopObserveClientCb(void *data)
{
    (void) data;
    PRINT("stopObserveClientCb\n");
    oc_stop_observe(s_lightUri, s_pLightEndpoint);
    s_generalQuit = 1;
    s_isGetResource = false;
    return OC_EVENT_DONE;
}

void RIHelper::observeLightCb(oc_client_response_t *data)
{
    PRINT("observeLightCb\n");
    oc_rep_t *rep = data->payload;
    while (rep != NULL)
    {
        PRINT("key %s, value ", oc_string(rep->name));
        switch (rep->type)
        {
            case OC_REP_BOOL:
                PRINT("%d\n", rep->value.boolean);
                s_lightState = rep->value.boolean;
                break;
            default:
                break;
        }
        rep = rep->next;
    }
    s_isObserveResourceSuccessfull = true;
}

void RIHelper::getLightClientCb(oc_client_response_t *data)
{
    PRINT("getLightClientCb\n");
    (void) data;
    s_isRequestSucessfull = true;
    s_isCollectionRequestSucessfull = true;
    s_isGetResource = false;
    s_generalQuit = 1;
}

void RIHelper::postLightClientCb(oc_client_response_t *data)
{
    PRINT("postLightClientCb:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("POST response OK\n");
    else
        PRINT("POST response code %d\n", data->code);
    s_isRequestSucessfull = true;
    s_isCollectionRequestSucessfull = true;
    s_generalQuit = 1;
}

void RIHelper::putLightClientCb(oc_client_response_t *data)
{
    PRINT("putLightClientCb\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("PUT response OK\n");
    else
        PRINT("PUT response code %d\n", data->code);
    s_isRequestSucessfull = true;
    s_isCollectionRequestSucessfull = true;
    s_isGetResource = false;
    s_generalQuit = 1;
}

void RIHelper::deleteLightClientCb(oc_client_response_t *data)
{
    PRINT("deleteLightClientCb\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("DELETE response OK\n");
    else
        PRINT("DELETE response code %d\n", data->code);
    s_isRequestSucessfull = true;
    s_generalQuit = 1;
}

oc_discovery_flags_t RIHelper::discovery(const char *di, const char *uri,
        oc_string_array_t types, oc_interface_mask_t interfaces,
        oc_endpoint_t *endpoint, oc_resource_properties_t bm, void *user_data)
{
    (void) di;
    (void) interfaces;
    (void) user_data;
    (void) bm;
    int i;
    int uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
    PRINT("discovery: %s\n", uri);
    for (i = 0; i < (int) oc_string_array_get_allocated_size(types); i++)
    {
        char *t = oc_string_array_get_item(types, i);
        if (strlen(t) == 10 && strncmp(t, RESOURCE_TYPE_LIGHT, 10) == 0)
        {
            strncpy(s_lightUri, uri, uri_len);
            s_lightUri[uri_len] = '\0';
            s_pLightEndpoint = endpoint;

            PRINT("Resource %s hosted at endpoints:\n", s_lightUri);
            s_generalQuit = 1;
            s_isDiscoverResourceSucessfull = true;
            return OC_STOP_DISCOVERY;
        }

    }
    oc_free_server_endpoints(endpoint);
    return OC_CONTINUE_DISCOVERY;
}

void RIHelper::discoverResource(char *resourcetype)
{
    PRINT("discoverResource:\n");
    s_generalQuit = 0;
    s_pResourceType = resourcetype;
    setAllVariableFalse();
    oc_do_ip_discovery(resourcetype, &discovery, NULL);
}

void RIHelper::getResource(char *query)
{
    PRINT("getResource:\n");
    s_generalQuit = 0;
    setAllVariableFalse();
    s_isGetResource = true;
    oc_do_get(s_lightUri, s_pLightEndpoint, query, &getLightClientCb, LOW_QOS,
              NULL);
}

void RIHelper::deleteResource()
{
    PRINT("deleteResource:\n");
    s_generalQuit = 0;
    s_isRequestSucessfull = false;
    oc_do_delete(s_lightUri, s_pLightEndpoint, NULL, &deleteLightClientCb,
                 LOW_QOS,
                 NULL);
}
void RIHelper::postRequestResource(char *query)
{
    PRINT("postRequestResource:\n");
    s_generalQuit = 0;
    s_isGetResource = true;
    setAllVariableFalse();
    if (oc_init_post(s_lightUri, s_pLightEndpoint, query, &postLightClientCb,
                     LOW_QOS,
                     NULL))
    {
        oc_rep_start_root_object();
        oc_rep_set_boolean(root, state, !s_lightState);
        oc_rep_end_root_object();
        if (oc_do_post())
            PRINT("Sent POST request\n");
        else
            PRINT("Could not send POST\n");
    }
    else
        PRINT("Could not init POST\n");
}

void RIHelper::putRequestResource(char *query)
{
    PRINT("putRequestResource:\n");
    s_generalQuit = 0;
    s_isGetResource = true;
    setAllVariableFalse();
    if (oc_init_put(s_lightUri, s_pLightEndpoint, query, &putLightClientCb,
                    LOW_QOS,
                    NULL))
    {
        oc_rep_start_root_object();
        oc_rep_set_boolean(root, state, !s_lightState);
        oc_rep_end_root_object();
        if (oc_do_put())
            PRINT("Sent PUT request\n");
        else
            PRINT("Could not send PUT\n");
    }
    else
        PRINT("Could not init PUT\n");
}

void RIHelper::observeResource(char *query)
{
    PRINT("observeResource:\n");
    s_generalQuit = 0;
    s_isGetResource = true;
    oc_do_observe(s_lightUri, s_pLightEndpoint, query, &observeLightCb, LOW_QOS,
                  NULL);
    oc_set_delayed_callback(NULL, &stopObserveClientCb, 10);
}

void RIHelper::handleSignalCb(int signal)
{
    (void) signal;
    PRINT("handleSignalCb:\n");
    signalEventLoopCb();
    s_generalQuit = 1;
}

//collection
int RIHelper::collectionResourceCreate()
{

    PRINT("createResource\n");
    int init = 0;

    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handleSignalCb;
    sigaction(SIGINT, &sa, NULL);

    setAllVariableFalse();

    s_handler.init = appInitCb;
    s_handler.signal_event_loop = signalEventLoopCb;
    s_handler.register_resources = collectionRegisterResourcesCb;
    s_handler.requests_entry = issueRequestsCb;

    oc_set_con_res_announced(false);

    init = oc_main_init(&s_handler);

    return init;
}

void RIHelper::collectionCreate(char *collName, char *collUri)
{
    PRINT("createCollection:\n");
    collection = oc_new_collection(collName, collUri, 1, 0);
    oc_resource_bind_resource_type(collection, RESOURCE_TYPE_COLLECTION);
    oc_resource_set_discoverable(collection, true);
}

void RIHelper::linkToCollection(oc_resource_t *res)
{
    PRINT("linkToCollection:\n");
    oc_link_t *link = oc_new_link(res);
    oc_collection_add_link(collection, link);
}

void RIHelper::addToCollection()
{
    PRINT("addToCollection:\n");
    oc_add_collection(collection);
}

void RIHelper::collectionRegisterResourcesCb(void)
{
    oc_resource_t *res1 = oc_new_resource(RESOURCE_NAME_LIGHT,
                                          RESOURCE_URI_LIGHT, 1, 0);
    oc_resource_bind_resource_type(res1, RESOURCE_TYPE_LIGHT);
    oc_resource_bind_resource_interface(res1, OC_IF_RW);
    oc_resource_set_default_interface(res1, OC_IF_RW);
    oc_resource_set_discoverable(res1, true);
    oc_resource_set_periodic_observable(res1, 1);
    oc_resource_set_request_handler(res1, OC_GET, getLightCb, NULL);
    oc_resource_set_request_handler(res1, OC_PUT, putLightCb, NULL);
    oc_resource_set_request_handler(res1, OC_POST, postLightCb, NULL);
    oc_add_resource(res1);

    oc_resource_t *res2 = oc_new_resource(RESOURCE_NAME_FAN, RESOURCE_URI_FAN,
                                          1, 0);
    oc_resource_bind_resource_type(res2, RESOURCE_TYPE_FAN);
    oc_resource_bind_resource_interface(res2, OC_IF_R);
    oc_resource_set_default_interface(res2, OC_IF_R);
    oc_resource_set_discoverable(res2, true);
    oc_resource_set_periodic_observable(res2, 1);

    oc_add_resource(res2);

    oc_resource_t *col = oc_new_collection(RESOURCE_COLLECTION_NAME_ROOM,
                                           RESOURCE_COLLECTION_TYPE_LIGHT, 1, 0);
    oc_resource_bind_resource_type(col, RESOURCE_TYPE_COLLECTION);
    oc_resource_set_discoverable(col, true);

    oc_link_t *l1 = oc_new_link(res1);
    oc_collection_add_link(col, l1);

    oc_link_t *l2 = oc_new_link(res2);
    oc_collection_add_link(col, l2);
    oc_add_collection(col);

    s_isRegisterResourceSuccessfull = true;
}

void RIHelper::collectionDiscoverResource()
{
    PRINT("collectionDiscoverResource:\n");
    s_generalQuit = 0;
    s_isDiscoverResourceSucessfull = false;
    oc_do_ip_discovery(NULL, &collectionDiscovery, NULL);
}
static oc_discovery_flags_t RIHelper::collectionDiscovery(const char *anchor,
        const char *uri, oc_string_array_t types,
        oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
        oc_resource_properties_t bm, void *user_data)
{
    (void) anchor;
    (void) interfaces;
    (void) user_data;
    (void) bm;
    int i;
    int uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

    for (i = 0; i < (int) oc_string_array_get_allocated_size(types); i++)
    {
        char *t = oc_string_array_get_item(types, i);
        if (strlen(t) == 10 && strncmp(t, "oic.wk.col", 10) == 0)
        {
            s_pLightEndpoint = endpoint;

            strncpy(s_lightUri, uri, uri_len);
            s_lightUri[uri_len] = '\0';

            PRINT("Resource %s hosted at endpoints:\n", s_lightUri);
            s_generalQuit = 1;
            s_isDiscoverResourceSucessfull = true;

            return OC_STOP_DISCOVERY;
        }
    }
    oc_free_server_endpoints(endpoint);
    return OC_CONTINUE_DISCOVERY;
}
static void RIHelper::collectionPostLightsCb(oc_client_response_t *data)
{
    PRINT("\nPOST_lights_oic_if_b:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("POST response OK\n");
    else
        PRINT("POST response code %d\n", data->code);

    oc_rep_t *ll = data->payload;

    while (ll != NULL)
    {
        PRINT("\tLink:\n");
        oc_rep_t *link = ll->value.object;
        while (link != NULL)
        {
            switch (link->type)
            {
                case OC_REP_STRING:
                    PRINT("\t\tkey: %s value: %s\n", oc_string(link->name),
                          oc_string(link->value.string));
                    break;
                case OC_REP_OBJECT:
                    {
                        PRINT("\t\tkey: %s value: { ", oc_string(link->name));
                        oc_rep_t *rep = link->value.object;
                        while (rep != NULL)
                        {
                            switch (rep->type)
                            {
                                case OC_REP_BOOL:
                                    PRINT(" %s : %d ", oc_string(rep->name),
                                          rep->value.boolean);
                                    break;
                                case OC_REP_INT:
                                    PRINT(" %s : %d ", oc_string(rep->name),
                                          rep->value.integer);
                                    break;
                                default:
                                    break;
                            }
                            rep = rep->next;
                        }
                        PRINT(" }\n\n");
                    }
                    break;
                default:
                    break;
            }
            link = link->next;
        }
        ll = ll->next;
    }
}

void RIHelper::collectionPostRequestResource(char *query)
{
    PRINT("postRequestResource:\n");
    s_generalQuit = 0;
    setAllVariableFalse();
    if (oc_init_post(s_lightUri, s_pLightEndpoint, query,
                     &collectionPostLightsCb, LOW_QOS,
                     NULL))
    {
        oc_rep_start_links_array();
        oc_rep_object_array_start_item (links);
        oc_rep_set_text_string(links, href, RESOURCE_URI_LIGHT);
        oc_rep_set_object(links, rep);
        oc_rep_set_boolean(rep, state, true);
        oc_rep_close_object(links, rep);
        oc_rep_object_array_end_item(links);
        oc_rep_object_array_start_item(links);
        oc_rep_set_text_string(links, href, RESOURCE_URI_FAN);
        oc_rep_set_object(links, rep);
        oc_rep_set_int(rep, count, 100);
        oc_rep_close_object(links, rep);
        oc_rep_object_array_end_item(links);
        oc_rep_end_links_array();
        if (oc_do_post())
            PRINT("Sent POST request\n");
        else
            PRINT("Could not send POST\n");
    }
    else
        PRINT("Could not init POST\n");
}

/*******************BLOCK DATA ************************/

void RIHelper::blockDataResourceCreate()
{
    PRINT("blockDataResourceCreate\n");
    int init = 0;
    setAllVariableFalse();
    s_handler.init = appInitCb;
    s_handler.signal_event_loop = signalEventLoopCb;
    s_handler.register_resources = blockDataRegisterResourcesCb;
    s_handler.requests_entry = issueRequestsCb;

    oc_set_con_res_announced(false);

    init = oc_main_init(&s_handler);
}

void RIHelper::blockDiscoverResource()
{
    PRINT("blockDiscoverResource:\n");
    s_generalQuit = 0;
    s_isDiscoverResourceSucessfull = false;
    oc_do_ip_discovery(NULL, &blockDiscovery, NULL);
}

static oc_discovery_flags_t RIHelper::blockDiscovery(const char *anchor,
        const char *uri, oc_string_array_t types,
        oc_interface_mask_t interfaces, oc_endpoint_t *endpoint,
        oc_resource_properties_t bm, void *user_data)
{
    (void) anchor;
    (void) interfaces;
    (void) user_data;
    (void) bm;
    int i;
    int uri_len = strlen(uri);
    uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;

    for (i = 0; i < (int) oc_string_array_get_allocated_size(types); i++)
    {
        char *t = oc_string_array_get_item(types, i);
        if (strlen(t) == 11 && strncmp(t, "oic.r.array", 11) == 0)
        {
            s_pLightEndpoint = endpoint;

            strncpy(s_lightUri, uri, uri_len);
            s_lightUri[uri_len] = '\0';

            PRINT("Resource %s hosted at endpoints:\n", s_lightUri);
            s_generalQuit = 1;
            s_isDiscoverResourceSucessfull = true;

            return OC_STOP_DISCOVERY;
        }
    }
    oc_free_server_endpoints(endpoint);
    return OC_CONTINUE_DISCOVERY;
}

static oc_event_callback_retval_t RIHelper::handleArrayResponseCb(void *data)
{
    (void) data;
    PRINT("handleArrayResponseCb:\n");
    if (array_response.active)
    {
        oc_set_separate_response_buffer(&array_response);
        PRINT("GET_array:\n");
        int i;
        for (i = 0; i < 100; i++)
        {
            large_array[i] = oc_random_value();
            PRINT("(%d %d) ", i, large_array[i]);
        }
        PRINT("\n");
        oc_rep_start_root_object();
        oc_rep_set_int_array(root, array, large_array, 100);
        oc_rep_end_root_object();
        oc_send_separate_response(&array_response, OC_STATUS_OK);
    }
    s_isServerRequestSucessfull = true;
    return OC_EVENT_DONE;
}

static void RIHelper::getArrayCb(oc_request_t *request,
                                 oc_interface_mask_t interface, void *user_data)
{
    (void) interface;
    (void) user_data;
    PRINT("GET_array_Cb:\n");
    oc_indicate_separate_response(request, &array_response);
    oc_set_delayed_callback(NULL, &handleArrayResponseCb, 5);
}

static void RIHelper::postArrayCb(oc_request_t *request,
                                  oc_interface_mask_t interface, void *user_data)
{
    (void) interface;
    (void) user_data;
    PRINT("POST_array_Cb:\n");
    int i;
    oc_rep_t *rep = request->request_payload;
    while (rep != NULL)
    {
        PRINT("key: %s ", oc_string(rep->name));
        switch (rep->type)
        {
            case OC_REP_INT_ARRAY:
                {
                    int *arr = oc_int_array(rep->value.array);
                    for (i = 0; i < (int) oc_int_array_size(rep->value.array); i++)
                    {
                        PRINT("(%d %d) ", i, arr[i]);
                    }
                    PRINT("\n");
                }
                break;
            default:
                break;
        }
        rep = rep->next;
    }
    oc_send_response(request, OC_STATUS_CHANGED);
    s_isServerRequestSucessfull = true;
}

static void RIHelper::blockDataRegisterResourcesCb(void)
{
    PRINT("blockDataRegisterResourcesCb:\n");
    s_pResource = oc_new_resource(NULL, RESOURCE_URI_LIGHT, 1, 0);
    oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_BLOCK_DATA);
    oc_resource_bind_resource_interface(s_pResource, OC_IF_RW);
    oc_resource_set_default_interface(s_pResource, OC_IF_RW);
    oc_resource_set_discoverable(s_pResource, true);
    oc_resource_set_periodic_observable(s_pResource, 5);
    oc_resource_set_request_handler(s_pResource, OC_GET, getArrayCb, NULL);
    oc_resource_set_request_handler(s_pResource, OC_POST, postArrayCb, NULL);
    oc_add_resource(s_pResource);
    s_isRegisterResourceSuccessfull = true;
}

static void RIHelper::blockDataGetArrayCb(oc_client_response_t *data)
{
    int i;
    PRINT("blockDataGetArrayCb:\n");

    oc_rep_t *rep = data->payload;
    while (rep != NULL)
    {
        PRINT("key %s, value ", oc_string(rep->name));
        switch (rep->type)
        {
            case OC_REP_INT_ARRAY:
                {
                    int *arr = oc_int_array(rep->value.array);
                    for (i = 0; i < (int) oc_int_array_size(rep->value.array); i++)
                    {
                        PRINT("(%d %d) ", i, arr[i]);
                    }
                    PRINT("\n");
                }
                break;
            default:
                break;
        }
        rep = rep->next;
    }
    s_isRequestSucessfull = true;
    s_generalQuit = 1;
}

void RIHelper::blockDataGetResource(char *query)
{
    PRINT("blockDataGetResource:\n");
    s_generalQuit = 0;
    setAllVariableFalse();
    oc_do_get(s_lightUri, s_pLightEndpoint, query, &blockDataGetArrayCb,
              HIGH_QOS,
              NULL);
}

static void
RIHelper::blockDataPostArrayCb(oc_client_response_t *data)
{
    PRINT("POST_array:\n");
    if (data->code == OC_STATUS_CHANGED)
        PRINT("POST response OK\n");
    else
        PRINT("POST response code %d\n", data->code);
    s_isRequestSucessfull = true;
    s_generalQuit = 1;

}

void RIHelper::blockDataPostResource(char *query)
{
    PRINT("blockDataPostResource:\n");
    s_generalQuit = 0;
    setAllVariableFalse();
    int large_array[100];
    int i;
    if (oc_init_post(s_lightUri, s_pLightEndpoint, NULL, &blockDataPostArrayCb, LOW_QOS, NULL))
    {
        for (i = 0; i < 100; i++)
        {
            large_array[i] = oc_random_value();
            PRINT("(%d %d) ", i, large_array[i]);
        }
        PRINT("\n");
        oc_rep_start_root_object();
        oc_rep_set_int_array(root, array, large_array, 100);
        oc_rep_end_root_object();
        if (oc_do_post())
            PRINT("Sent POST request\n");
        else
            PRINT("Could not send POST\n");
    }
    else
        PRINT("Could not init POST\n");
}


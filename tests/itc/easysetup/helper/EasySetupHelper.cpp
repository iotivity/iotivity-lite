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

#include "EasySetupHelper.h"
#include "es_common.h"

EasySetupHelper *EasySetupHelper::s_easySetupHelperInstance = NULL;
oc_handler_t EasySetupHelper::s_handler;

bool EasySetupHelper::s_lightState = false;

bool EasySetupHelper::s_iswifiProvinAppCbSucessfull = false;
bool EasySetupHelper::s_isdevConfProInAppCbSucessfull = false;
bool EasySetupHelper::s_iscloudConfProvinAppCBSucessfull = false;

es_provisioning_callbacks_s EasySetupHelper::easyset_callbacks_handler;
user_properties_t EasySetupHelper::s_useProperties;

int EasySetupHelper::s_generalQuit = 0;
oc_resource_t *EasySetupHelper::s_pResource = NULL;

pthread_mutex_t EasySetupHelper::s_mutex;
pthread_cond_t EasySetupHelper::s_cv;

EasySetupHelper::EasySetupHelper()
{
}

EasySetupHelper::~EasySetupHelper()
{
}

EasySetupHelper *EasySetupHelper::getInstance(void)
{
    if (s_easySetupHelperInstance == NULL)
    {
        if (s_easySetupHelperInstance == NULL)
        {
            s_easySetupHelperInstance = new EasySetupHelper();
        }
    }
    return s_easySetupHelperInstance;
}

int EasySetupHelper::createResource()
{
    PRINT("createResource\n");
    int init = 0;

    s_handler.init = appInitCb;
    s_handler.signal_event_loop = signalEventLoopCb;
    s_handler.register_resources = registerResourcesCb;
    s_handler.requests_entry = issueRequestsCb;

    oc_set_con_res_announced(false);

    init = oc_main_init(&s_handler);

    return init;
}

int EasySetupHelper::waitForEvent()
{
    int count = 0;
    while (s_generalQuit != 1 && count != TIMEOUT)
    {
        PRINT("waitforevent\n");
        oc_main_poll();
        sleep(1);
        count++;
    }
}

int EasySetupHelper::appInitCb(void)
{
    PRINT("appInitCb\n");

    int ret = oc_init_platform(MANUFACTURE_NAME, NULL, NULL);
    ret |= oc_add_device(DEVICE_URI_LIGHT, DEVICE_TYPE_LIGHT, DEVICE_NAME_LIGHT,
                         OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
    return ret;
}

void EasySetupHelper::signalEventLoopCb(void)
{
    PRINT("signalEventLoopCb\n");
    pthread_mutex_lock(&s_mutex);
    pthread_cond_signal(&s_cv);
    pthread_mutex_unlock(&s_mutex);
}

void EasySetupHelper::issueRequestsCb(void)
{
    PRINT("issueRequestsCb\n");
}

void EasySetupHelper::registerResourcesCb(void)
{
    PRINT("registerResourcesCb\n");

    s_pResource = oc_new_resource(NULL, RESOURCE_URI_LIGHT, 1, 0);
    oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_LIGHT);
    oc_resource_bind_resource_interface(s_pResource, OC_IF_RW);
    oc_resource_set_default_interface(s_pResource, OC_IF_RW);
    oc_resource_set_discoverable(s_pResource, true);
    oc_resource_set_request_handler(s_pResource, OC_GET, getLightCb, NULL);
    oc_resource_set_request_handler(s_pResource, OC_POST, postLightCb, NULL);
    oc_add_resource(s_pResource);
}

void EasySetupHelper::unRegisterResources(void)
{
    PRINT("unRegisterResources\n");
    oc_delete_resource(s_pResource);
    s_pResource = NULL;
}

void EasySetupHelper::shutDown()
{
    PRINT("shutDown:\n");
    oc_main_shutdown();
}

void EasySetupHelper::getLightCb(oc_request_t *request,
                                 oc_interface_mask_t interface, void *user_data)
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
        default:
            break;
    }
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
    PRINT("Light state %d\n", s_lightState);
}

static void EasySetupHelper::postLightCb(oc_request_t *request,
        oc_interface_mask_t interface, void *user_data)
{
    PRINT("postLightCb:\n");
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
                oc_send_response(request, OC_STATUS_BAD_REQUEST);
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
    s_generalQuit = 1;
}

/** Client Side **/

void EasySetupHelper::wifiProvinAppCb(es_wifi_conf_data *event_data)
{
    printf("wifiProvinAppCb in\n");

    s_isdevConfProInAppCbSucessfull = true;
    if (event_data == NULL)
    {
        printf("es_wifi_conf_data is NULL\n");
        return;
    }

    printf("SSID : %s\n", event_data->ssid);
    printf("Password : %s\n", event_data->pwd);
    printf("AuthType : %d\n", event_data->authtype);
    printf("EncType : %d\n", event_data->enctype);

    printf("wifiProvinAppCb out\n");
}

void EasySetupHelper::devConfProInAppCb(es_dev_conf_data *event_data)
{
    printf("devConfProInAppCb in\n");

    s_iswifiProvinAppCbSucessfull = true;
    if (event_data == NULL)
    {
        printf("es_dev_conf_data is NULL\n");
        return;
    }

    printf("devConfProInAppCb out\n");
}

void EasySetupHelper::cloudConfProvinAppCB(
    es_coap_cloud_conf_data *event_data)
{
    printf("cloudConfProvinAppCB in\n");

    s_iscloudConfProvinAppCBSucessfull = true;
    if (event_data == NULL)
    {
        printf("es_coap_cloud_conf_data is NULL\n");
        return;
    }

    if (oc_string(event_data->auth_code))
    {
        printf("AuthCode : %s\n", event_data->auth_code);
    }

    if (oc_string(event_data->access_token))
    {
        printf("Access Token : %s\n", event_data->access_token);
    }

    if (oc_string(event_data->auth_provider))
    {
        printf("AuthProvider : %s\n", event_data->auth_provider);
    }

    if (oc_string(event_data->ci_server))
    {
        printf("CI Server : %s\n", event_data->ci_server);
    }

    printf("cloudConfProvinAppCB out\n");
}

static void EasySetupHelper::readUserDataCb(oc_rep_t *payload,
        char *resourceType, void **userdata)
{
    (void) resourceType;

    printf("readUserDataCb in\n");

    int user_prop_value = 0;

    oc_rep_t *rep = payload;
    while (rep != NULL)
    {
        OC_DBG("key %s", oc_string(rep->name));
        switch (rep->type)
        {
            case OC_REP_INT:
                {
                    if (strcmp(oc_string(rep->name), STR_USERPROPERTY_KEY_INT) == 0)
                    {
                        user_prop_value = rep->value.integer;
                        OC_DBG("user_prop_value %u", user_prop_value);

                        if (*userdata != NULL)
                        {
                            *userdata = (void *) malloc(sizeof(user_properties_t));
                            ((user_properties_t *) (*userdata))->user_value_int =
                                user_prop_value;
                        }

                        s_useProperties.user_value_int = user_prop_value;
                    }
                }

            default:
                break;
        }
        rep = rep->next;
    }
    printf("readUserDataCb out\n");
}

static void EasySetupHelper::writeUserDataCb(oc_rep_t *payload,
        char *resourceType)
{
    (void) resourceType;
    (void) payload;

    printf("writeUserDataCb in\n");

    set_custom_property_int(root, USERPROPERTY_KEY_INT,
                            s_useProperties.user_value_int);
    set_custom_property_str(root, USERPROPERTY_KEY_STR,
                            s_useProperties.user_value_str);

    printf("writeUserDataCb out\n");
}

bool EasySetupHelper::easySetupInitEnrollee(bool isSecured,
        bool isResourceMaskNull, bool isHandlerNull)
{
    printf("EasySetupinitEnrollee in\n");

    s_iswifiProvinAppCbSucessfull = false;
    s_isdevConfProInAppCbSucessfull = false;
    s_iscloudConfProvinAppCBSucessfull = false;

    es_resource_mask_e resourcemMask = NULL;

    if (!isResourceMaskNull)
        resourcemMask = ES_WIFICONF_RESOURCE | ES_COAPCLOUDCONF_RESOURCE
                        | ES_DEVCONF_RESOURCE;
    if (isHandlerNull)
    {
        easyset_callbacks_handler.wifi_prov_cb = NULL;
        easyset_callbacks_handler.dev_conf_prov_cb = NULL;
        easyset_callbacks_handler.cloud_data_prov_cb = NULL;
    }
    else
    {
        easyset_callbacks_handler.wifi_prov_cb = &devConfProInAppCb;
        easyset_callbacks_handler.dev_conf_prov_cb = &devConfProInAppCb;
        easyset_callbacks_handler.cloud_data_prov_cb = &cloudConfProvinAppCB;
    }
    if (es_init_enrollee(isSecured, resourcemMask, easyset_callbacks_handler)
        != ES_OK)
    {
        printf("es_init_enrollee error!\n");
        return false;
    }

    printf("EasySetupinitEnrollee out\n");
    return true;
}

bool EasySetupHelper::easySetupCallbackforUserData(bool isCallbackNull)
{

    if (isCallbackNull)
    {
        if (es_set_callback_for_userdata(NULL, NULL, NULL) != ES_OK)
            return true;
        else
            return false;
    }
    else if (es_set_callback_for_userdata(&readUserDataCb, &writeUserDataCb,
                                          NULL) != ES_OK)
    {
        return false;
    }
    return true;
}

bool EasySetupHelper::setDeviceInfo(bool isDevicePropertyNull)
{
    printf("setDeviceInfo in\n");
    char *device_name = "TEST_DEVICE";

    es_device_property device_property = { { {
                WIFI_11G, WIFI_11N, WIFI_11AC,
                WiFi_EOF
            }, WIFI_5G
        }, { { 0 } }
    };

    oc_new_string(&device_property.DevConf.device_name, device_name,
                  strlen(device_name));

    if (isDevicePropertyNull)
    {
        if (es_set_device_property(NULL) != ES_OK)
        {
            return true;
        }
        return false;
    }
    else if (es_set_device_property(&device_property) != ES_OK)
        return false;

    printf("setDeviceInfo out\n");
    return true;
}

void EasySetupHelper::setUserProperties()
{
    s_useProperties.user_value_int = 0;
    strncpy(s_useProperties.user_value_str, "User String", MAXLEN_STRING);
    printf("setUserProperties done\n");
}

bool EasySetupHelper::stopEasySetup()
{
    printf("stopEasySetup in\n");

    if (es_terminate_enrollee() != ES_OK)
    {
        return false;
    }

    printf("stopEasySetup out\n");
    return true;
}

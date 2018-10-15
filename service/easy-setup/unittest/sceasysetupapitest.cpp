/* *****************************************************************
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

#include <cstdlib>
#include <string>
#include <gtest/gtest.h>

#include "easysetup.h"
#include "sc_easysetup.h"

#define DEVICE_URI "/oic/d"
#define DEVICE_TYPE "oic.d.light"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "TEST_DEVICE"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"
#define DEVICE_UUID "6d9488e5-9c03-bd5e-e2a4-bec3a21b16ab"

const char *deviceType = "deviceType";
static const char *deviceSubType = "deviceSubType";
static const char *regSetDev =
    "{\"wm\":\"00:11:22:33:44:55\",\"pm\":\"00:11:22:33:44:55\","
    "\"bm\":\"00:11:22:33:44:55\",\"rk\":[\"VOICE\",\"EXTRA\","
    "\"BTHIDPOWERON\"],\"sl\":[\"TV2MOBILE\",\"MOBILE2TV\","
    "\"BTWAKEUP\",\"WOWLAN\",\"BTREMOTECON\",\"DLNADMR\"]}";
static const char *nwProvInfo =
    "{\"IMEI\":\"123456789012345 / "
    "01\",\"IMSI\":\"123401234567890\",\"MCC_MNC\":\"100_10\","
    "\"SN\":\"XY0123456XYZ\"}";
static const char *pnpPin = "pinNumber";
static const char *modelNumber = "Model Number";
static const char *esProtocolVersion = "2.0";

static void scan_access_points(sec_accesspoint **ap_list)
{
    (void)ap_list;
}

/** Test Class for SC EasySetup API Test, this is the entry point. */
class TestSCEasySetupAPI: public testing::Test
{
   private:
        static oc_handler_t s_handler;
        static es_provisioning_callbacks_s es_api_callbacks;

        static int appInit(void)
        {
            int result = oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            result |= oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                                    OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
            return result;
        }

        static void registerResources(void)
        {
        }

        static void signalEventLoop(void)
        {
        }

        static void requestsEntry(void)
        {
        }

    protected:
        virtual void SetUp()
        {
            s_handler.init = appInit;
            s_handler.signal_event_loop = signalEventLoop;
            s_handler.register_resources = registerResources;
            s_handler.requests_entry = requestsEntry;

            int initResult = oc_main_init(&s_handler);

            ASSERT_TRUE((initResult == 0));
        }

        virtual void TearDown()
        {
            oc_main_shutdown();
        }
};

oc_handler_t TestSCEasySetupAPI::s_handler;

/** Positive Test Cases Start Here */

TEST_F(TestSCEasySetupAPI, SetScProperties_P)
{
    sc_properties sc_properties_setter;
    oc_new_string(&sc_properties_setter.device_type, deviceType, strlen(deviceType));
    oc_new_string(&sc_properties_setter.device_sub_type, deviceSubType,strlen(deviceSubType));
    sc_properties_setter.net_conn_state = NET_STATE_INIT;
    sc_properties_setter.disc_channel = WIFI_DISCOVERY_CHANNEL_INIT;
    oc_new_string(&sc_properties_setter.reg_set_dev, regSetDev, strlen(regSetDev));
    oc_new_string(&sc_properties_setter.net_prov_info, nwProvInfo, strlen(nwProvInfo));
    oc_new_string(&sc_properties_setter.pnp_pin, pnpPin, strlen(pnpPin));
    oc_new_string(&sc_properties_setter.model, modelNumber, strlen(modelNumber));
    oc_new_string(&sc_properties_setter.es_protocol_ver, esProtocolVersion,strlen(esProtocolVersion));

    es_result_e ret = set_sc_properties(&sc_properties_setter);

    EXPECT_TRUE((ES_OK == ret));
    reset_sc_properties();
}

TEST_F(TestSCEasySetupAPI, SetScPropertiesNULL_F)
{

    es_result_e ret = set_sc_properties(NULL);

    EXPECT_TRUE((ES_ERROR == ret));
    reset_sc_properties();
}

TEST_F(TestSCEasySetupAPI, GetScProperties_P)
{
    sc_properties sc_properties_setter;

    oc_new_string(&sc_properties_setter.device_type, deviceType, strlen(deviceType));
    oc_new_string(&sc_properties_setter.device_sub_type, deviceSubType,strlen(deviceSubType));
    sc_properties_setter.net_conn_state = NET_STATE_INIT;
    sc_properties_setter.disc_channel = WIFI_DISCOVERY_CHANNEL_INIT;
    oc_new_string(&sc_properties_setter.reg_set_dev, regSetDev, strlen(regSetDev));
    oc_new_string(&sc_properties_setter.net_prov_info, nwProvInfo, strlen(nwProvInfo));
    oc_new_string(&sc_properties_setter.pnp_pin, pnpPin, strlen(pnpPin));
    oc_new_string(&sc_properties_setter.model, modelNumber, strlen(modelNumber));
    oc_new_string(&sc_properties_setter.es_protocol_ver, esProtocolVersion,strlen(esProtocolVersion));

    set_sc_properties(&sc_properties_setter);
    sc_properties *sc_properties_getter = get_sc_properties();

    EXPECT_TRUE((NET_STATE_INIT == sc_properties_getter->net_conn_state));
    EXPECT_TRUE((WIFI_DISCOVERY_CHANNEL_INIT == sc_properties_getter->disc_channel));
    EXPECT_TRUE((strcmp(deviceType,oc_string(sc_properties_getter->device_type))==0));
    EXPECT_TRUE((strcmp(deviceSubType,oc_string(sc_properties_getter->device_sub_type))==0));
    EXPECT_TRUE((strcmp(regSetDev,oc_string(sc_properties_getter->reg_set_dev))==0));
    EXPECT_TRUE((strcmp(nwProvInfo,oc_string(sc_properties_getter->net_prov_info))==0));
    EXPECT_TRUE((strcmp(pnpPin,oc_string(sc_properties_getter->pnp_pin))==0));
    EXPECT_TRUE((strcmp(modelNumber,oc_string(sc_properties_getter->model))==0));
    EXPECT_TRUE((strcmp(esProtocolVersion,oc_string(sc_properties_getter->es_protocol_ver))==0));


    reset_sc_properties();
}

TEST_F(TestSCEasySetupAPI, ResetScProperties_P)
{
    es_result_e ret = reset_sc_properties();

    EXPECT_TRUE((ES_OK == ret));
}

TEST_F(TestSCEasySetupAPI, InitProvisioningInfoResource_P)
{

    es_result_e ret = init_provisioning_info_resource(NULL);
    EXPECT_TRUE((ES_OK == ret));
    deinit_provisioning_info_resource();
}

TEST_F(TestSCEasySetupAPI, SetSecProvInfo_P)
{
    init_provisioning_info_resource(NULL);
    sec_provisioning_info provisioninginfo_resource;
    provisioninginfo_resource.targets = (sec_provisioning_info_targets *)malloc(1 * sizeof(sec_provisioning_info_targets));
    for (int i = 0; i < 1; i++) {
        oc_new_string(&provisioninginfo_resource.targets[i].target_di, DEVICE_UUID,strlen(DEVICE_UUID));
        oc_new_string(&provisioninginfo_resource.targets[i].target_rt, "oic.d.tv",9);
        provisioninginfo_resource.targets[i].published = false;
    }
    provisioninginfo_resource.targets_size = 1;
    provisioninginfo_resource.owned = false;
    oc_new_string(&provisioninginfo_resource.easysetup_di, DEVICE_UUID, 38);

    es_result_e ret = set_sec_prov_info(&provisioninginfo_resource);

    EXPECT_TRUE((ES_OK == ret));
    deinit_provisioning_info_resource();
}

TEST_F(TestSCEasySetupAPI, SetSecProvInfoNULL_F1)
{
    init_provisioning_info_resource(NULL);

    es_result_e ret = set_sec_prov_info(NULL);

    EXPECT_TRUE((ES_ERROR == ret));
    deinit_provisioning_info_resource();
}

TEST_F(TestSCEasySetupAPI, DeinitProvisioningInfoResource_P)
{
    init_provisioning_info_resource(NULL);
    es_result_e ret = deinit_provisioning_info_resource();
    EXPECT_TRUE((ES_OK == ret));
}

TEST_F(TestSCEasySetupAPI, InitAccessPointListResource_P)
{
    es_result_e ret = init_accesspointlist_resource(scan_access_points);

    EXPECT_TRUE((ES_OK == ret));
    deinit_accesspointlist_resource();
}

TEST_F(TestSCEasySetupAPI, InitAccessPointListResourceScanAccessCallbackNULL_F1)
{
    es_result_e ret = init_accesspointlist_resource(NULL);

    EXPECT_TRUE((ES_ERROR == ret));
    deinit_accesspointlist_resource();
}

TEST_F(TestSCEasySetupAPI, DeInitAccessPointListResource_P)
{
    init_accesspointlist_resource(scan_access_points);
    es_result_e ret = deinit_accesspointlist_resource();

    EXPECT_TRUE((ES_OK == ret));
}
/** Positive Test Cases End Here */

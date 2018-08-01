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

#include <gtest/gtest.h>

#include "EasySetupHelper.h"

class EasySetupIntegrationTest: public ::testing::Test
{
    public:

        virtual void SetUp()
        {
        }

        virtual void TearDown()
        {
        }
};

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained easy setup Initialize API with positive values
 * @target es_result_e es_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
 es_provisioning_callbacks_s callbacks);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * @procedure     1. call es_init_enrollee
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api should return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_init_enrollee_return_check_P)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    EXPECT_TRUE(m_pEasySetupHelper->easySetupInitEnrollee(false, false, false));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained easy setup Initialize API with Negative values
 * @target es_result_e es_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
 es_provisioning_callbacks_s callbacks);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * @procedure     1. call es_init_enrollee with resource mask null
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api should not return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_init_enrollee_resource_mark_null_check_N)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    EXPECT_FALSE(m_pEasySetupHelper->easySetupInitEnrollee(false, true, false));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained easy setup Initialize API with Negative values
 * @target es_result_e es_init_enrollee(bool is_secured, es_resource_mask_e resource_mask,
 es_provisioning_callbacks_s callbacks);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * @procedure     1. call es_init_enrollee with callback null param
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will not return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_init_enrollee_handler_null_check_N)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    EXPECT_FALSE(m_pEasySetupHelper->easySetupInitEnrollee(false, false, true));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, oc_main_shutdown
 * @objective Test iotivity-constrained set_callback_for_usedata API with Posivite values
 * @target es_result_e es_set_callback_for_userdata(es_read_userdata_cb readcb,
 es_write_userdata_cb writecb);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * 2. call es_init_enrollee
 * @procedure     1. es_set_callback_for_userdata
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_set_callback_return_check_P)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    m_pEasySetupHelper->easySetupInitEnrollee(false, false, false);
    EXPECT_TRUE(m_pEasySetupHelper->easySetupCallbackforUserData(false));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, oc_main_shutdown
 * @objective Test iotivity-constrained set_callback_for_usedata API with Nagive values
 * @target es_result_e es_set_callback_for_userdata(es_read_userdata_cb readcb,
 es_write_userdata_cb writecb);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * 2. call es_init_enrollee
 * @procedure     1. es_set_callback_for_userdata with callback NULL
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will not return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_set_callback_null_check_N)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    m_pEasySetupHelper->easySetupInitEnrollee(false, false, false);
    EXPECT_FALSE(m_pEasySetupHelper->easySetupCallbackforUserData(true));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, es_set_callback_for_userdata, oc_main_shutdown
 * @objective Test iotivity-constrained es_set_device_property API with positive values
 * @target es_result_e es_set_device_property(es_device_property *device_property);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * 2. call es_init_enrollee
 * 3. es_set_callback_for_userdata
 * @procedure     1. es_set_device_property
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_set_device_info_return_check_P)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    m_pEasySetupHelper->easySetupInitEnrollee(false, false, false);
    m_pEasySetupHelper->easySetupCallbackforUserData(false);
    EXPECT_TRUE(m_pEasySetupHelper->setDeviceInfo(false));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, es_set_callback_for_userdata, oc_main_shutdown
 * @objective Test iotivity-constrained es_set_device_property API with negative values
 * @target es_result_e es_set_device_property(es_device_property *device_property);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * 2. call es_init_enrollee
 * 3. es_set_callback_for_userdata
 * @procedure     1. es_set_device_property with null param
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will not return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_set_device_info_null_check_N)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    m_pEasySetupHelper->easySetupInitEnrollee(false, false, false);
    m_pEasySetupHelper->easySetupCallbackforUserData(false);
    EXPECT_FALSE(m_pEasySetupHelper->setDeviceInfo(true));

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, es_set_callback_for_userdata, es_set_device_property, oc_main_shutdown
 * @objective Test iotivity-constrained es_terminate_enrollee API with positive values
 * @target es_result_es_result_e es_terminate_enrollee(void);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * 2. call es_init_enrollee
 * 3. es_set_callback_for_userdata
 * 4. es_set_device_property
 * @procedure     1. es_terminate_enrollee
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_stop_return_check_P)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    m_pEasySetupHelper->easySetupInitEnrollee(false, false, false);
    m_pEasySetupHelper->easySetupCallbackforUserData(false);
    m_pEasySetupHelper->setDeviceInfo(false);
    EXPECT_TRUE(m_pEasySetupHelper->stopEasySetup());

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, es_set_callback_for_userdata, es_set_device_property, oc_main_shutdown
 * @objective Test iotivity-constrained es_terminate_enrollee API with negative values
 * @target es_result_es_result_e es_terminate_enrollee(void);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * @procedure     1. es_terminate_enrollee
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected api will return ES_OK
 */
TEST(EasySetupIntegrationTest, easysetup_stop_without_init_check_N)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();

    EXPECT_TRUE(m_pEasySetupHelper->stopEasySetup());

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init, es_init_enrollee, es_set_callback_for_userdata, es_set_device_property,es_terminate_enrollee, oc_main_shutdown
 * @objective Test iotivity-constrained all API with positive values multiple times
 * @target es_result_es_result_e es_terminate_enrollee(void);
 * @test_data     1. OCResourceHandle pointer to the created resource
 * @pre_condition 1. create resource
 * @procedure     1. call es_init_enrollee
 * 2. es_set_callback_for_userdata
 * 3. es_set_device_property
 * 4. es_terminate_enrollee
 * @post_condition 1. unregister resource
 * 2. oc_main_shutdown()
 * @expected system will not crash
 */
TEST(EasySetupIntegrationTest, easysetup_start_stop_multiple_check_P)
{
    EasySetupHelper *m_pEasySetupHelper = EasySetupHelper::getInstance();
    m_pEasySetupHelper->createResource();
    for ( int i = 0; i < 10; i++)
    {
        m_pEasySetupHelper->easySetupInitEnrollee(false, false, false);
        m_pEasySetupHelper->easySetupCallbackforUserData(false);
        m_pEasySetupHelper->setDeviceInfo(false);
        m_pEasySetupHelper->stopEasySetup();
    }

    m_pEasySetupHelper->unRegisterResources();
    m_pEasySetupHelper->shutDown();
}

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

#include <gtest/gtest.h>

class RIGeneralIntegrationTest: public ::testing::Test
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
 * @objective Test iotivity-constrained ri Initialize server and shutDown server with positive values
 * @target int oc_main_init(const oc_handler_t *handler);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. oc_main_init
 * @post_condition 1.  oc_main_shutdown()
 * @expected api should not crash
 */

TEST(RIGeneralIntegrationTest, ri_nonsecure_initserver_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();
    m_pRIHelper->initServer();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri Initialize client and shutDown server with positive values
 * @target int oc_main_init(const oc_handler_t *handler);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. oc_main_init
 * @post_condition 1.  oc_main_shutdown()
 * @expected api should not crash
 */

TEST(RIGeneralIntegrationTest, ri_nonsecure_initclient_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();
    m_pRIHelper->initClient();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri create resource with positive values
 * @target int oc_main_init(const oc_handler_t *handler);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. oc_main_init
 *  2. Discover resource
 * @post_condition 1.  oc_main_shutdown()
 * @expected sucessfully discover created resource
 */

TEST(RIGeneralIntegrationTest, ri_nonsecure_client_createResource_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->createResource();
    m_pRIHelper->discoverResource(RESOURCE_TYPE_LIGHT);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isDiscoverResourceSucessfull );
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri create resource with positive values
 * @target int oc_main_init(const oc_handler_t *handler);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. oc_main_init
 *  2. Discover resource
 * @post_condition 1.  oc_main_shutdown()
 * @expected sucessfully discover created resource
 */

TEST(RIGeneralIntegrationTest, ri_nonsecure_client_discover_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->createResource();
    m_pRIHelper->discoverResource(RESOURCE_TYPE_LIGHT);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isDiscoverResourceSucessfull );
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri observe resource with positive values
 * @target bool oc_do_observe(const char *uri, oc_endpoint_t *endpoint, const char *query,
                   oc_response_handler_t handler, oc_qos_t qos,
                   void *user_data);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 *  2. observe resource
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected sucessfully observe created resource
 */
TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_observe_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->createResource();
    m_pRIHelper->discoverResource(RESOURCE_TYPE_LIGHT);
    m_pRIHelper->waitForEvent();
    m_pRIHelper->observeResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isObserveResourceSuccessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri client send post request
 * @target bool oc_do_post(void);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 *  2. bool oc_do_post(void);
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected post request should be successful
 */
TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_post_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->createResource();
    m_pRIHelper->discoverResource(RESOURCE_TYPE_LIGHT);
    m_pRIHelper->waitForEvent();
    m_pRIHelper->postRequestResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri client send put request
 * @target bool oc_do_put(void);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 *  2. bool oc_do_put(void);
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected put request should be successful
 */

TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_put_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->createResource();
    m_pRIHelper->discoverResource(RESOURCE_TYPE_LIGHT);
    m_pRIHelper->waitForEvent();
    m_pRIHelper->putRequestResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri client send get request
 * @target bool oc_do_get(void);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 *  2. bool oc_do_get(void);
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected get request should be successful
 */

TEST(RIGeneralIntegrationTest, ri_nonsecure_clien_get_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->createResource();
    m_pRIHelper->discoverResource(RESOURCE_TYPE_LIGHT);
    m_pRIHelper->waitForEvent();
    m_pRIHelper->getResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}


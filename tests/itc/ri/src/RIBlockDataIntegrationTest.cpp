#include "RIHelper.h"

#include <gtest/gtest.h>

class RIBlockDataIntegrationTest: public ::testing::Test
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
 * @objective Test iotivity-constrained ri register block resource
 * @target oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_BLOCK_DATA);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected register resource successful
 */
TEST(RIBlockDataIntegrationTest, blockdata_createResource_P)
{
    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->blockDataResourceCreate();
    EXPECT_TRUE( m_pRIHelper->s_isRegisterResourceSuccessfull );
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri discover block resource
 * @target oc_resource_bind_resource_type(s_pResource, RESOURCE_TYPE_BLOCK_DATA);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected resource discover successful
 */
TEST(RIBlockDataIntegrationTest, blockdata_discover_P)
{
    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->blockDataResourceCreate();
    m_pRIHelper->blockDiscoverResource();
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isDiscoverResourceSucessfull );
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri send get request to block resource
 * @target oc_do_get();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_get()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send get request successfully
 */

TEST(RIBlockDataIntegrationTest, blockdata_get_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->blockDataResourceCreate();
    m_pRIHelper->blockDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->blockDataGetResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri send post request to block resource
 * @target oc_do_post();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_post()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send post request successfully
 */
TEST(RIBlockDataIntegrationTest, blockdata_post_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->blockDataResourceCreate();
    m_pRIHelper->blockDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->blockDataPostResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}


/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri server callback check for get request
 * @target oc_do_get();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_get()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send get request successfully
 */
TEST(RIBlockDataIntegrationTest, blockdata_server_get_request_P)
{
    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->blockDataResourceCreate();
    m_pRIHelper->blockDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->blockDataGetResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isServerRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri server callback check for post
 * @target oc_do_post();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_post()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send post request successfully
 */
TEST(RIBlockDataIntegrationTest, blockdata_server_post_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->blockDataResourceCreate();
    m_pRIHelper->blockDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->blockDataPostResource(NULL);
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isServerRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

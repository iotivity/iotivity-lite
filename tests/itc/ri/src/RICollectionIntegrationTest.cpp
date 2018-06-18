#include "RIHelper.h"

#include <gtest/gtest.h>

class RICollectionIntegrationTest: public ::testing::Test
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
 * @objective Test iotivity-constrained ri register collection resource
 * @target void oc_add_collection(oc_resource_t *collection);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected discover successful
 */

TEST(RICollectionIntegrationTest, collection_resource_P)
{
    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    EXPECT_TRUE( m_pRIHelper->s_isRegisterResourceSuccessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri discover collection resource
 * @target void oc_add_collection(oc_resource_t *collection);
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected discover successful
 */

TEST(RICollectionIntegrationTest, collection_resource_discover_P)
{
    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    m_pRIHelper->collectionDiscoverResource();
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isDiscoverResourceSucessfull );
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}


/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri send get request to collection resource
 * @target oc_do_get();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_get()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send get request successfully
 */

TEST(RICollectionIntegrationTest,  collection_resource_get_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    m_pRIHelper->collectionDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->getResource("if=oic.if.ll");
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isCollectionRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri send post request to collection resource
 * @target oc_do_post();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_post()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send post request successfully
 */
TEST(RICollectionIntegrationTest,  collection_resource_post_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    m_pRIHelper->collectionDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->postRequestResource("if=oic.if.b");
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isCollectionRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}

/**
 * @since 2018-06-04
 * @see oc_main_init
 * @objective Test iotivity-constrained ri send put request to collection resource
 * @target oc_do_put();
 * @test_data     node
 * @pre_condition 1. create resource
 * @procedure     1. Discover resource
 * 2. oc_do_put()
 * @post_condition 1. unregister resource
 *  2. oc_main_shutdown()
 * @expected send put request successfully
 */
TEST(RICollectionIntegrationTest,  collection_resource_put_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    m_pRIHelper->collectionDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->putRequestResource("if=oic.if.b");
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isCollectionRequestSucessfull);
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
TEST(RICollectionIntegrationTest, collection_resource_server_post_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    m_pRIHelper->collectionDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->collectionPostRequestResource("if=oic.if.b");
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isServerRequestSucessfull);
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
TEST(RICollectionIntegrationTest, collection_resource_server_get_request_P)
{

    RIHelper *m_pRIHelper;
    m_pRIHelper = RIHelper::getInstance();

    m_pRIHelper->collectionResourceCreate();
    m_pRIHelper->collectionDiscoverResource();
    m_pRIHelper->waitForEvent();
    m_pRIHelper->getResource("if=oic.if.b");
    m_pRIHelper->waitForEvent();
    EXPECT_TRUE( m_pRIHelper->s_isServerRequestSucessfull);
    m_pRIHelper->unRegisterResources();
    m_pRIHelper->shutDown();
}





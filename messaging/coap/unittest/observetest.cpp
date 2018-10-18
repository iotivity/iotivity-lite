
#include <cstdlib>
#include "gtest/gtest.h"

#include "observe.h"
#include "oc_api.h"
#include "oc_endpoint.h"

class TestObserve: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

/*
 * @API: coap_remove_observer_by_client()
 * @Description: Tries to remove observers by client
 * @PassCondition: Should remove observers by client
 * @PreCondition: Create new endpoint
 * @PostCondition: N/A
 */
TEST_F(TestObserve, CreateTransactionTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    int ret = coap_remove_observer_by_client(endpoint);
    oc_free_endpoint(endpoint);
    EXPECT_TRUE(ret == 0) << "Failed to remove observer";
}

/*
 * @API: coap_remove_observer_by_token()
 * @Description: Tries to remove observers by token
 * @PassCondition: Should remove observers by token
 * @PreCondition: Create new endpoint
 * @PostCondition: N/A
 */
TEST_F(TestObserve, RemoveObserverByTokenTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    uint8_t token = 255;
    int ret = coap_remove_observer_by_token(endpoint, &token, 3);
    oc_free_endpoint(endpoint);
    EXPECT_TRUE(ret == 0) << "Failed to remove observer by token";
}

/*
 * @API: coap_remove_observer_by_mid()
 * @Description: Tries to remove observers by mid
 * @PassCondition: Should remove observers by mid
 * @PreCondition: Create new endpoint and get mid
 * @PostCondition: N/A
 */
TEST_F(TestObserve, RemoveObserverByMidTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    int mid = coap_get_mid();
    int ret = coap_remove_observer_by_mid(endpoint, mid);
    oc_free_endpoint(endpoint);
    EXPECT_TRUE(ret == 0) << "Failed to remove observer by mid";
}

/*
 * @API: coap_free_all_observers()
 * @Description: Tries to free all observers
 * @PassCondition: should not throw exception
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestObserve, FreeAllObserverTest_P)
{
    ASSERT_NO_THROW(coap_free_all_observers());
}


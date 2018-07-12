
#include <cstdlib>
#include "gtest/gtest.h"

extern "C" {
#include "observe.h"
#include "oc_api.h"
#include "oc_endpoint.h"
}

OC_MEMB(observers_memb, coap_observer_t, COAP_MAX_OBSERVERS);

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

TEST_F(TestObserve, CreateTransactionTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    int ret = coap_remove_observer_by_client(endpoint);
    EXPECT_TRUE(ret == 0) << "Failed to remove observer";
}

TEST_F(TestObserve, RemoveObserverByTokenTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    int ret = coap_remove_observer_by_token(endpoint, 1234, 3);
    EXPECT_TRUE(ret == 0) << "Failed to remove observer by token";
}

TEST_F(TestObserve, RemoveObserverByMidTest_P)
{
    oc_endpoint_t *endpoint = oc_new_endpoint();
    int mid = coap_get_mid();
    int ret = coap_remove_observer_by_mid(endpoint, mid);
    EXPECT_TRUE(ret == 0) << "Failed to remove observer by mid";
}

TEST_F(TestObserve, FreeAllObserverTest_P)
{
    coap_free_all_observers();
}


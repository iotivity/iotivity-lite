#include <cstdlib>
#include "gtest/gtest.h"

#include "separate.h"
#include "oc_api.h"

class TestCoapPacketSeparate: public testing::Test
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
 * @API: coap_separate_resume()
 * @Description: Tries to separate resume by mid
 * @PassCondition: should not throw exception
 * @PreCondition: Get mid
 * @PostCondition: N/A
 */
TEST_F(TestCoapPacketSeparate, CoapSeparateClearTest_P)
{
    coap_packet_t response[1];
    coap_separate_t separate_store;
    int mid = coap_get_mid();
    ASSERT_NO_THROW(coap_separate_resume( response, &separate_store, OC_STATUS_OK, mid ));
}

/*
 * @API: coap_separate_resume()
 * @Description: Tries to separate resume by mid
 * @PassCondition: should not throw exception
 * @PreCondition: Get mid
 * @PostCondition: N/A
 */
TEST_F(TestCoapPacketSeparate, CoapSeparateResumeTest_P)
{
    coap_packet_t response[1];
    coap_separate_t separate_store;
    int mid = coap_get_mid();
    ASSERT_NO_THROW(coap_separate_resume( response, &separate_store, OC_STATUS_OK,  mid));
}

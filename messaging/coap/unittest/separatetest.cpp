#include <cstdlib>
#include "gtest/gtest.h"

extern "C" {
#include "separate.h"
#include "oc_api.h"
}

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

TEST_F(TestCoapPacketSeparate, CoapSeparateClearTest_P)
{
    coap_packet_t response[1];
    coap_separate_t separate_store;

    coap_separate_resume( response, &separate_store, OC_STATUS_OK, coap_get_mid());
}

TEST_F(TestCoapPacketSeparate, CoapSeparateResumeTest_P)
{
    coap_packet_t response[1];
    coap_separate_t separate_store;
    coap_separate_resume( response, &separate_store,    OC_STATUS_OK,  coap_get_mid());
}

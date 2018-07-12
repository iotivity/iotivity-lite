#include <cstdlib>
#include "gtest/gtest.h"

extern "C" {
#include "engine.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_signal_event_loop.h"
#define delete pseudo_delete
#include "oc_core_res.h"
#undef delete
}

#define MAX_WAIT_TIME 10
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"

class TestEngine: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};

TEST_F(TestEngine, CreateTransactionTest_P)
{
    coap_init_engine();
}

TEST_F(TestEngine, coapReceiveTest_P)
{
    coap_init_engine();
    oc_message_t *message = oc_internal_allocate_outgoing_message();
    int ret = coap_receive(message);
    EXPECT_TRUE(ret) << "Failed to get ret of receive message";

}

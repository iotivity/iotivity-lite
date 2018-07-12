#include <cstdlib>
#include "gtest/gtest.h"

extern "C" {
#include "coap.h"
#include "oc_api.h"
#include "oc_endpoint.h"
}

class TestCoap: public testing::Test
{
    protected:
        virtual void SetUp()
        {

        }

        virtual void TearDown()
        {

        }
};


TEST_F(TestCoap, CoapGetMidTest_P)
{
    uint16_t mid = coap_get_mid();
    EXPECT_TRUE(mid) << "Failed to get mid transaction";
}


TEST_F(TestCoap, CoapUDPInitMessageTest_P)
{
    coap_packet_t ack[1];
    uint16_t mid = coap_get_mid();
    coap_udp_init_message(ack, COAP_TYPE_ACK, 0, mid);
}

TEST_F(TestCoap, CoapSerializeMessageTest_P)
{
    coap_packet_t ack[1];
    uint16_t mid = coap_get_mid();
    coap_udp_init_message(ack, COAP_TYPE_ACK, 0, mid);
    oc_message_t *message = oc_internal_allocate_outgoing_message();
    size_t size = coap_serialize_message(ack, message->data);

    EXPECT_TRUE(size) << "Failed to get mid transaction";
}


TEST_F(TestCoap, CoapSendMessageTest_P)
{
    coap_packet_t ack[1];
    uint16_t mid = coap_get_mid();
    coap_udp_init_message(ack, COAP_TYPE_ACK, 0, mid);
    oc_message_t *message = oc_internal_allocate_outgoing_message();
    coap_serialize_message(ack, message->data);
    coap_send_message(message);
}


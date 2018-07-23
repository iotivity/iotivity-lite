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

TEST_F(TestCoap, UDPParseMessageTest_P)
{
    uint8_t data[] = "1234567890";
    coap_packet_t packet[1];
    coap_status_t status = coap_udp_parse_message(packet, data, 10);
    ASSERT_NE(status, 0);
}

TEST_F(TestCoap, CoapSetHeaderMaxAgeTest_P)
{
    coap_packet_t packet[1];
    int isSuccess = coap_set_header_max_age(packet, 10);
    ASSERT_EQ(isSuccess, 1);

}

TEST_F(TestCoap, CoapGetHeaderEtagTest_P)
{
    coap_packet_t packet[1];
    uint8_t *etag = "1234";
    int ret = coap_get_header_etag(packet, &etag);
    ASSERT_NE(ret, -1);
}

TEST_F(TestCoap, CoapSetHeaderQueryTest_P)
{
    coap_packet_t packet[1];
    char query[] = "1234";
    int isSuccess = coap_set_header_location_query(packet, query);
    ASSERT_NE(isSuccess, 0);
}

TEST_F(TestCoap, CoapSetHeaderBlock1Test_N)
{
    coap_packet_t packet[1];
    int isFailure = coap_set_header_block1(packet, 10, 1, 5);
    ASSERT_EQ(isFailure, 0);
}

TEST_F(TestCoap, CoapSetHeaderBlock1Test_P)
{
    coap_packet_t packet[1];
    int isSuccess = coap_set_header_block1(packet, 10, 1, 32);
    ASSERT_NE(isSuccess, 0);
}

TEST_F(TestCoap, CoapGetHeaderSize2Test_P)
{
    coap_packet_t packet[1];
    uint32_t size;
    int isSuccess = coap_get_header_size2(packet, &size);
    ASSERT_NE(isSuccess, 0);
}

TEST_F(TestCoap, CoapGetHeaderSize1Test_N)
{
    coap_packet_t packet[1];
    uint32_t size;
    int isSuccess = coap_get_header_size1(packet, &size);
    ASSERT_EQ(isSuccess, 0);
}

TEST_F(TestCoap, CoapSetHeaderSize1Test_P)
{
    coap_packet_t packet[1];
    int isSuccess = coap_set_header_size1(packet, 10);
    ASSERT_EQ(isSuccess, 1);
}


#ifdef OC_TCP
TEST_F(TestCoap, CoapTCPInitMessageTest_P)
{
    coap_packet_t packet[1];
    uint16_t mid = coap_get_mid();
    coap_tcp_init_message(packet, 0);
}


TEST_F(TestCoap, TCPPacketSizeTest_P)
{
    uint8_t data[] = "1234567890";
    size_t size = coap_tcp_get_packet_size(data);
    ASSERT_NE(size, 0);

}

TEST_F(TestCoap, TCPParseMessageTest_P)
{
    uint8_t data[] = "1234567890";
    coap_packet_t packet[1];
    coap_status_t status = coap_tcp_parse_message(packet, data, 10);
    ASSERT_NE(status, 0);

}

#endif /* OC_TCP */
/*
int coap_set_header_max_age(void *packet, uint32_t age);
int coap_get_header_etag(void *packet, const uint8_t **etag);
int coap_set_header_location_query(void *packet, const char *query);
int coap_set_header_block1(void *packet, uint32_t num, uint8_t more,
                           uint16_t size);
int coap_get_header_size2(void *packet, uint32_t *size);

int coap_get_header_size1(void *packet, uint32_t *size);
int coap_set_header_size1(void *packet, uint32_t size);
*/
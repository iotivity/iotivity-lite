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

/*
* @API: coap_get_mid()
* @Description: Tries to get mid value
* @PassCondition: Should return mid value
* @PreCondition: N/A
* @PostCondition: N/A
*/
TEST_F(TestCoap, CoapGetMidTest_P)
{
    uint16_t mid = coap_get_mid();
    EXPECT_TRUE(mid) << "Failed to get mid transaction";
}

/*
 * @API: coap_udp_init_message()
 * @Description: Tries to initialize udp message
 * @PassCondition: should not throw exception
 * @PreCondition: Get mid value
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapUDPInitMessageTest_P)
{
    coap_packet_t ack[1];
    uint16_t mid = coap_get_mid();
    ASSERT_NO_THROW(coap_udp_init_message(ack, COAP_TYPE_ACK, 0, mid));
}

/*
 * @API: coap_serialize_message()
 * @Description: Tries to serialize message
 * @PassCondition: Should serialize message
 * @PreCondition: Get mid value, initialize udp message and getting internal outgoing message
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapSerializeMessageTest_P)
{
    coap_packet_t ack[1];
    uint16_t mid = coap_get_mid();
    coap_udp_init_message(ack, COAP_TYPE_ACK, 0, mid);
    oc_message_t *message = oc_internal_allocate_outgoing_message();
    size_t size = coap_serialize_message(ack, message->data);

    EXPECT_TRUE(size) << "Failed to get mid transaction";
}

/*
 * @API: coap_udp_parse_message()
 * @Description: Tries to parse udp message
 * @PassCondition: Should get status of udp parsing message
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, UDPParseMessageTest_P)
{
    uint8_t data[] = "1234567890";
    coap_packet_t packet[1];
    coap_status_t status = coap_udp_parse_message(packet, data, 10);
    ASSERT_NE(status, 0);
}

/*
 * @API: coap_set_header_max_age()
 * @Description: Tries to set header maximum age
 * @PassCondition: Should get status of setup maximum age
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapSetHeaderMaxAgeTest_P)
{
    coap_packet_t packet[1];
    int isSuccess = coap_set_header_max_age(packet, 10);
    ASSERT_EQ(isSuccess, 1);

}

/*
 * @API: coap_get_header_etag()
 * @Description: Tries to get header etag
 * @PassCondition: Should get status result of getting header etag
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapGetHeaderEtagTest_P)
{
    coap_packet_t packet[1];
    uint8_t *etag = "1234";
    int ret = coap_get_header_etag(packet, &etag);
    ASSERT_NE(ret, -1);
}

/*
 * @API: coap_set_header_location_query()
 * @Description: Tries to set header location query
 * @PassCondition: Should get status of setup header location query
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapSetHeaderQueryTest_P)
{
    coap_packet_t packet[1];
    char query[] = "1234";
    int isSuccess = coap_set_header_location_query(packet, query);
    ASSERT_NE(isSuccess, 0);
}

/*
 * @API: coap_set_header_block1()
 * @Description: Tries to set header block
 * @PassCondition: Should get failure status of setup header block
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapSetHeaderBlock1Test_N)
{
    coap_packet_t packet[1];
    int isFailure = coap_set_header_block1(packet, 10, 1, 5);
    ASSERT_EQ(isFailure, 0);
}

/*
 * @API: coap_set_header_block1()
 * @Description: Tries to set header block
 * @PassCondition: Should get success status of setup header block
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapSetHeaderBlock1Test_P)
{
    coap_packet_t packet[1];
    int isSuccess = coap_set_header_block1(packet, 10, 1, 32);
    ASSERT_NE(isSuccess, 0);
}

/*
 * @API: coap_get_header_size2()
 * @Description: Tries to get header size2
 * @PassCondition: Should get failure status of getting header size2
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapGetHeaderSize2Test_N)
{
    coap_packet_t packet[1];
    uint32_t size;
    int isSuccess = coap_get_header_size2(packet, &size);
    // checking will be added later after verification
}

/*
 * @API: coap_get_header_size1()
 * @Description: Tries to get header size1
 * @PassCondition: Should get failure status of getting header size1
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapGetHeaderSize1Test_N)
{
    coap_packet_t packet[1];
    uint32_t size;
    int isSuccess = coap_get_header_size1(packet, &size);
    // checking will be added later after verification
}

/*
 * @API: coap_set_header_size1()
 * @Description: Tries to set header size
 * @PassCondition: Should get success status of getting header size1
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, CoapSetHeaderSize1Test_P)
{
    coap_packet_t packet[1];
    int isSuccess = coap_set_header_size1(packet, 10);
    ASSERT_EQ(isSuccess, 1);
}

/*
 * @API: coap_tcp_init_message()
 * @Description: Tries to initialize tcp message
 * @PassCondition: Should should not throw exception
 * @PreCondition: Get mid value
 * @PostCondition: N/A
 */
#ifdef OC_TCP
TEST_F(TestCoap, CoapTCPInitMessageTest_P)
{
    coap_packet_t packet[1];
    uint16_t mid = coap_get_mid();
    ASSERT_NO_THROW(coap_tcp_init_message(packet, 0));
}

/*
 * @API: coap_tcp_get_packet_size()
 * @Description: Tries to get tcp packet size
 * @PassCondition: Should get tcp packet size
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, TCPPacketSizeTest_P)
{
    uint8_t data[] = "1234567890";
    size_t size = coap_tcp_get_packet_size(data);
    ASSERT_NE(size, 0);

}

/*
 * @API: coap_tcp_parse_message()
 * @Description: Tries to get status tcp parse message
 * @PassCondition: Should get status tcp parsing message
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoap, TCPParseMessageTest_P)
{
    uint8_t data[] = "1234567890";
    coap_packet_t packet[1];
    coap_status_t status = coap_tcp_parse_message(packet, data, 10);
    ASSERT_NE(status, 0);

}
#endif /* OC_TCP */

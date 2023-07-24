/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "coap.h"
#include "coap_signal.h"
#include "oc_api.h"
#include "oc_endpoint.h"

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#if defined(OC_TCP) && defined(OC_IPV4)

static constexpr size_t kDeviceID = 0;

static void
signal_event_loop(void)
{
  // no-op
}

static int
app_init(void)
{
  int ret = oc_init_platform("Samsung", nullptr, nullptr);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", nullptr, nullptr);
  return ret;
}

class TestCoapSignal : public testing::Test {
public:
  void SetUp() override
  {
    static oc_handler_t handler = { /*.init =*/app_init,
                                    /*.signal_event_loop =*/signal_event_loop,
                                    /*.register_resources =*/nullptr,
                                    /*.requests_entry =*/nullptr };

    oc_main_init(&handler);
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(kDeviceID);
    while (ep) {
      if ((ep->flags & TCP) && !(ep->flags & SECURED) && (ep->flags & IPV4)) {
        break;
      }
      ep = ep->next;
    }
    ASSERT_NE(nullptr, ep);
    oc_endpoint_copy(&_target_ep, ep);
  }

  void TearDown() override { oc_main_shutdown(); }

  oc_endpoint_t _target_ep;
};

TEST_F(TestCoapSignal, coap_send_csm_message_P)
{
  int ret =
    coap_send_csm_message(&_target_ep, static_cast<uint32_t>(OC_PDU_SIZE), 1);
  EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_csm_message_N)
{
  int ret =
    coap_send_csm_message(nullptr, static_cast<uint32_t>(OC_PDU_SIZE), 0);
  EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_ping_message_P)
{
  std::array<uint8_t, 4> token = { 0x01, 0x02, 0x03, 0x04 };
  int ret = coap_send_ping_message(&_target_ep, 1, token.data(), token.size());
  EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_ping_message_N)
{
  int ret = coap_send_ping_message(nullptr, 0, nullptr, 0);
  EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_pong_message_P)
{
  std::array<uint8_t, 4> token = { 0x01, 0x02, 0x03, 0x04 };
  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, PING_7_02);
  coap_set_token(&packet, token.data(), token.size());
  ASSERT_TRUE(coap_signal_set_custody(&packet, 1));

  int ret = coap_send_pong_message(&_target_ep, &packet);
  EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_pong_message_N)
{
  int ret = coap_send_pong_message(nullptr, nullptr);
  EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_release_message_P)
{
  std::string addr = "coap+tcp://127.0.0.1:5683";
  uint32_t hold_off = 10;
  int ret = coap_send_release_message(&_target_ep, addr.c_str(),
                                      addr.length() + 1, hold_off);
  EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_release_message_N)
{
  int ret = coap_send_release_message(nullptr, nullptr, 0, 0);
  EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_abort_message_P)
{
  uint16_t opt = 10;
  std::string msg = "Abort!";

  int ret =
    coap_send_abort_message(&_target_ep, opt, msg.c_str(), msg.length() + 1);
  EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_abort_message_N)
{
  int ret = coap_send_abort_message(nullptr, 0, nullptr, 0);
  EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_check_signal_message_P)
{
  coap_packet_t packet{};
  ASSERT_NO_THROW(coap_tcp_init_message(&packet, CSM_7_01));

  int ret = coap_check_signal_message(&packet);
  EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_check_signal_message_N)
{
  coap_packet_t packet{};
  ASSERT_NO_THROW(coap_tcp_init_message(&packet, COAP_GET));

  int ret = coap_check_signal_message(&packet);
  EXPECT_EQ(0, ret);
} /*
   * @API: coap_signal_get_max_msg_size()
   * @Description: Tries to get max message size for signal packet
   * @PassCondition: Should get max message size
   * @PreCondition: set max message size option
   * @PostCondition: N/A
   */
TEST_F(TestCoapSignal, SignalGetMaxMsgSizeTest_P)
{
  coap_packet_t packet{};
  uint32_t answer = 1152;
  coap_tcp_init_message(&packet, CSM_7_01);
  ASSERT_TRUE(coap_signal_set_max_msg_size(&packet, answer));

  uint32_t size = 0;
  ASSERT_TRUE(coap_signal_get_max_msg_size(&packet, &size));
  ASSERT_EQ(answer, size);
}

/*
 * @API: coap_signal_get_max_msg_size()
 * @Description: Tries to get max message size for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetMaxMsgSizeTest_N)
{
  coap_packet_t packet{};
  uint32_t size = 0;
  ASSERT_FALSE(coap_signal_get_max_msg_size(&packet, &size));
}

/*
 * @API: coap_signal_set_max_msg_size()
 * @Description: Tries to set max message size for signal packet
 * @PassCondition: Should set max message size
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetMaxMsgSizeTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, CSM_7_01);

  uint32_t size = 1152;
  ASSERT_TRUE(coap_signal_set_max_msg_size(&packet, size));

  uint32_t actual = 0;
  ASSERT_TRUE(coap_signal_get_max_msg_size(&packet, &actual));
  ASSERT_EQ(size, actual);
}

/*
 * @API: coap_signal_get_max_msg_size()
 * @Description: Tries to set max message size for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetMaxMsgSizeTest_N)
{
  coap_packet_t packet{};
  uint32_t size = 1152;
  ASSERT_FALSE(coap_signal_set_max_msg_size(&packet, size));
}

/*
 * @API: coap_signal_get_blockwise_transfer()
 * @Description: Tries to get blockwise_transfer flag for signal packet
 * @PassCondition: Should get blockwise_transfer flag
 * @PreCondition: set blockwise_transfer option
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetBertTest_P)
{
  coap_packet_t packet{};
  uint8_t blockwise_transfer = 1;
  coap_tcp_init_message(&packet, CSM_7_01);
  coap_signal_set_blockwise_transfer(&packet, blockwise_transfer);

  uint8_t flag = 0;
  ASSERT_TRUE(coap_signal_get_blockwise_transfer(&packet, &flag));
  ASSERT_EQ(blockwise_transfer, flag);
}

/*
 * @API: coap_signal_get_blockwise_transfer()
 * @Description: Tries to get gert flag for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetBertTest_N)
{
  coap_packet_t packet{};
  uint8_t flag = 0;
  ASSERT_FALSE(coap_signal_get_blockwise_transfer(&packet, &flag));
}

/*
 * @API: coap_signal_set_blockwise_transfer()
 * @Description: Tries to set blockwise_transfer flag for signal packet
 * @PassCondition: Should set blockwise_transfer flag
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetBertTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, CSM_7_01);

  uint8_t blockwise_transfer = 1;
  ASSERT_TRUE(coap_signal_set_blockwise_transfer(&packet, blockwise_transfer));

  uint8_t actual = 0;
  coap_signal_get_blockwise_transfer(&packet, &actual);
  ASSERT_EQ(blockwise_transfer, actual);
}

/*
 * @API: coap_signal_set_blockwise_transfer()
 * @Description: Tries to set blockwise_transfer flag for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetBertTest_N)
{
  coap_packet_t packet{};
  uint8_t blockwise_transfer = 1;
  ASSERT_FALSE(coap_signal_set_blockwise_transfer(&packet, blockwise_transfer));
}

/*
 * @API: coap_signal_get_custody()
 * @Description: Tries to get custody flag for signal packet
 * @PassCondition: Should get custody flag
 * @PreCondition: set custody option
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetCustodyTest_P)
{
  coap_packet_t packet{};
  uint8_t custody = 1;
  coap_tcp_init_message(&packet, PING_7_02);
  ASSERT_TRUE(coap_signal_set_custody(&packet, custody));

  uint8_t flag = 0;
  ASSERT_TRUE(coap_signal_get_custody(&packet, &flag));
  ASSERT_EQ(custody, flag);
}

/*
 * @API: coap_signal_get_custody()
 * @Description: Tries to get custody flag for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetCustodyTest_N)
{
  coap_packet_t packet{};
  uint8_t flag = 0;
  ASSERT_FALSE(coap_signal_get_custody(&packet, &flag));
}

/*
 * @API: coap_signal_set_custody()
 * @Description: Tries to set custody flag for signal packet
 * @PassCondition: Should set custody flag
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetCustodyTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, PING_7_02);

  uint8_t custody = 1;
  ASSERT_TRUE(coap_signal_set_custody(&packet, custody));

  uint8_t actual = 0;
  ASSERT_TRUE(coap_signal_get_custody(&packet, &actual));
  ASSERT_EQ(custody, actual);
}

/*
 * @API: coap_signal_set_custody()
 * @Description: Tries to set custody flag for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetCustodyTest_N)
{
  coap_packet_t packet{};
  uint8_t custody = 1;
  ASSERT_FALSE(coap_signal_set_custody(&packet, custody));
}

/*
 * @API: coap_signal_get_alt_addr()
 * @Description: Tries to get alternative address for signal packet
 * @PassCondition: Should get alternative address
 * @PreCondition: set alternative address option
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetAltAddrTest_P)
{
  coap_packet_t packet{};
  std::string addr = "coap+tcp://127.0.0.1:5683";
  coap_tcp_init_message(&packet, RELEASE_7_04);
  coap_signal_set_alt_addr(&packet, addr.c_str(), addr.length() + 1);

  const char *actual = nullptr;
  size_t actual_len = coap_signal_get_alt_addr(&packet, &actual);

  ASSERT_EQ(addr.length() + 1, actual_len);
  ASSERT_EQ(addr.c_str(), actual);
}

/*
 * @API: coap_signal_get_alt_addr()
 * @Description: Tries to get alternative address for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetAltAddrTest_N)
{
  coap_packet_t packet{};
  size_t isFailure = coap_signal_get_alt_addr(&packet, nullptr);

  ASSERT_EQ(isFailure, 0);
}

/*
 * @API: coap_signal_set_alt_addr()
 * @Description: Tries to set alternative address for signal packet
 * @PassCondition: Should set alternative address
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetAltAddrTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, RELEASE_7_04);

  std::string addr = "coap+tcp://127.0.0.1:5683";
  size_t length =
    coap_signal_set_alt_addr(&packet, addr.c_str(), addr.length() + 1);
  ASSERT_EQ(addr.length() + 1, length);

  const char *actual = nullptr;
  length = coap_signal_get_alt_addr(&packet, &actual);
  ASSERT_EQ(addr.length() + 1, length);
  ASSERT_STREQ(addr.c_str(), actual);
}

/*
 * @API: coap_signal_set_alt_addr()
 * @Description: Tries to set alternative address for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetAltAddrTest_N)
{
  coap_packet_t packet{};
  size_t isFailure = coap_signal_set_alt_addr(&packet, nullptr, 0);

  ASSERT_EQ(isFailure, 0);
}

/*
 * @API: coap_signal_get_hold_off()
 * @Description: Tries to get hold off seconds for signal packet
 * @PassCondition: Should get hold off seconds
 * @PreCondition: set hold off option
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetHoldOffTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, RELEASE_7_04);
  uint32_t time_seconds = 10;
  ASSERT_TRUE(coap_signal_set_hold_off(&packet, time_seconds));

  uint32_t actual = 0;
  ASSERT_TRUE(coap_signal_get_hold_off(&packet, &actual));
  ASSERT_EQ(time_seconds, actual);
}

/*
 * @API: coap_signal_get_hold_off()
 * @Description: Tries to get hold off seconds for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetHoldOffTest_N)
{
  coap_packet_t packet{};
  uint32_t time_seconds;
  ASSERT_FALSE(coap_signal_get_hold_off(&packet, &time_seconds));
}

/*
 * @API: coap_signal_set_hold_off()
 * @Description: Tries to set hold off seconds for signal packet
 * @PassCondition: Should set hold off seconds
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetHoldOffTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, RELEASE_7_04);

  uint32_t time_seconds = 10;
  ASSERT_TRUE(coap_signal_set_hold_off(&packet, time_seconds));

  uint32_t actual = 0;
  ASSERT_TRUE(coap_signal_get_hold_off(&packet, &actual));
  ASSERT_EQ(time_seconds, actual);
}

/*
 * @API: coap_signal_set_hold_off()
 * @Description: Tries to set hold off seconds for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetHoldOffTest_N)
{
  coap_packet_t packet{};

  uint32_t time_seconds = 10;
  ASSERT_FALSE(coap_signal_set_hold_off(&packet, time_seconds));
}

/*
 * @API: coap_signal_get_bad_csm()
 * @Description: Tries to get bad csm option for signal packet
 * @PassCondition: Should get bad csm option
 * @PreCondition: set bad csm option
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetBadCsmTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, ABORT_7_05);
  uint16_t opt = 10;
  ASSERT_TRUE(coap_signal_set_bad_csm(&packet, opt));

  uint16_t actual = 0;
  ASSERT_TRUE(coap_signal_get_bad_csm(&packet, &actual));
  ASSERT_EQ(opt, actual);
}

/*
 * @API: coap_signal_get_bad_csm()
 * @Description: Tries to get bad csm option for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalGetBadCsmTest_N)
{
  coap_packet_t packet{};
  uint16_t opt;
  ASSERT_FALSE(coap_signal_get_bad_csm(&packet, &opt));
}

/*
 * @API: coap_signal_set_bad_csm()
 * @Description: Tries to set bad csm option for signal packet
 * @PassCondition: Should set bad csm option
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetBadCsmTest_P)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, ABORT_7_05);

  uint16_t opt = 10;
  ASSERT_TRUE(coap_signal_set_bad_csm(&packet, opt));

  uint16_t actual = 0;
  ASSERT_TRUE(coap_signal_get_bad_csm(&packet, &actual));
  ASSERT_EQ(opt, actual);
}

/*
 * @API: coap_signal_set_bad_csm()
 * @Description: Tries to set bad csm option for signal packet
 * @PassCondition: Should get failure status
 * @PreCondition: N/A
 * @PostCondition: N/A
 */
TEST_F(TestCoapSignal, SignalSetBadCsmTest_N)
{
  coap_packet_t packet{};
  uint16_t opt = 10;
  ASSERT_FALSE(coap_signal_set_bad_csm(&packet, opt));
}

TEST_F(TestCoapSignal, SignalSerializeParseTest_CSM)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, CSM_7_01);

  uint32_t size = 1152;
  coap_signal_set_max_msg_size(&packet, size);
  coap_signal_set_blockwise_transfer(&packet, 1);

  std::vector<uint8_t> buffer;
  buffer.reserve(OC_PDU_SIZE);
  size_t buffer_len =
    coap_serialize_message(&packet, buffer.data(), buffer.capacity());

  coap_packet_t parse_packet{};
  coap_status_t ret =
    coap_tcp_parse_message(&parse_packet, buffer.data(), buffer_len, false);

  ASSERT_EQ(COAP_NO_ERROR, ret);
  ASSERT_EQ(packet.code, parse_packet.code);
  ASSERT_EQ(packet.max_msg_size, parse_packet.max_msg_size);
  ASSERT_EQ(packet.blockwise_transfer, parse_packet.blockwise_transfer);
}

TEST_F(TestCoapSignal, SignalSerializeParseTest_PING)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, PING_7_02);
  coap_signal_set_custody(&packet, 1);

  std::vector<uint8_t> buffer;
  buffer.reserve(OC_PDU_SIZE);
  size_t buffer_len =
    coap_serialize_message(&packet, buffer.data(), buffer.capacity());

  coap_packet_t parse_packet{};
  coap_status_t ret =
    coap_tcp_parse_message(&parse_packet, buffer.data(), buffer_len, false);

  ASSERT_EQ(COAP_NO_ERROR, ret);
  ASSERT_EQ(packet.code, parse_packet.code);
  ASSERT_EQ(packet.custody, parse_packet.custody);
}

TEST_F(TestCoapSignal, SignalSerializeParseTest_PONG)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, PONG_7_03);
  coap_signal_set_custody(&packet, 1);

  std::vector<uint8_t> buffer;
  buffer.reserve(OC_PDU_SIZE);
  size_t buffer_len =
    coap_serialize_message(&packet, buffer.data(), buffer.capacity());

  coap_packet_t parse_packet{};
  coap_status_t ret =
    coap_tcp_parse_message(&parse_packet, buffer.data(), buffer_len, false);

  ASSERT_EQ(COAP_NO_ERROR, ret);
  ASSERT_EQ(packet.code, parse_packet.code);
  ASSERT_EQ(packet.custody, parse_packet.custody);
}

TEST_F(TestCoapSignal, SignalSerializeParseTest_RELEASE)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, RELEASE_7_04);

  std::string addr = "coap+tcp://127.0.0.1:5683";
  coap_signal_set_alt_addr(&packet, addr.c_str(), addr.length() + 1);
  uint32_t hold_off = 10;
  ASSERT_TRUE(coap_signal_set_hold_off(&packet, hold_off));

  std::vector<uint8_t> buffer;
  buffer.reserve(OC_PDU_SIZE);
  size_t buffer_len =
    coap_serialize_message(&packet, buffer.data(), buffer.capacity());

  coap_packet_t parse_packet{};
  coap_status_t ret =
    coap_tcp_parse_message(&parse_packet, buffer.data(), buffer_len, false);

  ASSERT_EQ(COAP_NO_ERROR, ret);
  ASSERT_EQ(packet.code, parse_packet.code);
  ASSERT_STREQ(packet.alt_addr, parse_packet.alt_addr);
  ASSERT_EQ(packet.alt_addr_len, parse_packet.alt_addr_len);
  ASSERT_EQ(packet.hold_off, parse_packet.hold_off);
}

TEST_F(TestCoapSignal, SignalSerializeParseTest_ABORT)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, ABORT_7_05);

  uint16_t bad_csm_opt = 10;
  coap_signal_set_bad_csm(&packet, bad_csm_opt);

  std::vector<uint8_t> diagnostic{ 'B', 'A', 'D', ' ', 'C', 'S', 'M', ' ',
                                   'O', 'P', 'T', 'I', 'O', 'N', '\0' };
  coap_set_payload(&packet, diagnostic.data(),
                   static_cast<uint32_t>(diagnostic.size()));

  std::vector<uint8_t> buffer;
  buffer.reserve(OC_PDU_SIZE);
  size_t buffer_len =
    coap_serialize_message(&packet, buffer.data(), buffer.capacity());

  coap_packet_t parse_packet{};
  coap_status_t ret =
    coap_tcp_parse_message(&parse_packet, buffer.data(), buffer_len, false);

  ASSERT_EQ(COAP_NO_ERROR, ret);
  ASSERT_EQ(packet.code, parse_packet.code);
  ASSERT_EQ(packet.bad_csm_opt, parse_packet.bad_csm_opt);
  ASSERT_STREQ((char *)diagnostic.data(), (char *)parse_packet.payload);
}

#endif /* OC_TCP && IPV4 */

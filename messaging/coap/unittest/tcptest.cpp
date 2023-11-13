/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ***************************************************************************/

#include "util/oc_features.h"

#ifdef OC_TCP

#include "messaging/coap/coap_internal.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/options_internal.h"

#include <array>
#include <gtest/gtest.h>

TEST(CoapTCP, ParseLength_0)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];

  // case 0: header size 0-12
  auto uri = std::string(4, 'a');
  coap_options_set_uri_path(&packet, uri.c_str(), uri.length());
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  size_t message_length;
  uint8_t num_extended_length_bytes;
  ASSERT_TRUE(coap_tcp_parse_message_length(
    &buffer[0], buffer.size(), &message_length, &num_extended_length_bytes));
  EXPECT_EQ(message_length, hdr.length + hdr.extended_length);
  EXPECT_EQ(num_extended_length_bytes, hdr.num_extended_length_bytes);
}

TEST(CoapTCP, ParseLength_1)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];

  // case 1: header size 13-268
  auto uri = std::string(13, 'a');
  coap_options_set_uri_path(&packet, uri.c_str(), uri.length());
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  size_t message_length;
  uint8_t num_extended_length_bytes;
  ASSERT_TRUE(coap_tcp_parse_message_length(
    &buffer[0], buffer.size(), &message_length, &num_extended_length_bytes));
  EXPECT_EQ(message_length,
            COAP_TCP_EXTENDED_LENGTH_1_DEFAULT_LEN + hdr.extended_length);
  EXPECT_EQ(num_extended_length_bytes, hdr.num_extended_length_bytes);
}

TEST(CoapTCP, ParseLength_2)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];

  // case 2: header size 269-65804
  auto uri = std::string(269, 'a');
  coap_options_set_uri_path(&packet, uri.c_str(), uri.length());
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  size_t message_length;
  uint8_t num_extended_length_bytes;
  ASSERT_TRUE(coap_tcp_parse_message_length(
    &buffer[0], buffer.size(), &message_length, &num_extended_length_bytes));
  EXPECT_EQ(message_length,
            COAP_TCP_EXTENDED_LENGTH_2_DEFAULT_LEN + hdr.extended_length);
  EXPECT_EQ(num_extended_length_bytes, hdr.num_extended_length_bytes);
}

TEST(CoapTCP, ParseLength_3)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];

  // case 3: header size 65805-
  auto uri = std::string(65805, 'a');
  coap_options_set_uri_path(&packet, uri.c_str(), uri.length());
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  size_t message_length;
  uint8_t num_extended_length_bytes;
  ASSERT_TRUE(coap_tcp_parse_message_length(
    &buffer[0], buffer.size(), &message_length, &num_extended_length_bytes));
  EXPECT_EQ(message_length,
            COAP_TCP_EXTENDED_LENGTH_3_DEFAULT_LEN + hdr.extended_length);
  EXPECT_EQ(num_extended_length_bytes, hdr.num_extended_length_bytes);
}

TEST(CoapTCP, ParseLength_Fail)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];

  // case 2: header size 269-65804
  auto uri = std::string(269, 'a');
  coap_options_set_uri_path(&packet, uri.c_str(), uri.length());
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  std::array<uint8_t, 1> corrupted{};
  // take the first byte with the length, but don't take the extended bytes
  corrupted[0] = packet.buffer[0];
  size_t message_length;
  uint8_t num_extended_length_bytes;
  EXPECT_FALSE(coap_tcp_parse_message_length(&corrupted[0], corrupted.size(),
                                             &message_length,
                                             &num_extended_length_bytes));
}

TEST(CoapTCP, GetPacketSize)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  EXPECT_EQ(COAP_TCP_DEFAULT_HEADER_LEN,
            coap_tcp_get_packet_size(&buffer[0], buffer.size()));
}

TEST(CoapTCP, GetPacketSize_Fail)
{
  coap_packet_t packet{};
  coap_tcp_init_message(&packet, COAP_GET);
  std::array<uint8_t, 8> buffer{};
  packet.buffer = &buffer[0];

  // case 1: header size 13-268
  auto uri = std::string(13, 'a');
  coap_options_set_uri_path(&packet, uri.c_str(), uri.length());
  auto hdr = coap_calculate_header_size(&packet, true, true, false, 0);
  coap_tcp_set_header_length(&packet, hdr.num_extended_length_bytes, hdr.length,
                             hdr.extended_length);

  std::array<uint8_t, 1> corrupted{};
  // take the first byte with the length, but don't take the extended bytes
  corrupted[0] = packet.buffer[0];
  EXPECT_EQ(-1, coap_tcp_get_packet_size(&corrupted[0], corrupted.size()));
}

#endif /* OC_TCP */

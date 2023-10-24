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

#include "messaging/coap/coap_internal.h"
#include "messaging/coap/options_internal.h"
#include "tests/gtest/Device.h"

#include <cstring>
#include <gtest/gtest.h>
#include <string>

class TestOptions : public testing::Test {};

TEST_F(TestOptions, GetContentFormat)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_CONTENT_FORMAT));
  auto content_format = APPLICATION_NOT_DEFINED;
  EXPECT_FALSE(coap_options_get_content_format(&packet, &content_format));
  EXPECT_EQ(APPLICATION_NOT_DEFINED, content_format);
}

TEST_F(TestOptions, SetContentFormat)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_CONTENT_FORMAT));
  coap_options_set_content_format(&packet, APPLICATION_CBOR);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_CONTENT_FORMAT));
  auto content_format = APPLICATION_NOT_DEFINED;
  EXPECT_TRUE(coap_options_get_content_format(&packet, &content_format));
  EXPECT_EQ(APPLICATION_CBOR, content_format);

  // unset Content-Format
  UNSET_OPTION(&packet, COAP_OPTION_CONTENT_FORMAT);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_CONTENT_FORMAT));
  content_format = APPLICATION_NOT_DEFINED;
  EXPECT_FALSE(coap_options_get_content_format(&packet, &content_format));
  EXPECT_EQ(APPLICATION_NOT_DEFINED, content_format);
}

TEST_F(TestOptions, GetAccept)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ACCEPT));
  auto accept = APPLICATION_NOT_DEFINED;
  EXPECT_FALSE(coap_options_get_accept(&packet, &accept));
  EXPECT_EQ(APPLICATION_NOT_DEFINED, accept);
}

TEST_F(TestOptions, SetAccept)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ACCEPT));
  coap_options_set_accept(&packet, APPLICATION_CBOR);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_ACCEPT));
  auto accept = APPLICATION_NOT_DEFINED;
  EXPECT_TRUE(coap_options_get_accept(&packet, &accept));
  EXPECT_EQ(APPLICATION_CBOR, accept);

  // unset Accept
  UNSET_OPTION(&packet, COAP_OPTION_ACCEPT);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ACCEPT));
  accept = APPLICATION_NOT_DEFINED;
  EXPECT_FALSE(coap_options_get_accept(&packet, &accept));
  EXPECT_EQ(APPLICATION_NOT_DEFINED, accept);
}

TEST_F(TestOptions, GetMaxAge)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_MAX_AGE));
  uint32_t max_age = 0;
  EXPECT_FALSE(coap_options_get_max_age(&packet, &max_age));
  EXPECT_EQ(COAP_DEFAULT_MAX_AGE, max_age);
}

TEST_F(TestOptions, SetMaxAge)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_MAX_AGE));
  coap_options_set_max_age(&packet, 1234);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_MAX_AGE));
  uint32_t max_age;
  EXPECT_TRUE(coap_options_get_max_age(&packet, &max_age));
  EXPECT_EQ(1234, max_age);

  // unset Max-Age
  UNSET_OPTION(&packet, COAP_OPTION_MAX_AGE);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_MAX_AGE));
  max_age = 0;
  EXPECT_FALSE(coap_options_get_max_age(&packet, &max_age));
  EXPECT_EQ(COAP_DEFAULT_MAX_AGE, max_age);
}

TEST_F(TestOptions, GetETag)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  const uint8_t *etag;
  EXPECT_EQ(0, coap_options_get_etag(&packet, &etag));
}

TEST_F(TestOptions, SetETag)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  std::vector<uint8_t> etag{ 0x01, 0x02, 0x03, 0x04 };
  EXPECT_EQ(etag.size(),
            coap_options_set_etag(&packet, etag.data(), etag.size()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  const uint8_t *etag_out = nullptr;
  size_t etag_out_len = coap_options_get_etag(&packet, &etag_out);
  EXPECT_EQ(etag.size(), etag_out_len);
  EXPECT_TRUE(memcmp(etag.data(), etag_out, etag.size()) == 0);

  // truncate too long value to COAP_ETAG_LEN
  std::vector<uint8_t> etag2(COAP_ETAG_LEN + 1, 0x42);
  size_t etag2_len = coap_options_set_etag(&packet, etag2.data(),
                                           static_cast<uint8_t>(etag2.size()));
  EXPECT_GT(etag2.size(), etag2_len);
  etag_out_len = coap_options_get_etag(&packet, &etag_out);
  EXPECT_EQ(COAP_ETAG_LEN, etag_out_len);
  EXPECT_TRUE(memcmp(etag2.data(), etag_out, COAP_ETAG_LEN) == 0);

  // unset ETag
  UNSET_OPTION(&packet, COAP_OPTION_ETAG);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_ETAG));
  etag_out = nullptr;
  EXPECT_EQ(0, coap_options_get_etag(&packet, &etag_out));
  EXPECT_EQ(nullptr, etag_out);
}

TEST_F(TestOptions, GetProxyURI)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_PROXY_URI));
  const char *proxy_uri = nullptr;
  EXPECT_EQ(0, coap_options_get_proxy_uri(&packet, &proxy_uri));
  EXPECT_EQ(nullptr, proxy_uri);
}

TEST_F(TestOptions, SetProxyURI)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_PROXY_URI));
  std::string proxy_uri = "coap://[::1]:1234";
  EXPECT_EQ(
    proxy_uri.length(),
    coap_options_set_proxy_uri(&packet, proxy_uri.c_str(), proxy_uri.length()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_PROXY_URI));
  const char *proxy_uri_out = nullptr;
  size_t proxy_uri_out_len =
    coap_options_get_proxy_uri(&packet, &proxy_uri_out);
  EXPECT_EQ(proxy_uri.length(), proxy_uri_out_len);
  EXPECT_TRUE(memcmp(proxy_uri.c_str(), proxy_uri_out, proxy_uri.length()) ==
              0);

  // unset Proxy-URI
  UNSET_OPTION(&packet, COAP_OPTION_PROXY_URI);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_PROXY_URI));
  proxy_uri_out = nullptr;
  EXPECT_EQ(0, coap_options_get_proxy_uri(&packet, &proxy_uri_out));
  EXPECT_EQ(nullptr, proxy_uri_out);
}

TEST_F(TestOptions, GetURIPath)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_URI_PATH));
  const char *uri_path = nullptr;
  EXPECT_EQ(0, coap_options_get_uri_path(&packet, &uri_path));
  EXPECT_EQ(nullptr, uri_path);
}

TEST_F(TestOptions, SetURIPath)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_URI_PATH));

  // absolute URI path
  std::string uri_path = "/a/b/c";
  size_t prefix_len = 1; // skip the single leading '/'
  EXPECT_EQ(
    uri_path.substr(prefix_len).length(),
    coap_options_set_uri_path(&packet, uri_path.c_str(), uri_path.length()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_URI_PATH));
  const char *uri_path_out = nullptr;
  size_t uri_path_out_len = coap_options_get_uri_path(&packet, &uri_path_out);
  EXPECT_EQ(uri_path.substr(prefix_len).length(), uri_path_out_len);
  EXPECT_TRUE(memcmp(uri_path.substr(prefix_len).c_str(), uri_path_out,
                     uri_path_out_len) == 0);

  // relative URI path
  uri_path = "a/b/c";
  EXPECT_EQ(uri_path.length(), coap_options_set_uri_path(
                                 &packet, uri_path.c_str(), uri_path.length()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_URI_PATH));
  uri_path_out = nullptr;
  uri_path_out_len = coap_options_get_uri_path(&packet, &uri_path_out);
  EXPECT_EQ(uri_path.length(), uri_path_out_len);
  EXPECT_TRUE(memcmp(uri_path.c_str(), uri_path_out, uri_path_out_len) == 0);

  // unset URI-Path
  UNSET_OPTION(&packet, COAP_OPTION_URI_PATH);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_URI_PATH));
  uri_path_out = nullptr;
  EXPECT_EQ(0, coap_options_get_uri_path(&packet, &uri_path_out));
  EXPECT_EQ(nullptr, uri_path_out);
}

TEST_F(TestOptions, GetURIQuery)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_URI_QUERY));
  const char *uri_query = nullptr;
  EXPECT_EQ(0, coap_options_get_uri_query(&packet, &uri_query));
  EXPECT_EQ(nullptr, uri_query);
}

#ifdef OC_CLIENT

TEST_F(TestOptions, SetURIQuery)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_URI_QUERY));

  // URI query with leading '?'
  std::string uri_query = "?a=1&b=2&c=3";
  size_t prefix_len = 1; // skip the single leading '?'
  EXPECT_EQ(
    uri_query.substr(prefix_len).length(),
    coap_options_set_uri_query(&packet, uri_query.c_str(), uri_query.length()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_URI_QUERY));
  const char *uri_query_out = nullptr;
  size_t uri_query_out_len =
    coap_options_get_uri_query(&packet, &uri_query_out);
  EXPECT_EQ(uri_query.substr(prefix_len).length(), uri_query_out_len);
  EXPECT_TRUE(memcmp(uri_query.substr(prefix_len).c_str(), uri_query_out,
                     uri_query_out_len) == 0);

  // URI query without leading '?'
  uri_query = "a=1&b=2&c=3";
  EXPECT_EQ(
    uri_query.length(),
    coap_options_set_uri_query(&packet, uri_query.c_str(), uri_query.length()));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_URI_QUERY));
  uri_query_out = nullptr;
  uri_query_out_len = coap_options_get_uri_query(&packet, &uri_query_out);
  EXPECT_EQ(uri_query.length(), uri_query_out_len);
  EXPECT_TRUE(memcmp(uri_query.c_str(), uri_query_out, uri_query_out_len) == 0);

  // unset URI-Query
  UNSET_OPTION(&packet, COAP_OPTION_URI_QUERY);
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_URI_QUERY));
  uri_query_out = nullptr;
  EXPECT_EQ(0, coap_options_get_uri_query(&packet, &uri_query_out));
  EXPECT_EQ(nullptr, uri_query_out);
}

#endif // OC_CLIENT

TEST_F(TestOptions, GetObserve)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_OBSERVE));
  int32_t observe = -1;
  EXPECT_FALSE(coap_options_get_observe(&packet, &observe));
  EXPECT_EQ(-1, observe);
}

TEST_F(TestOptions, SetObserve)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_OBSERVE));

  int32_t observe = 42;
  coap_options_set_observe(&packet, observe);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_OBSERVE));
  int32_t observe_out = -1;
  EXPECT_TRUE(coap_options_get_observe(&packet, &observe_out));
  EXPECT_EQ(observe, observe_out);
}

TEST_F(TestOptions, GetSize1)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_SIZE1));
  uint32_t size1 = 0;
  EXPECT_FALSE(coap_options_get_size1(&packet, &size1));
  EXPECT_EQ(0, size1);
}

TEST_F(TestOptions, SetSize1)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_SIZE1));

  uint32_t size1 = 42;
  coap_options_set_size1(&packet, size1);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_SIZE1));
  uint32_t size1_out = 0;
  EXPECT_TRUE(coap_options_get_size1(&packet, &size1_out));
  EXPECT_EQ(size1, size1_out);
}

TEST_F(TestOptions, GetSize2)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_SIZE2));
  uint32_t size2 = 0;
  EXPECT_FALSE(coap_options_get_size2(&packet, &size2));
  EXPECT_EQ(0, size2);
}

TEST_F(TestOptions, SetSize2)
{
  coap_packet_t packet{};
  EXPECT_EQ(0, IS_OPTION(&packet, COAP_OPTION_SIZE2));

  uint32_t size2 = 42;
  coap_options_set_size2(&packet, size2);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_SIZE2));
  uint32_t size2_out = 0;
  EXPECT_TRUE(coap_options_get_size2(&packet, &size2_out));
  EXPECT_EQ(size2, size2_out);
}

TEST_F(TestOptions, GetBlock1)
{
  coap_packet_t packet{};
  ASSERT_EQ(0, IS_OPTION(&packet, COAP_OPTION_BLOCK1));
  uint32_t num = UINT32_MAX;
  uint8_t m = UINT8_MAX;
  uint16_t size = UINT16_MAX;
  uint32_t offset = UINT32_MAX;
  EXPECT_FALSE(coap_options_get_block1(&packet, &num, &m, &size, &offset));
  EXPECT_EQ(UINT32_MAX, num);
  EXPECT_EQ(UINT8_MAX, m);
  EXPECT_EQ(UINT16_MAX, size);
}

TEST_F(TestOptions, SetBlock1)
{
  coap_packet_t packet{};
  ASSERT_EQ(0, IS_OPTION(&packet, COAP_OPTION_BLOCK1));

  uint32_t num = 42;
  uint8_t m = 1;
  uint16_t size = 512;
  uint32_t offset = 1337;
  EXPECT_TRUE(coap_options_set_block1(&packet, num, m, size, offset));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_BLOCK1));
  // get all
  uint32_t num_out = UINT32_MAX;
  uint8_t m_out = UINT8_MAX;
  uint16_t size_out = UINT16_MAX;
  uint32_t offset_out = UINT32_MAX;
  EXPECT_TRUE(
    coap_options_get_block1(&packet, &num_out, &m_out, &size_out, &offset_out));
  EXPECT_EQ(num, num_out);
  EXPECT_EQ(m, m_out);
  EXPECT_EQ(size, size_out);
  EXPECT_EQ(offset, offset_out);

  // get only block_num
  num_out = UINT32_MAX;
  EXPECT_TRUE(
    coap_options_get_block1(&packet, &num_out, nullptr, nullptr, nullptr));
  EXPECT_EQ(num, num_out);
  // get only block_more
  m_out = UINT8_MAX;
  EXPECT_TRUE(
    coap_options_get_block1(&packet, nullptr, &m_out, nullptr, nullptr));
  EXPECT_EQ(m, m_out);
  // get only block_size
  size_out = UINT16_MAX;
  EXPECT_TRUE(
    coap_options_get_block1(&packet, nullptr, nullptr, &size_out, nullptr));
  EXPECT_EQ(size, size_out);
  // get only block_offset
  offset_out = UINT32_MAX;
  EXPECT_TRUE(
    coap_options_get_block1(&packet, nullptr, nullptr, nullptr, &offset_out));
  EXPECT_EQ(offset, offset_out);
}

TEST_F(TestOptions, SetBlock1_Fail)
{
  coap_packet_t packet{};
  ASSERT_EQ(0, IS_OPTION(&packet, COAP_OPTION_BLOCK1));

  // invalid num >2^20-1
  uint32_t num = (1 << 20);
  uint8_t m = 1;
  uint16_t size = 512;
  uint32_t offset = 1337;
  EXPECT_FALSE(coap_options_set_block1(&packet, num, m, size, offset));

  // invalid size <16
  num = 42;
  size = 15;
  EXPECT_FALSE(coap_options_set_block1(&packet, num, m, size, offset));

  // invalid size >2048
  size = 2049;
  EXPECT_FALSE(coap_options_set_block1(&packet, num, m, size, offset));
}

TEST_F(TestOptions, GetBlock2)
{
  coap_packet_t packet{};
  ASSERT_EQ(0, IS_OPTION(&packet, COAP_OPTION_BLOCK2));
  uint32_t num = UINT32_MAX;
  uint8_t m = UINT8_MAX;
  uint16_t size = UINT16_MAX;
  uint32_t offset = UINT32_MAX;
  EXPECT_FALSE(coap_options_get_block2(&packet, &num, &m, &size, &offset));
  EXPECT_EQ(UINT32_MAX, num);
  EXPECT_EQ(UINT8_MAX, m);
  EXPECT_EQ(UINT16_MAX, size);
}

TEST_F(TestOptions, SetBlock2)
{
  coap_packet_t packet{};
  ASSERT_EQ(0, IS_OPTION(&packet, COAP_OPTION_BLOCK2));

  uint32_t num = 42;
  uint8_t m = 1;
  uint16_t size = 512;
  uint32_t offset = 1337;
  EXPECT_TRUE(coap_options_set_block2(&packet, num, m, size, offset));
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_BLOCK2));
  // get all
  uint32_t num_out = UINT32_MAX;
  uint8_t m_out = UINT8_MAX;
  uint16_t size_out = UINT16_MAX;
  uint32_t offset_out = UINT32_MAX;
  EXPECT_TRUE(
    coap_options_get_block2(&packet, &num_out, &m_out, &size_out, &offset_out));
  EXPECT_EQ(num, num_out);
  EXPECT_EQ(m, m_out);
  EXPECT_EQ(size, size_out);
  EXPECT_EQ(offset, offset_out);

  // get only block_num
  num_out = UINT32_MAX;
  EXPECT_TRUE(
    coap_options_get_block2(&packet, &num_out, nullptr, nullptr, nullptr));
  EXPECT_EQ(num, num_out);
  // get only block_more
  m_out = UINT8_MAX;
  EXPECT_TRUE(
    coap_options_get_block2(&packet, nullptr, &m_out, nullptr, nullptr));
  EXPECT_EQ(m, m_out);
  // get only block_size
  size_out = UINT16_MAX;
  EXPECT_TRUE(
    coap_options_get_block2(&packet, nullptr, nullptr, &size_out, nullptr));
  EXPECT_EQ(size, size_out);
  // get only block_offset
  offset_out = UINT32_MAX;
  EXPECT_TRUE(
    coap_options_get_block2(&packet, nullptr, nullptr, nullptr, &offset_out));
  EXPECT_EQ(offset, offset_out);
}

TEST_F(TestOptions, SetBlock2_Fail)
{
  coap_packet_t packet{};
  ASSERT_EQ(0, IS_OPTION(&packet, COAP_OPTION_BLOCK2));

  // invalid num >2^20-1
  uint32_t num = (1 << 20);
  uint8_t m = 1;
  uint16_t size = 512;
  uint32_t offset = 1337;
  EXPECT_FALSE(coap_options_set_block2(&packet, num, m, size, offset));

  // invalid size <16
  num = 42;
  size = 15;
  EXPECT_FALSE(coap_options_set_block2(&packet, num, m, size, offset));

  // invalid size >2048
  size = 2049;
  EXPECT_FALSE(coap_options_set_block2(&packet, num, m, size, offset));
}

TEST_F(TestOptions, Block1EncodeAndDecode)
{
  uint32_t num = 42;
  uint8_t m = 1;
  uint16_t size = 512;
  uint32_t block1 = coap_options_block_encode(num, m, size);

  coap_packet_t packet{};
  coap_options_block1_decode(&packet, block1);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_BLOCK1));
  EXPECT_EQ(num, packet.block1_num);
  EXPECT_EQ(m, packet.block1_more);
  EXPECT_EQ(size, packet.block1_size);
  EXPECT_NE(0, packet.block1_offset);

  packet = {};
  num = 1337;
  m = 0;
  size = 1024;
  block1 = coap_options_block_encode(num, m, size);
  coap_options_block1_decode(&packet, block1);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_BLOCK1));
  EXPECT_EQ(num, packet.block1_num);
  EXPECT_EQ(m, packet.block1_more);
  EXPECT_EQ(size, packet.block1_size);
  EXPECT_NE(0, packet.block1_offset);
}

TEST_F(TestOptions, Block2EncodeAndDecode)
{
  uint32_t num = 42;
  uint8_t m = 1;
  uint16_t size = 512;
  uint32_t block2 = coap_options_block_encode(num, m, size);

  coap_packet_t packet{};
  coap_options_block2_decode(&packet, block2);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_BLOCK2));
  EXPECT_EQ(num, packet.block2_num);
  EXPECT_EQ(m, packet.block2_more);
  EXPECT_EQ(size, packet.block2_size);
  EXPECT_NE(0, packet.block2_offset);

  packet = {};
  num = 1337;
  m = 0;
  size = 1024;
  block2 = coap_options_block_encode(num, m, size);
  coap_options_block2_decode(&packet, block2);
  EXPECT_NE(0, IS_OPTION(&packet, COAP_OPTION_BLOCK2));
  EXPECT_EQ(num, packet.block2_num);
  EXPECT_EQ(m, packet.block2_more);
  EXPECT_EQ(size, packet.block2_size);
  EXPECT_NE(0, packet.block2_offset);
}

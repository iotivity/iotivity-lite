/****************************************************************************
 *
 * Copyright (c) 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "api/oc_endpoint_internal.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#include "port/common/oc_ip.h"
#include "port/oc_allocator_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_random.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#include <WinSock2.h>
#endif /* _WIN32 */

using addr4_t = std::array<uint8_t, 4>;
using addr6_t = std::array<uint8_t, 16>;

class TestEndpoint : public testing::Test {
public:
  void SetUp() override
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif /* _WIN32 */
#ifndef OC_DYNAMIC_ALLOCATION
    oc_allocator_mutex_init();
#endif /* !OC_DYNAMIC_ALLOCATION */
  }

  void TearDown() override
  {
#ifndef OC_DYNAMIC_ALLOCATION
    oc_allocator_mutex_destroy();
#endif /* !OC_DYNAMIC_ALLOCATION */

#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }

  static int EndpointCompareAddress(const std::string &addr1,
                                    const std::string &addr2)
  {
    oc_endpoint_t ep1 = oc::endpoint::FromString(addr1);
    oc_endpoint_t ep2 = oc::endpoint::FromString(addr2);
    return oc_endpoint_compare_address(&ep1, &ep2);
  }

  static int EndpointCompare(const std::string &addr1, const std::string &addr2)
  {
    oc_endpoint_t ep1 = oc::endpoint::FromString(addr1);
    oc_endpoint_t ep2 = oc::endpoint::FromString(addr2);
    return oc_endpoint_compare(&ep1, &ep2);
  }
};

TEST_F(TestEndpoint, Alloc)
{
  oc_endpoint_t *ep = oc_new_endpoint();
  oc_free_endpoint(ep);

  oc_free_endpoint(nullptr);
}

TEST_F(TestEndpoint, SetDeviceID)
{
  oc_random_init();
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);

  oc_endpoint_t ep{};
  EXPECT_FALSE(oc_uuid_is_equal(ep.di, uuid));

  oc_endpoint_set_di(&ep, &uuid);
  EXPECT_TRUE(oc_uuid_is_equal(ep.di, uuid));

  oc_random_destroy();
}

TEST_F(TestEndpoint, EndpointFlagsToScheme)
{
  std::array<char, 13> buf;
  buf.fill(0);
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP),
            oc_endpoint_flags_to_scheme(0, buf.data(), buf.size()));
  EXPECT_STREQ(OC_SCHEME_COAP, buf.data());
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP),
            oc_endpoint_flags_to_scheme(0, nullptr, 0));
  EXPECT_EQ(-1, oc_endpoint_flags_to_scheme(0, buf.data(), 0));

  buf.fill(0);
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS),
            oc_endpoint_flags_to_scheme(SECURED, buf.data(), buf.size()));
  EXPECT_STREQ(OC_SCHEME_COAPS, buf.data());
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS),
            oc_endpoint_flags_to_scheme(SECURED, nullptr, 0));
  EXPECT_EQ(-1, oc_endpoint_flags_to_scheme(SECURED, buf.data(), 0));

#ifdef OC_TCP
  buf.fill(0);
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP_TCP),
            oc_endpoint_flags_to_scheme(TCP, buf.data(), buf.size()));
  EXPECT_STREQ(OC_SCHEME_COAP_TCP, buf.data());
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAP_TCP),
            oc_endpoint_flags_to_scheme(TCP, nullptr, 0));
  EXPECT_EQ(-1, oc_endpoint_flags_to_scheme(TCP, buf.data(), 0));

  buf.fill(0);
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS_TCP),
            oc_endpoint_flags_to_scheme(SECURED | TCP, buf.data(), buf.size()));
  EXPECT_STREQ(OC_SCHEME_COAPS_TCP, buf.data());
  EXPECT_EQ(OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS_TCP),
            oc_endpoint_flags_to_scheme(SECURED | TCP, nullptr, 0));
  EXPECT_EQ(-1, oc_endpoint_flags_to_scheme(SECURED | TCP, buf.data(), 0));
#endif /* OC_TCP */
}

TEST_F(TestEndpoint, EndpointToCStringInvalid)
{
  oc_endpoint_t ep = oc::endpoint::FromString("coap://[::1]:42");
  // cannot fit scheme
  std::array<char, 1> too_small{};
  EXPECT_EQ(-1, oc_endpoint_to_cstring(&ep, &too_small[0], too_small.size()));

  // can fit scheme but not address
  std::array<char, OC_CHAR_ARRAY_LEN(OC_SCHEME_COAPS_TCP) + 1> too_small2{};
  EXPECT_EQ(-1, oc_endpoint_to_cstring(&ep, &too_small2[0], too_small2.size()));
}

TEST_F(TestEndpoint, EndpointToStringInvalid)
{
  EXPECT_EQ(-1, oc_endpoint_to_string(nullptr, nullptr));

  oc_string_t ep_str{};
  EXPECT_EQ(-1, oc_endpoint_to_string(nullptr, &ep_str));

  oc_endpoint_t ep{};
  EXPECT_EQ(-1, oc_endpoint_to_string(&ep, nullptr));

  EXPECT_EQ(-1, oc_endpoint_to_string(&ep, &ep_str));
}

TEST_F(TestEndpoint, StringToEndpointInvalid)
{
  EXPECT_EQ(-1, oc_string_to_endpoint(nullptr, nullptr, nullptr));

  oc_string_t ep_str{};
  EXPECT_EQ(-1, oc_string_to_endpoint(&ep_str, nullptr, nullptr));

  oc_endpoint_t ep{};
  EXPECT_EQ(-1, oc_string_to_endpoint(&ep_str, &ep, nullptr));

  /* bad format */
  std::vector<std::string> espu = {
    "http://1.1.1.1:56789", "coap://1.1.1.1:abc", "coap://1.1.1.1:56789abc",
    "coap://[::ffff:192.0.2.1]:1", // embedded ipv4 in ipv6 not supported
  };
  for (size_t i = 0; i < espu.size(); i++) {
    oc_new_string(&ep_str, espu[i].c_str(), espu[i].length());
    oc_string_t uri{};

    memset(&ep, 0, sizeof(ep));
    int ret = oc_string_to_endpoint(&ep_str, &ep, &uri);
    EXPECT_EQ(ret, -1) << "espu[" << i << "] " << espu[i];
    EXPECT_TRUE(oc_endpoint_is_empty(&ep));
    EXPECT_EQ(nullptr, oc_string(uri));

    oc_free_string(&ep_str);
    oc_free_string(&uri);
  }
}

TEST_F(TestEndpoint, IPv6AddressToStringFail)
{
  constexpr std::string_view ENDPOINT_ADDR = "[fe80:123::1]:42";
  std::string ep_str = "coap://" + std::string(ENDPOINT_ADDR);

  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);
  std::array<char, 1> too_small{};
  EXPECT_EQ(-1, oc_ipv6_address_and_port_to_string(
                  &ep.addr.ipv6, too_small.data(), too_small.size()));

  std::array<char, sizeof("fe80:123::1") - 1> too_small2{};
  EXPECT_EQ(-1, oc_ipv6_address_and_port_to_string(
                  &ep.addr.ipv6, too_small2.data(), too_small2.size()));

  std::array<char, sizeof(ENDPOINT_ADDR) - 1> too_small3{};
  EXPECT_EQ(-1, oc_ipv6_address_and_port_to_string(
                  &ep.addr.ipv6, too_small3.data(), too_small3.size()));
}

TEST_F(TestEndpoint, IPv6AddressToString)
{
  constexpr std::string_view ENDPOINT_ADDR = "[::1]:42";
  std::string ep_str = "coap://" + std::string(ENDPOINT_ADDR);
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);

  std::array<char, sizeof(ENDPOINT_ADDR)> exact{};
  EXPECT_EQ(8, oc_ipv6_address_and_port_to_string(&ep.addr.ipv6, exact.data(),
                                                  exact.size()));
  EXPECT_STREQ(ENDPOINT_ADDR.data(), exact.data());

  std::array<char, 256> larger{};
  EXPECT_EQ(8, oc_ipv6_address_and_port_to_string(&ep.addr.ipv6, larger.data(),
                                                  larger.size()));
  EXPECT_STREQ(ENDPOINT_ADDR.data(), larger.data());
}

TEST_F(TestEndpoint, EndpointToString64Invalid)
{
  EXPECT_FALSE(oc_endpoint_to_string64(nullptr, nullptr));

  oc_string64_t ep_str{};
  EXPECT_FALSE(oc_endpoint_to_string64(nullptr, &ep_str));

  oc_endpoint_t ep{};
  EXPECT_FALSE(oc_endpoint_to_string64(&ep, nullptr));

  EXPECT_FALSE(oc_endpoint_to_string64(&ep, &ep_str));
}

TEST_F(TestEndpoint, IPv6EndpointToString64)
{
  constexpr std::string_view ENDPOINT_ADDR = "[::1]:42";
  std::string ep_str = "coap://" + std::string(ENDPOINT_ADDR);
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);

  oc_string64_t ep_str64{};
  oc_endpoint_to_string64(&ep, &ep_str64);
  EXPECT_EQ(15, oc_string_len(ep_str64));
  EXPECT_EQ(15, strlen(oc_string(ep_str64)));
  EXPECT_STREQ(ep_str.c_str(), oc_string(ep_str64));
}

#ifdef OC_IPV4

TEST_F(TestEndpoint, IPv4AddressToStringFail)
{
  constexpr std::string_view ENDPOINT_ADDR = "127.0.0.1:80";
  std::string ep_str = "coap://" + std::string(ENDPOINT_ADDR);
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);
  std::array<char, 1> too_small{};
  EXPECT_EQ(-1, oc_ipv4_address_and_port_to_string(
                  &ep.addr.ipv4, too_small.data(), too_small.size()));

  std::array<char, sizeof("127.0.0.1")> too_small2{};
  EXPECT_EQ(-1, oc_ipv4_address_and_port_to_string(
                  &ep.addr.ipv4, too_small2.data(), too_small2.size()));
}

TEST_F(TestEndpoint, IPv4AddressToString)
{
  constexpr std::string_view ENDPOINT_ADDR = "127.0.0.1:80";
  std::string ep_str = "coap://" + std::string(ENDPOINT_ADDR);
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);
  std::array<char, sizeof(ENDPOINT_ADDR)> exact{};
  EXPECT_EQ(12, oc_ipv4_address_and_port_to_string(&ep.addr.ipv4, exact.data(),
                                                   exact.size()));
  EXPECT_STREQ(ENDPOINT_ADDR.data(), exact.data());

  std::array<char, 256> larger{};
  EXPECT_EQ(12, oc_ipv4_address_and_port_to_string(&ep.addr.ipv4, larger.data(),
                                                   larger.size()));
  EXPECT_STREQ(ENDPOINT_ADDR.data(), larger.data());
}

TEST_F(TestEndpoint, IPv4EndpointToString64)
{
  constexpr std::string_view ENDPOINT_ADDR = "127.0.0.1:80";
  std::string ep_str = "coap://" + std::string(ENDPOINT_ADDR);
  oc_endpoint_t ep = oc::endpoint::FromString(ep_str);

  EXPECT_FALSE(oc_endpoint_to_string64(&ep, nullptr));

  oc_string64_t ep_str64{};
  EXPECT_TRUE(oc_endpoint_to_string64(&ep, &ep_str64));
  EXPECT_EQ(19, oc_string_len(ep_str64));
  EXPECT_EQ(19, strlen(oc_string(ep_str64)));
  EXPECT_STREQ(ep_str.c_str(), oc_string(ep_str64));
}

#endif /* OC_IPV4 */

TEST_F(TestEndpoint, StringToEndpoint)
{
  std::vector<std::string> spu0 = {
    "coap://[2001:0000:85a3:0000:1319:8a2e:0370:7344]:1337",
    "coap://[0000:0000:85a3:0000:1319:8a2e:0370:7344]:1337",
    "coap://[0000:85a3:0000:0000:1319:8a2e:0000:0000]:1337",
  };

  std::vector<std::string> exp = {
    "coap://[2001:0:85a3:0:1319:8a2e:370:7344]:1337",
    "coap://[::85a3:0:1319:8a2e:370:7344]:1337",
    "coap://[0:85a3::1319:8a2e:0:0]:1337",
  };
  ASSERT_EQ(spu0.size(), exp.size());

  for (size_t i = 0; i < spu0.size(); ++i) {
    oc_endpoint_t ep = oc::endpoint::FromString(spu0[i]);

    oc_string_t ep_str{};
    EXPECT_EQ(0, oc_endpoint_to_string(&ep, &ep_str));
    EXPECT_STREQ(exp[i].c_str(), oc_string(ep_str));
    oc_free_string(&ep_str);

    oc_string64_t ep_str64{};
    EXPECT_TRUE(oc_endpoint_to_string64(&ep, &ep_str64));
    EXPECT_STREQ(exp[i].c_str(), oc_string(ep_str64));

    std::array<char, 64> ep_buf{};
    EXPECT_EQ(exp[i].length(),
              oc_endpoint_to_cstring(&ep, &ep_buf[0], ep_buf.size()));
    EXPECT_STREQ(exp[i].c_str(), ep_buf.data());
  }
}

#ifdef OC_IPV4
TEST_F(TestEndpoint, StringToEndpointIPv4)
{
  std::string spu0 = { "coaps://10.211.55.3:56789/a/light" };
  oc_endpoint_t ep{};
  oc_string_t uri{};
  int ret = oc::endpoint::FromString(spu0, &ep, &uri);
  EXPECT_EQ(ret, 0) << "spu0 " << spu0;

  EXPECT_TRUE(ep.flags & IPV4);
  EXPECT_TRUE(ep.flags & SECURED);
  EXPECT_FALSE(ep.flags & TCP);
  EXPECT_EQ(ep.addr.ipv4.port, 56789);
  EXPECT_STREQ(oc_string(uri), "/a/light");
  addr4_t addr = { 10, 211, 55, 3 };
  EXPECT_EQ(0, memcmp(ep.addr.ipv4.address, addr.data(), addr.size()));

  oc_free_string(&uri);
}
#endif /* OC_IPV4 */

#ifdef OC_TCP
TEST_F(TestEndpoint, StringToEndpointTCP)
{
#ifdef OC_IPV4
  std::vector<std::string> spu2 = {
    "coaps+tcp://10.211.55.3/a/light",
    "coap+tcp://1.2.3.4:2568",
  };
  for (size_t i = 0; i < spu2.size(); i++) {
    oc_endpoint_t ep{};
    oc_string_t uri{};
    int ret = oc::endpoint::FromString(spu2[i], &ep, &uri);
    EXPECT_EQ(ret, 0) << "spu2[" << i << "] " << spu2[i];

    switch (i) {
    case 0: {
      EXPECT_TRUE(ep.flags & IPV4);
      EXPECT_TRUE(ep.flags & SECURED);
      EXPECT_TRUE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 5684);
      EXPECT_STREQ(oc_string(uri), "/a/light");
      addr4_t addr = { 10, 211, 55, 3 };
      EXPECT_EQ(0, memcmp(ep.addr.ipv4.address, addr.data(), addr.size()));
    } break;
    case 1: {
      EXPECT_TRUE(ep.flags & IPV4);
      EXPECT_FALSE(ep.flags & SECURED);
      EXPECT_TRUE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 2568);
      EXPECT_EQ(oc_string_len(uri), 0);
      addr4_t addr = { 1, 2, 3, 4 };
      EXPECT_EQ(0, memcmp(ep.addr.ipv4.address, addr.data(), addr.size()));
    } break;
    default:
      break;
    }
    oc_free_string(&uri);
  }
#endif /* OC_IPV4 */
  std::vector<std::string> spu3 = {
    "coaps+tcp://openconnectivity.org:3456",
    "coap+tcp://[ff02::158]",
    "coaps+tcp://[ff02::158]/a/light",
    "coaps+tcp://[fe80::12]:2439/a/light",
  };
  for (size_t i = 0; i < spu3.size(); i++) {
    oc_endpoint_t ep{};
    oc_string_t uri{};
    int ret = oc::endpoint::FromString(spu3[i], &ep, &uri);
    switch (i) {
    case 0:
#if defined(OC_IPV4) || defined(OC_DNS_LOOKUP_IPV6)
      EXPECT_EQ(ret, 0) << "spu3[" << i << "] " << spu3[i];
#else
      EXPECT_EQ(ret, -1) << "spu3[" << i << "] " << spu3[i];
#endif /* OC_IPV4 || OC_DNS_LOOKUP_IPV6  */
      break;
    default:
      EXPECT_EQ(ret, 0) << "spu3[" << i << "] " << spu3[i];
      break;
    }

    switch (i) {
    case 0:
#if defined(OC_IPV4) || defined(OC_DNS_LOOKUP_IPV6)
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
      ASSERT_TRUE(ep.flags & SECURED);
      ASSERT_TRUE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 3456);
      EXPECT_EQ(oc_string_len(uri), 0);
#endif /* OC_IPV4 || OC_DNS_LOOKUP_IPV6  */
      break;
    case 1: {
      ASSERT_TRUE(ep.flags & IPV6);
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_TRUE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv6.port, 5683);
      EXPECT_EQ(oc_string_len(uri), 0);
      addr6_t addr = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                       0,    0,    0, 0, 0, 0, 0x01, 0x58 };
      EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr.data(), addr.size()));
    } break;
    case 2: {
      ASSERT_TRUE(ep.flags & IPV6);
      ASSERT_TRUE(ep.flags & SECURED);
      ASSERT_TRUE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv6.port, 5684);
      addr6_t addr = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                       0,    0,    0, 0, 0, 0, 0x01, 0x58 };
      EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr.data(), addr.size()));
      EXPECT_STREQ(oc_string(uri), "/a/light");
    } break;
    case 3: {
      ASSERT_TRUE(ep.flags & IPV6);
      ASSERT_TRUE(ep.flags & SECURED);
      ASSERT_TRUE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv6.port, 2439);
      addr6_t addr = {
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12
      };
      EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr.data(), addr.size()));
      EXPECT_STREQ(oc_string(uri), "/a/light");
    } break;
    default:
      break;
    }
    oc_free_string(&uri);
  }

  // test dns lookup when uri is NULL
  std::vector<std::string> spu4 = {
#ifdef OC_IPV4
    "coap://10.211.55.3:56789/a/light",
    "coaps+tcp://10.211.55.3/a/light",
#endif /* OC_IPV4 */
#if defined(OC_IPV4) || defined(OC_DNS_LOOKUP_IPV6)
    "coap://openconnectivity.org/alpha",
    "coaps://openconnectivity.org:3456/alpha",
#endif /* OC_IPV4 || OC_DNS_LOOKUP_IPV6 */
  };
  for (size_t i = 0; i < spu4.size(); i++) {
    oc_endpoint_t ep{};
    int ret = oc::endpoint::FromString(spu4[i], &ep, nullptr);
    EXPECT_EQ(ret, 0) << "spu4[" << i << "] " << spu4[i];
  }
}
#endif /* OC_TCP */

TEST_F(TestEndpoint, DNSStringToEndpoint)
{
  std::vector<std::string> spu1 = {
    "coap://openconnectivity.org",
    "coap://openconnectivity.org/alpha",
    "coaps://openconnectivity.org:3456/alpha",
  };
  for (size_t i = 0; i < spu1.size(); i++) {
    oc_endpoint_t ep{};
    oc_string_t uri{};
    int ret = oc::endpoint::FromString(spu1[i], &ep, &uri);
#if defined(OC_IPV4) || defined(OC_DNS_LOOKUP_IPV6)
    EXPECT_EQ(ret, 0) << "spu1[" << i << "] " << spu1[i];

    switch (i) {
    case 0:
#ifdef OC_IPV4
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
#endif /* OC_IPV4 */
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
#ifdef OC_IPV4
      EXPECT_EQ(ep.addr.ipv4.port, 5683);
#endif /* OC_IPV4 */
      EXPECT_EQ(oc_string_len(uri), 0);
      break;
    case 1:
#ifdef OC_IPV4
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
#endif /* OC_IPV4 */
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
#ifdef OC_IPV4
      EXPECT_EQ(ep.addr.ipv4.port, 5683);
#endif /* OC_IPV4 */
      EXPECT_STREQ(oc_string(uri), "/alpha");
      break;
    case 2:
#ifdef OC_IPV4
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
#endif /* OC_IPV4 */
      ASSERT_TRUE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
#ifdef OC_IPV4
      EXPECT_EQ(ep.addr.ipv4.port, 3456);
#endif /* OC_IPV4 */
      EXPECT_STREQ(oc_string(uri), "/alpha");
      break;
    default:
      break;
    }
#else  /* !OC_IPV4 && !OC_DNS_LOOKUP_IPV6 */
    EXPECT_EQ(ret, -1) << "spu1[" << i << "] " << spu1[i];
    EXPECT_TRUE(oc_endpoint_is_empty(&ep));
    EXPECT_EQ(nullptr, oc_string(uri));
#endif /* OC_IPV4 || OC_DNS_LOOKUP_IPV6 */

    oc_free_string(&uri);
  }
}

TEST_F(TestEndpoint, EndpointStringParsePath)
{
  std::vector<std::string> spu = { "coaps://10.211.55.3:56789/a/light",
                                   "coap://openconnectivity.org",
                                   "coap://openconnectivity.org/alpha",
                                   "coaps://openconnectivity.org:3456/alpha",
                                   "coaps+tcp://10.211.55.3/a/light",
                                   "coap+tcp://1.2.3.4:2568",
                                   "coaps+tcp://openconnectivity.org:3456",
                                   "coap+tcp://[ff02::158]",
                                   "coaps+tcp://[ff02::158]/a/light",
                                   "coaps+tcp://[fe80::12]:2439/a/light",
                                   "coaps+tcp://[fe80::12]:2439/a/light?s=100",
                                   "coap://0/foo" };
  for (size_t i = 0; i < spu.size(); i++) {
    int ret = -1;
    oc_string_t s;
    oc_new_string(&s, spu[i].c_str(), spu[i].length());
    oc_string_t path;
    memset(&path, 0, sizeof(oc_string_t));
    switch (i) {
    case 0:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/a/light");
      break;
    case 1:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(-1, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_EQ(nullptr, path.ptr);
      break;
    case 2:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/alpha");
      break;
    case 3:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/alpha");
      break;
    case 4:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/a/light");
      break;
    case 5:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(-1, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_EQ(nullptr, path.ptr);
      break;
    case 6:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(-1, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_EQ(nullptr, path.ptr);
      break;
    case 7:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(-1, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_EQ(nullptr, path.ptr);
      break;
    case 8:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/a/light");
      break;
    case 9:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/a/light");
      break;
    case 10:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/a/light");
      break;
    case 11:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(0, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_STREQ(oc_string(path), "/foo");
      break;
    default:
      break;
    }
    oc_free_string(&s);
    oc_free_string(&path);
  }

  // paths with expected errors
  std::vector<std::string> spu2 = {
    "coaps://",                        // no address
    "coaps:/10.211.55.3:56789/a/light" // missing ://
  };
  for (size_t i = 0; i < spu2.size(); i++) {
    oc_string_t s;
    oc_new_string(&s, spu2[i].c_str(), spu2[i].length());
    oc_string_t path;
    memset(&path, 0, sizeof(oc_string_t));

    int ret = oc_endpoint_string_parse_path(&s, &path);
    EXPECT_EQ(-1, ret) << "spu2[" << i << "] " << spu2[i];

    oc_free_string(&s);
    oc_free_string(&path);
  }

  oc_string_t path;
  int ret = oc_endpoint_string_parse_path(nullptr, &path);
  EXPECT_EQ(-1, ret);
  if (-1 != ret) {
    // If code is working as expected this should never run.
    oc_free_string(&path);
  }

  std::string spu3 = "coap://0/p";
  oc_string_t s;
  oc_new_string(&s, spu3.c_str(), spu3.length());
  EXPECT_EQ(-1, oc_endpoint_string_parse_path(&s, nullptr)) << "spu3 " << spu3;
  oc_free_string(&s);
}

TEST_F(TestEndpoint, EndpointPortFail)
{
  oc_endpoint_t ep{};
  EXPECT_EQ(-1, oc_endpoint_port(&ep));
}

TEST_F(TestEndpoint, EndpointPort)
{
  std::vector<std::string> spu = {
    "coap://[::1]:42",
#ifdef OC_IPV4
    "coap://127.0.0.1:42",
#endif /* OC_IPV4 */
  };
  for (const auto &addr : spu) {
    oc_endpoint_t ep = oc::endpoint::FromString(addr);
    EXPECT_EQ(42, oc_endpoint_port(&ep));
  }
}

TEST_F(TestEndpoint, IsEmpty)
{
  oc_endpoint_t endpoint{};
  EXPECT_TRUE(oc_endpoint_is_empty(&endpoint));

  std::string ep_str = "coap://[ff02::158]";
  EXPECT_EQ(0, oc::endpoint::FromString(ep_str, &endpoint, nullptr));
  EXPECT_FALSE(oc_endpoint_is_empty(&endpoint));
}

TEST_F(TestEndpoint, IsIPv6LinkLocal)
{
  EXPECT_EQ(-1, oc_ipv6_endpoint_is_link_local(nullptr));

  oc_endpoint_t ep_empty{};
  EXPECT_EQ(-1, oc_ipv6_endpoint_is_link_local(&ep_empty));

  std::vector<std::string> addrs_nonLL = {
#ifdef OC_IPV4
    "coap://10.211.55.3", "coap://1.2.3.4:2568",
#endif /* OC_IPV4 */
    "coap://[ff02::158]", "coap://[ff02::158]/a/light",
    "coap://[fe81::]",    "coap://[fd80::]",
  };

  for (const auto &addr : addrs_nonLL) {
    oc_endpoint_t ep{};
    EXPECT_EQ(0, oc::endpoint::FromString(addr, &ep, nullptr));
    EXPECT_EQ(-1, oc_ipv6_endpoint_is_link_local(&ep));
  }

  std::vector<std::string> addrs_LL = {
    "coap://[fe80::]",
    "coap://[fe80::12]:2439",
    "coap://[fe80::45]:6789/a/light?s=100",
  };

  for (const auto &addr : addrs_LL) {
    oc_endpoint_t ep{};
    EXPECT_EQ(0, oc::endpoint::FromString(addr, &ep, nullptr));
    EXPECT_EQ(0, oc_ipv6_endpoint_is_link_local(&ep));
  }
}

TEST_F(TestEndpoint, CompareAddress)
{
  oc_endpoint_t ep{};
  EXPECT_EQ(-1, oc_endpoint_compare_address(&ep, nullptr));
  EXPECT_EQ(-1, oc_endpoint_compare_address(nullptr, &ep));
  EXPECT_EQ(-1, oc_endpoint_compare_address(&ep, &ep));

  EXPECT_EQ(-1, EndpointCompareAddress("coap://[fe80::]", "coap://[::]"));
  EXPECT_EQ(0, EndpointCompareAddress("coap://[fe80::]:42", "coap://[fe80::]"));
  EXPECT_EQ(0, EndpointCompareAddress("coap://[fe80::]", "coap://[fe80::]"));
  EXPECT_EQ(
    0, EndpointCompareAddress("coap://[fe80::]:1337", "coap://[fe80::]:1337"));
}

#ifdef OC_IPV4
TEST_F(TestEndpoint, CompareAddressIPv4)
{
  EXPECT_EQ(-1, EndpointCompareAddress("coap://127.0.0.1", "coap://[::1]"));
  EXPECT_EQ(-1,
            EndpointCompareAddress("coap://127.0.0.1", "coap://192.168.1.1"));

  EXPECT_EQ(
    0, EndpointCompareAddress("coap://127.0.0.1:12", "coap://127.0.0.1:43"));
  EXPECT_EQ(0, EndpointCompareAddress("coap://127.0.0.1", "coap://127.0.0.1"));
  EXPECT_EQ(0, EndpointCompareAddress("coap://127.0.0.1:1337",
                                      "coap://127.0.0.1:1337"));
}
#endif /* OC_IPV4 */

TEST_F(TestEndpoint, Compare)
{
  oc_endpoint_t ep{};
  EXPECT_EQ(-1, oc_endpoint_compare(&ep, nullptr));
  EXPECT_EQ(-1, oc_endpoint_compare(nullptr, &ep));
  EXPECT_EQ(-1, oc_endpoint_compare(&ep, &ep));

  EXPECT_EQ(-1, EndpointCompare("coap://[fe80::]", "coap://[::]"));
  EXPECT_EQ(-1, EndpointCompare("coap://[fe80::]:42", "coap://[fe80::]"));
  EXPECT_EQ(0, EndpointCompare("coap://[fe80::]", "coap://[fe80::]"));
  EXPECT_EQ(0, EndpointCompare("coap://[fe80::]:1337", "coap://[fe80::]:1337"));
}

#ifdef OC_IPV4
TEST_F(TestEndpoint, ComparePv4)
{
  EXPECT_EQ(-1, EndpointCompare("coap://127.0.0.1", "coap://[::1]"));
  EXPECT_EQ(-1, EndpointCompare("coap://127.0.0.1", "coap://192.168.1.1"));
  EXPECT_EQ(-1, EndpointCompare("coap://127.0.0.1:12", "coap://127.0.0.1:43"));

  EXPECT_EQ(0, EndpointCompare("coap://127.0.0.1", "coap://127.0.0.1"));
  EXPECT_EQ(0,
            EndpointCompare("coap://127.0.0.1:1337", "coap://127.0.0.1:1337"));
}
#endif /* OC_IPV4 */

TEST_F(TestEndpoint, ListCopy)
{
  oc_endpoint_t *eps_copy = nullptr;
  EXPECT_EQ(0, oc_endpoint_list_copy(&eps_copy, nullptr));

  oc_endpoint_t model = oc::endpoint::FromString("coap://[ff02::158]");
  auto make_endpoint_list = [&model](size_t size) {
    oc_endpoint_t *head = nullptr;
    for (size_t i = 0; i < size; ++i) {
      oc_endpoint_t *ep = oc_new_endpoint();
      oc_endpoint_copy(ep, &model);
      ep->next = head;
      head = ep;
    }
    return head;
  };
#ifdef OC_DYNAMIC_ALLOCATION
  size_t size = 4;
  oc_endpoint_t *eps = make_endpoint_list(size);

  eps_copy = nullptr;
  int ret = oc_endpoint_list_copy(&eps_copy, eps);
  EXPECT_EQ(size, ret);

  oc_endpoint_list_free(eps_copy);
  oc_endpoint_list_free(eps);
#else  /* !OC_DYNAMIC_ALLOCATION */
  oc_endpoint_t *eps = make_endpoint_list(OC_MAX_NUM_ENDPOINTS);
  eps_copy = nullptr;
  int ret = oc_endpoint_list_copy(&eps_copy, eps);
  EXPECT_EQ(-1, ret);
  oc_endpoint_list_free(eps);

  eps = make_endpoint_list((OC_MAX_NUM_ENDPOINTS / 2) + 1);
  eps_copy = nullptr;
  ret = oc_endpoint_list_copy(&eps_copy, eps);
  EXPECT_EQ(-1, ret);
  oc_endpoint_list_free(eps);

  size_t size = (OC_MAX_NUM_ENDPOINTS - 1) / 2;
  eps = make_endpoint_list(size);
  eps_copy = nullptr;
  ret = oc_endpoint_list_copy(&eps_copy, eps);
  EXPECT_EQ(size, ret);
  oc_endpoint_list_free(eps);
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestEndpoint, EndpointHostInvalid)
{
  oc_endpoint_t ep{};
  std::array<char, OC_IPV6_MAXADDRSTRLEN> buffer{};
  EXPECT_EQ(-1, oc_endpoint_host(&ep, buffer.data(), buffer.size()));
}

TEST_F(TestEndpoint, EndpointHost)
{
  std::vector<std::string> addrs = {
    "coap://[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080",
    "coap://[ff02:0000:0000:0000:0000:0000:0000:0158]:5683",
    "coap://[fe80:0000:0000:0000:0042:04ff:febd:9875]:38558",
#ifdef OC_TCP
    "coap+tcp://[2001:db8::1]:5678",
    "coap+tcp://[fe80::1]:1234",
#endif /* OC_TCP */
#ifdef OC_SECURITY
    "coaps://[2001:db8:0:0:0:ff00:42:8329]",
#endif /* OC_SECURITY */
    "coap://[::1]",
  };
  std::vector<std::string> expected = {
    "2001:db8:85a3::8a2e:370:7334",
    "ff02::158",
    "fe80::42:4ff:febd:9875",
#ifdef OC_TCP
    "2001:db8::1",
    "fe80::1",
#endif /* OC_TCP */
#ifdef OC_SECURITY
    "2001:db8::ff00:42:8329",
#endif /* OC_SECURITY */
    "::1",
  };

  ASSERT_EQ(addrs.size(), expected.size());

  for (size_t i = 0; i < addrs.size(); ++i) {
    oc_endpoint_t ep = oc::endpoint::FromString(addrs[i]);
    std::array<char, OC_IPV6_MAXADDRSTRLEN> buffer{};
    EXPECT_LT(0, oc_endpoint_host(&ep, buffer.data(), buffer.size()));
    EXPECT_STREQ(expected[i].c_str(), buffer.data());
  }

#ifdef OC_IPV4
  addrs = {
    "coap://10.211.55.3:8080",
#ifdef OC_SECURITY
    "coaps://1.2.3.4",
#endif /* OC_SECURITY */

#ifdef OC_TCP
    "coap+tcp://192.193.194.195:1234",
#endif /* OC_TCP */
  };
  expected = {
    "10.211.55.3",
#ifdef OC_SECURITY
    "1.2.3.4",
#endif /* OC_SECURITY */
#ifdef OC_TCP
    "192.193.194.195",
#endif /* OC_TCP */
  };
  ASSERT_EQ(addrs.size(), expected.size());

  for (size_t i = 0; i < addrs.size(); ++i) {
    oc_endpoint_t ep = oc::endpoint::FromString(addrs[i]);
    std::array<char, OC_IPV4_MAXADDRSTRLEN> buffer{};
    EXPECT_LT(0, oc_endpoint_host(&ep, buffer.data(), buffer.size()));
    EXPECT_STREQ(expected[i].c_str(), buffer.data());
  }
#endif /* OC_IPV4 */
}

#ifdef OC_CLIENT

static constexpr size_t kDeviceID{ 0 };

class TestEndpointWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

TEST_F(TestEndpointWithServer, SetLocalAddressFail)
{
  oc_endpoint_t ep{};
  oc_endpoint_set_local_address(&ep, UINT32_MAX);
  EXPECT_TRUE(oc_endpoint_is_empty(&ep));
}

TEST_F(TestEndpointWithServer, SetLocalAddress)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  std::array<char, sizeof(ep.addr_local)> addr_empty{};
  ASSERT_EQ(0, memcmp(&ep.addr_local, &addr_empty[0], sizeof(ep.addr_local)));

  // oc_endpoint_set_local_address should modify only the output parameter,
  // which is a local copy in this test case, so the global endpoints shouldn't
  // be modified
  auto checkEndpoints = [](size_t device) {
    oc_endpoint_t *eps = oc_connectivity_get_endpoints(device);
    while (eps != nullptr) {
      EXPECT_NE(0, memcmp(&eps->addr, &eps->addr_local, sizeof(eps->addr)));
      eps = eps->next;
    }
  };

  oc_endpoint_set_local_address(&ep, ep.interface_index);
  EXPECT_NE(0, memcmp(&ep.addr_local, &addr_empty[0], sizeof(ep.addr_local)));
  checkEndpoints(kDeviceID);
}

#endif /* OC_CLIENT */

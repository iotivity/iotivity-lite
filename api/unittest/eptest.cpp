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

#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include "oc_uuid.h"
#include "port/oc_random.h"

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>
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
  }

  void TearDown() override
  {
#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }

  static int EndpointFromString(const std::string &addr, oc_endpoint_t *ep,
                                oc_string_t *uri)
  {
    oc_string_t s;
    oc_new_string(&s, addr.c_str(), addr.length());
    int ret = oc_string_to_endpoint(&s, ep, uri);
    oc_free_string(&s);
    return ret;
  }

  static int EndpointCompareAddress(const std::string &addr1,
                                    const std::string &addr2)
  {
    oc_endpoint_t ep1{};
    EXPECT_EQ(0, EndpointFromString(addr1, &ep1, nullptr));
    oc_endpoint_t ep2{};
    EXPECT_EQ(0, EndpointFromString(addr2, &ep2, nullptr));
    return oc_endpoint_compare_address(&ep1, &ep2);
  }

  static int EndpointCompare(const std::string &addr1, const std::string &addr2)
  {
    oc_endpoint_t ep1{};
    EXPECT_EQ(0, EndpointFromString(addr1, &ep1, nullptr));
    oc_endpoint_t ep2{};
    EXPECT_EQ(0, EndpointFromString(addr2, &ep2, nullptr));
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

TEST_F(TestEndpoint, StringToEndpointInvalid)
{
  /* bad format */
  std::vector<const char *> espu = {
    nullptr,
    "",
    "http://1.1.1.1:56789",
    "coap://1.1.1.1:abc",
    "coap://1.1.1.1:56789abc",
  };
  for (size_t i = 0; i < espu.size(); i++) {
    oc_string_t s;
    oc_new_string(&s, espu[i], espu[i] != nullptr ? strlen(espu[i]) : 0);
    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(oc_endpoint_t));
    oc_string_t uri;
    memset(&uri, 0, sizeof(oc_string_t));

    int ret = oc_string_to_endpoint(&s, &ep, &uri);
    EXPECT_EQ(ret, -1) << "espu[" << i << "] "
                       << (espu[i] != nullptr ? espu[i] : "NULL");
    EXPECT_TRUE(oc_endpoint_is_empty(&ep));
    EXPECT_EQ(nullptr, oc_string(uri));

    oc_free_string(&s);
    oc_free_string(&uri);
  }
}

#ifdef OC_IPV4
TEST_F(TestEndpoint, StringToEndpointIPv4)
{
  std::string spu0 = { "coaps://10.211.55.3:56789/a/light" };
  oc_endpoint_t ep{};
  oc_string_t uri{};
  int ret = EndpointFromString(spu0, &ep, &uri);
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
    int ret = EndpointFromString(spu2[i], &ep, &uri);
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
    int ret = EndpointFromString(spu3[i], &ep, &uri);
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
    int ret = EndpointFromString(spu4[i], &ep, nullptr);
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
    int ret = EndpointFromString(spu1[i], &ep, &uri);
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

TEST_F(TestEndpoint, IsEmpty)
{
  oc_endpoint_t endpoint{};
  EXPECT_TRUE(oc_endpoint_is_empty(&endpoint));

  std::string ep_str = "coap://[ff02::158]";
  EXPECT_EQ(0, EndpointFromString(ep_str, &endpoint, nullptr));
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
    EXPECT_EQ(0, EndpointFromString(addr, &ep, nullptr));
    EXPECT_EQ(-1, oc_ipv6_endpoint_is_link_local(&ep));
  }

  std::vector<std::string> addrs_LL = {
    "coap://[fe80::]",
    "coap://[fe80::12]:2439",
    "coap://[fe80::45]:6789/a/light?s=100",
  };

  for (const auto &addr : addrs_LL) {
    oc_endpoint_t ep{};
    EXPECT_EQ(0, EndpointFromString(addr, &ep, nullptr));
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

  oc_endpoint_t model;
  EXPECT_EQ(0, EndpointFromString("coap://[ff02::158]", &model, nullptr));

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

/*
// Copyright (c) 2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "gtest/gtest.h"
#include <cstdlib>

#include "oc_endpoint.h"

TEST(OCEndpoints, StringToEndpoint)
{
  const char *spu[4] = { "coaps://10.211.55.3:56789/a/light",
                          "coap://openconnectivity.org",
                          "coap://openconnectivity.org/alpha",
                          "coaps://openconnectivity.org:3456/alpha" };
  for (int i = 0; i < 4; i++) {
    oc_string_t s;
    oc_new_string(&s, spu[i], strlen(spu[i]));
    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(oc_endpoint_t));
    oc_string_t uri;
    memset(&uri, 0, sizeof(oc_string_t));

    int ret = oc_string_to_endpoint(&s, &ep, &uri);
    EXPECT_EQ(ret, 0) << "spu[" << i << "] " << spu[i];

    switch (i) {
    case 0: {
      EXPECT_TRUE(ep.flags & IPV4);
      EXPECT_TRUE(ep.flags & SECURED);
      EXPECT_FALSE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 56789);
      EXPECT_STREQ(oc_string(uri), "/a/light");
      uint8_t addr[4] = { 10, 211, 55, 3 };
      EXPECT_EQ(0, memcmp(ep.addr.ipv4.address, addr, 4));
    } break;
    case 1:
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 5683);
      EXPECT_EQ(oc_string_len(uri), 0);
      break;
    case 2:
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 5683);
      EXPECT_STREQ(oc_string(uri), "/alpha");
      break;
    case 3:
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
      ASSERT_TRUE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 3456);
      EXPECT_STREQ(oc_string(uri), "/alpha");
      break;
    default:
      break;
    }
    oc_free_string(&s);
    oc_free_string(&uri);
  }

#ifdef OC_TCP
    const char *spu2[6] = { "coaps+tcp://10.211.55.3/a/light",
                            "coap+tcp://1.2.3.4:2568",
                            "coaps+tcp://openconnectivity.org:3456",
                            "coap+tcp://[ff02::158]",
                            "coaps+tcp://[ff02::158]/a/light",
                            "coaps+tcp://[fe80::12]:2439/a/light" };
    for (int i = 0; i < 6; i++) {
      oc_string_t s;
      oc_new_string(&s, spu2[i], strlen(spu2[i]));
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      oc_string_t uri;
      memset(&uri, 0, sizeof(oc_string_t));

      int ret = oc_string_to_endpoint(&s, &ep, &uri);
      EXPECT_EQ(ret, 0) << "spu2[" << i << "] " << spu2[i];

      switch (i) {
      case 0: {
        EXPECT_TRUE(ep.flags & IPV4);
        EXPECT_TRUE(ep.flags & SECURED);
        EXPECT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv4.port, 5684);
        EXPECT_STREQ(oc_string(uri), "/a/light");
        uint8_t addr[4] = { 10, 211, 55, 3 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv4.address, addr, 4));
      } break;
      case 1: {
        EXPECT_TRUE(ep.flags & IPV4);
        EXPECT_FALSE(ep.flags & SECURED);
        EXPECT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv4.port, 2568);
        EXPECT_EQ(oc_string_len(uri), 0);
        uint8_t addr[4] = { 1, 2, 3, 4 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv4.address, addr, 4));
      } break;
      case 2:
        ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
        ASSERT_TRUE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv4.port, 3456);
        EXPECT_EQ(oc_string_len(uri), 0);
        break;
      case 3: {
        ASSERT_TRUE(ep.flags & IPV6);
        ASSERT_FALSE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv6.port, 5683);
        EXPECT_EQ(oc_string_len(uri), 0);
        uint8_t addr[16] = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                             0,    0,    0, 0, 0, 0, 0x01, 0x58 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr, 16));
      } break;
      case 4: {
        ASSERT_TRUE(ep.flags & IPV6);
        ASSERT_TRUE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv6.port, 5684);
        uint8_t addr[16] = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                             0,    0,    0, 0, 0, 0, 0x01, 0x58 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr, 16));
        EXPECT_STREQ(oc_string(uri), "/a/light");
      } break;
      case 5: {
        ASSERT_TRUE(ep.flags & IPV6);
        ASSERT_TRUE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv6.port, 2439);
        uint8_t addr[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                             0,    0,    0, 0, 0, 0, 0, 0x12 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr, 16));
        EXPECT_STREQ(oc_string(uri), "/a/light");
      } break;
      default:
        break;
      }
      oc_free_string(&s);
      oc_free_string(&uri);
    }

    // test dns lookup when uri is NULL
    const char *spu3[4] = { "coap://10.211.55.3:56789/a/light",
                           "coaps+tcp://10.211.55.3/a/light",
                           "coap://openconnectivity.org/alpha",
                           "coaps://openconnectivity.org:3456/alpha" };
    for (int i = 0; i < 4; i++) {
      oc_string_t s;
      oc_new_string(&s, spu3[i], strlen(spu[i]));
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      int ret = oc_string_to_endpoint(&s, &ep, NULL);
      EXPECT_EQ(ret, 0) << "spu3[" << i << "] " << spu3[i];
    }
#endif


}

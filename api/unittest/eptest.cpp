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
#include "oc_helpers.h"

TEST(OCEndpoints, StringToEndpoint)
{
#ifdef OC_IPV4
  const char *spu0[1] = { "coaps://10.211.55.3:56789/a/light" };
    for (int i = 0; i < 1; i++) {
      oc_string_t s;
      oc_new_string(&s, spu0[i], strlen(spu0[i]));
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      oc_string_t uri;
      memset(&uri, 0, sizeof(oc_string_t));

      int ret = oc_string_to_endpoint(&s, &ep, &uri);
      EXPECT_EQ(ret, 0) << "spu0[" << i << "] " << spu0[i];

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
      default:
        break;
      }
      oc_free_string(&s);
      oc_free_string(&uri);
    }
#endif /* OC_IPV4 */
  const char *spu1[3] = { "coap://openconnectivity.org",
                         "coap://openconnectivity.org/alpha",
                         "coaps://openconnectivity.org:3456/alpha" };
  for (int i = 0; i < 3; i++) {
    oc_string_t s;
    oc_new_string(&s, spu1[i], strlen(spu1[i]));
    oc_endpoint_t ep;
    memset(&ep, 0, sizeof(oc_endpoint_t));
    oc_string_t uri;
    memset(&uri, 0, sizeof(oc_string_t));

    int ret = oc_string_to_endpoint(&s, &ep, &uri);
    EXPECT_EQ(ret, 0) << "spu1[" << i << "] " << spu1[i];

    switch (i) {
    case 0:
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 5683);
      EXPECT_EQ(oc_string_len(uri), 0);
      break;
    case 1:
      ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
      ASSERT_FALSE(ep.flags & SECURED);
      ASSERT_FALSE(ep.flags & TCP);
      EXPECT_EQ(ep.addr.ipv4.port, 5683);
      EXPECT_STREQ(oc_string(uri), "/alpha");
      break;
    case 2:
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
#ifdef OC_IPV4
  const char *spu2[2] = { "coaps+tcp://10.211.55.3/a/light",
                          "coap+tcp://1.2.3.4:2568"};
      for (int i = 0; i < 2; i++) {
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
        default:
          break;
        }
        oc_free_string(&s);
        oc_free_string(&uri);
      }
#endif /* OC_IPV4 */
    const char *spu3[4] = { "coaps+tcp://openconnectivity.org:3456",
                            "coap+tcp://[ff02::158]",
                            "coaps+tcp://[ff02::158]/a/light",
                            "coaps+tcp://[fe80::12]:2439/a/light" };
    for (int i = 0; i < 4; i++) {
      oc_string_t s;
      oc_new_string(&s, spu3[i], strlen(spu3[i]));
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      oc_string_t uri;
      memset(&uri, 0, sizeof(oc_string_t));

      int ret = oc_string_to_endpoint(&s, &ep, &uri);
      EXPECT_EQ(ret, 0) << "spu3[" << i << "] " << spu3[i];

      switch (i) {
      case 0:
        ASSERT_TRUE((ep.flags & IPV4) || (ep.flags & IPV6));
        ASSERT_TRUE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv4.port, 3456);
        EXPECT_EQ(oc_string_len(uri), 0);
        break;
      case 1: {
        ASSERT_TRUE(ep.flags & IPV6);
        ASSERT_FALSE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv6.port, 5683);
        EXPECT_EQ(oc_string_len(uri), 0);
        uint8_t addr[16] = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                             0,    0,    0, 0, 0, 0, 0x01, 0x58 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr, 16));
      } break;
      case 2: {
        ASSERT_TRUE(ep.flags & IPV6);
        ASSERT_TRUE(ep.flags & SECURED);
        ASSERT_TRUE(ep.flags & TCP);
        EXPECT_EQ(ep.addr.ipv6.port, 5684);
        uint8_t addr[16] = { 0xff, 0x02, 0, 0, 0, 0, 0,    0,
                             0,    0,    0, 0, 0, 0, 0x01, 0x58 };
        EXPECT_EQ(0, memcmp(ep.addr.ipv6.address, addr, 16));
        EXPECT_STREQ(oc_string(uri), "/a/light");
      } break;
      case 3: {
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
    const char *spu4[4] = { "coap://10.211.55.3:56789/a/light",
                           "coaps+tcp://10.211.55.3/a/light",
                           "coap://openconnectivity.org/alpha",
                           "coaps://openconnectivity.org:3456/alpha" };
    for (int i = 0; i < 4; i++) {
      oc_string_t s;
      oc_new_string(&s, spu4[i], strlen(spu4[i]));
      oc_endpoint_t ep;
      memset(&ep, 0, sizeof(oc_endpoint_t));
      int ret = oc_string_to_endpoint(&s, &ep, NULL);
      EXPECT_EQ(ret, 0) << "spu4[" << i << "] " << spu4[i];
    }
#endif


}

TEST(OCEndpoints, EndpointStringParsePath)
{
  const char *spu[12] = { "coaps://10.211.55.3:56789/a/light",
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
                         "coap://0/foo"};
  for (int i = 0; i < 12; i++) {
    oc_string_t s;
    oc_string_t path;
    int ret = -1;
    oc_new_string(&s, spu[i], strlen(spu[i]));
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
      EXPECT_EQ(path.ptr, NULL);
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
      EXPECT_EQ(path.ptr, NULL);
      break;
    case 6:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(-1, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_EQ(path.ptr, NULL);
      break;
    case 7:
      ret = oc_endpoint_string_parse_path(&s, &path);
      EXPECT_EQ(-1, ret) << "spu[" << i << "] " << spu[i];
      EXPECT_EQ(path.ptr, NULL);
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


  }

  // paths with expected errors
  const char *spu2[2] = { "coaps://", // no address
                          "coaps:/10.211.55.3:56789/a/light" // missing ://
  };
  for (int i = 0; i < 2; i++) {
    oc_string_t s;
    oc_new_string(&s, spu2[i], strlen(spu2[i]));
    oc_string_t path;
    memset(&path, 0, sizeof(oc_string_t));

    int ret = oc_endpoint_string_parse_path(&s, &path);
    EXPECT_EQ(-1, ret) << "spu2[" << i << "] " << spu2[i];

    oc_free_string(&s);
    oc_free_string(&path);
  }
  {
    oc_string_t path;
    int ret = oc_endpoint_string_parse_path(NULL, &path);
    EXPECT_EQ(-1, ret);
    if (-1 != ret) {
        // If code is working as expected this should never run.
        oc_free_string(&path);
    }
  }
  {
    oc_string_t s;
    oc_new_string(&s, "coap://0/p", strlen("coap://0/p"));
    EXPECT_EQ(-1, oc_endpoint_string_parse_path(&s, NULL));
    oc_free_string(&s);
  }

}

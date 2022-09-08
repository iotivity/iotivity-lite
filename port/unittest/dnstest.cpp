/******************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "oc_config.h"

#ifdef OC_DNS_LOOKUP

#include "port/oc_connectivity.h"
#include "oc_endpoint.h"
#include "oc_helpers.h"
#include <gtest/gtest.h>
#ifdef _WIN32
#include <WinSock2.h>
#endif /* _WIN32 */

class TestDNS : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif /* _WIN32 */
  }

  static void TearDownTestCase()
  {
#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }
};

TEST_F(TestDNS, oc_dns_lookup_invalid)
{
  EXPECT_EQ(-1, oc_dns_lookup("openconnectivity.org", nullptr,
                              static_cast<transport_flags>(0)));

  oc_string_t addr;
  EXPECT_EQ(-1, oc_dns_lookup(nullptr, &addr, static_cast<transport_flags>(0)));

  EXPECT_NE(0, oc_dns_lookup("openconnectivity", &addr,
                             static_cast<transport_flags>(0)));
}

TEST_F(TestDNS, oc_dns_lookup)
{
  oc_string_t addr;
  EXPECT_EQ(0, oc_dns_lookup("localhost", &addr, IPV6));
  oc_free_string(&addr);
}

#ifdef OC_IPV4

TEST_F(TestDNS, oc_dns_lookup_ipv4)
{
  oc_string_t addr;
  EXPECT_EQ(0, oc_dns_lookup("localhost", &addr, IPV4));
  oc_free_string(&addr);
}

#endif /* OC_IPV4 */

#endif /* OC_DNS_LOOKUP */

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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "port/oc_fcntl_internal.h"
#include "tests/gtest/Endpoint.h"

#ifdef OC_TCP
#include "port/oc_tcp_socket_internal.h"
#endif /* OC_TCP */

#ifndef _WIN32
#include "port/common/posix/oc_fcntl_internal.h"
#endif /* !_WIN32 */

#include <fcntl.h>
#include <cstdio>
#include <gtest/gtest.h>
#include <string>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#endif /* _WIN32 */

class TestFcntl : public testing::Test {
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

#ifdef OC_TCP

TEST_F(TestFcntl, SetBlocking)
{
  EXPECT_FALSE(oc_fcntl_set_blocking(OC_INVALID_SOCKET));

  auto ep = oc::endpoint::FromString("coap://[::1]:80");
  oc_tcp_socket_t tcp = oc_tcp_socket_connect(&ep, nullptr);
  ASSERT_NE(-1, tcp.state);
  ASSERT_NE(OC_INVALID_SOCKET, tcp.fd);

  EXPECT_TRUE(oc_fcntl_set_blocking(tcp.fd));

  OC_CLOSE_SOCKET(tcp.fd);
}

TEST_F(TestFcntl, SetNonBlocking)
{
  EXPECT_FALSE(oc_fcntl_set_nonblocking(OC_INVALID_SOCKET));

  auto ep = oc::endpoint::FromString("coap://[::1]:80");
  oc_tcp_socket_t tcp = oc_tcp_socket_connect(&ep, nullptr);
  ASSERT_NE(-1, tcp.state);
  ASSERT_NE(OC_INVALID_SOCKET, tcp.fd);

  EXPECT_TRUE(oc_fcntl_set_nonblocking(tcp.fd));

  OC_CLOSE_SOCKET(tcp.fd);
}

#endif /* OC_TCP */

#ifndef _WIN32

TEST_F(TestFcntl, SetFlags)
{
  // invalid fd
  EXPECT_EQ(-1, oc_fcntl_set_flags(-1, 0, 0));

  std::string file = "./flags";
  FILE *fp = fopen(file.c_str(), "w");
  ASSERT_NE(nullptr, fp);
  int fd = fileno(fp);
  ASSERT_NE(-1, fd);

  int flags = oc_fcntl_set_flags(fd, O_APPEND, 0);
  ASSERT_NE(-1, flags);
  EXPECT_EQ(false, oc_fcntl_set_flags(fd, 0, flags));

  ASSERT_EQ(0, remove(file.c_str()));
}

#endif /* !_WIN32 */

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

#if defined(OC_SECURITY)

#include "oc_api.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "security/oc_pstat.h"
#include "security/oc_tls_internal.h"

#include <gtest/gtest.h>
#include <mbedtls/x509_crt.h>

#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#ifdef _WIN32
#include <WinSock2.h>
#endif /* _WIN32 */

struct Peer
{
  std::string address;
  oc_uuid_t uuid;
  int role;
};

static Peer
createPeer(const std::string &addr, int role)
{
  static size_t peerCount = 0;
  std::ostringstream ostr;
  ostr << std::setfill('0') << std::setw(12) << peerCount;

  std::string uuid = "00000000-0000-0000-0000-" + ostr.str();
  ++peerCount;

  Peer peer{};
  peer.address = addr;
  oc_str_to_uuid(uuid.c_str(), &peer.uuid);
  peer.role = role;
  return peer;
}

class TestTLSPeer : public testing::Test {
#if defined(_WIN32)
#include <windows.h>
  static CRITICAL_SECTION s_mutex;
  static CONDITION_VARIABLE s_cv;
#else
#include <pthread.h>
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
#endif

protected:
  static void SetUpTestCase()
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    InitializeCriticalSection(&s_mutex);
    InitializeConditionVariable(&s_cv);
#endif /* _WIN32 */
  }

  static void TearDownTestCase()
  {
#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }

  void SetUp() override
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    ASSERT_EQ(0, oc_main_init(&s_handler));
    size_t deviceCount = oc_core_get_num_devices();
    ASSERT_LT(0, deviceCount);
    deviceId_ = deviceCount - 1;

    oc_sec_pstat_t *pstat = oc_sec_get_pstat(deviceId_);
    pstat->s = OC_DOS_RFNOP;
  }

  void TearDown() override
  {
    oc_main_shutdown();
  }

public:
  size_t deviceId_{ static_cast<size_t>(-1) };

  static oc_handler_t s_handler;

  static int appInit(void)
  {
    if (oc_init_platform("OCFCloud", nullptr, nullptr) != 0) {
      return -1;
    }
    if (oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                      "ocf.res.1.0.0", nullptr, nullptr) != 0) {
      return -1;
    }
    return 0;
  }

  static void signalEventLoop(void)
  {
#ifdef _WIN32
    WakeConditionVariable(&s_cv);
#else
    pthread_cond_signal(&s_cv);
#endif
  }

  static oc_event_callback_retval_t quitEvent(void *data)
  {
    auto quit = (bool *)data;
    *quit = true;
    return OC_EVENT_DONE;
  }

  static void mutex_lock(void)
  {
#ifdef _WIN32
    EnterCriticalSection(&s_mutex);
#else
    pthread_mutex_lock(&s_mutex);
#endif
  }

  static void mutex_unlock(void)
  {
#ifdef _WIN32
    LeaveCriticalSection(&s_mutex);
#else
    pthread_mutex_unlock(&s_mutex);
#endif
  }

  static void cond_wait(oc_clock_time_t next_event)
  {
#ifdef _WIN32
    if (next_event == 0) {
      SleepConditionVariableCS(&s_cv, &s_mutex, INFINITE);
    } else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(
          &s_cv, &s_mutex,
          (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
#else
    if (next_event == 0) {
      pthread_cond_wait(&s_cv, &s_mutex);
    } else {
      struct timespec ts;
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = static_cast<long>((next_event % OC_CLOCK_SECOND) * 1.e09 /
                                     OC_CLOCK_SECOND);
      pthread_cond_timedwait(&s_cv, &s_mutex, &ts);
    }
#endif
  }

  static void poolEvents(uint16_t seconds)
  {
    bool quit = false;
    oc_set_delayed_callback(&quit, quitEvent, seconds);

    while (true) {
      mutex_lock();
      oc_clock_time_t next_event = oc_main_poll();
      if (quit) {
        mutex_unlock();
        break;
      }
      cond_wait(next_event);
      mutex_unlock();
    }
  }

  static oc_endpoint_t getEndpoint(const std::string &ep)
  {
    oc_string_t ep_str;
    oc_new_string(&ep_str, ep.c_str(), ep.length());
    oc_endpoint_t endpoint;
    EXPECT_EQ(0, oc_string_to_endpoint(&ep_str, &endpoint, nullptr));
    oc_free_string(&ep_str);
    return endpoint;
  }

  static std::vector<Peer> getClients()
  {
    std::vector<Peer> clients{ createPeer("coaps://[ff02::41]:1336",
                                          MBEDTLS_SSL_IS_CLIENT) };
#ifdef OC_IPV4
    clients.emplace_back(
      createPeer("coaps://1.3.3.6:41", MBEDTLS_SSL_IS_CLIENT));
#endif /* OC_IPV4 */

#ifdef OC_TCP
    clients.emplace_back(
      createPeer("coaps+tcp://[ff02::42]:1337", MBEDTLS_SSL_IS_CLIENT));
#ifdef OC_IPV4
    clients.emplace_back(
      createPeer("coaps+tcp://1.3.3.7:42", MBEDTLS_SSL_IS_CLIENT));
#endif /* OC_IPV4 */
#endif /* OC_TCP */

    return clients;
  }

  static std::vector<Peer> getServers()
  {

    std::vector<Peer> servers{ createPeer("coaps://[ff02::43]:1338",
                                          MBEDTLS_SSL_IS_SERVER) };
#ifdef OC_IPV4
    servers.emplace_back(
      createPeer("coaps://1.3.3.8:43", MBEDTLS_SSL_IS_SERVER));
#endif /* OC_IPV4 */

#ifdef OC_TCP
    servers.emplace_back(
      createPeer("coaps+tcp://[ff02::44]:1339", MBEDTLS_SSL_IS_SERVER));
#ifdef OC_IPV4
    servers.emplace_back(
      createPeer("coaps+tcp://1.3.3.9:44", MBEDTLS_SSL_IS_SERVER));
#endif /* OC_IPV4 */
#endif /* OC_TCP */

    return servers;
  }

  static void addPeers(const std::vector<Peer> &peers)
  {
    for (const auto &p : peers) {
      oc_endpoint_t ep = getEndpoint(p.address);
      oc_tls_peer_t *peer = oc_tls_add_peer(&ep, p.role);
      ASSERT_NE(nullptr, peer);
      peer->uuid = p.uuid;
#ifdef OC_PKI
      peer->user_data.data = calloc(1 /* dummy */, 1);
      ASSERT_NE(nullptr, peer->user_data.data);
      peer->user_data.free = free;
#endif /* OC_PKI */
    }
  }
};

oc_handler_t TestTLSPeer::s_handler{};
#ifdef _WIN32
CRITICAL_SECTION TestTLSPeer::s_mutex;
CONDITION_VARIABLE TestTLSPeer::s_cv;
#else
pthread_mutex_t TestTLSPeer::s_mutex;
pthread_cond_t TestTLSPeer::s_cv;
#endif

TEST_F(TestTLSPeer, CountPeers)
{
  ASSERT_EQ(0, oc_tls_num_peers(deviceId_));

  auto endpoints = getClients();
#ifndef OC_DYNAMIC_ALLOCATION
  if (endpoints.size() > OC_MAX_TLS_PEERS) {
    endpoints.resize(OC_MAX_TLS_PEERS);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(endpoints);
  ASSERT_EQ(endpoints.size(), oc_tls_num_peers(deviceId_));
}

TEST_F(TestTLSPeer, GetPeer)
{
  ASSERT_EQ(0, oc_tls_num_peers(deviceId_));
  auto servers = getServers();
#ifndef OC_DYNAMIC_ALLOCATION
  if (servers.size() > OC_MAX_TLS_PEERS) {
    servers.resize(OC_MAX_TLS_PEERS);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(servers);
  ASSERT_EQ(servers.size(), oc_tls_num_peers(deviceId_));

  auto clients = getClients();
  for (const auto &c : clients) {
    oc_endpoint_t ep = getEndpoint(c.address);
    ASSERT_EQ(nullptr, oc_tls_get_peer(&ep));
    ASSERT_EQ(nullptr, oc_tls_get_peer_uuid(&ep));
  }

  for (const auto &s : servers) {
    oc_endpoint_t ep = getEndpoint(s.address);
    const oc_tls_peer_t *peer = oc_tls_get_peer(&ep);
    ASSERT_NE(nullptr, peer);
    ASSERT_EQ(MBEDTLS_SSL_IS_SERVER, peer->role);
    ASSERT_EQ(0, oc_endpoint_compare(&ep, &peer->endpoint));

    const oc_uuid_t *uuid = oc_tls_get_peer_uuid(&ep);
    ASSERT_NE(nullptr, uuid);
    ASSERT_TRUE(oc_uuid_is_equal(s.uuid, *uuid));
  }
}

TEST_F(TestTLSPeer, ClearPeers)
{
  auto clients = getClients();
  auto servers = getServers();

#ifndef OC_DYNAMIC_ALLOCATION
  size_t max_peers = OC_MAX_TLS_PEERS;
  if (clients.size() > max_peers) {
    clients.resize(max_peers);
  }
  max_peers -= clients.size();
  if (servers.size() > max_peers) {
    servers.resize(max_peers);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(clients);
  addPeers(servers);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(deviceId_));

  oc_tls_close_peers([](const oc_tls_peer_t *peer,
                        void *) { return peer->role == MBEDTLS_SSL_IS_CLIENT; },
                     nullptr);
  ASSERT_EQ(servers.size(), oc_tls_num_peers(deviceId_));

  oc_tls_close_peers(nullptr, nullptr);
  ASSERT_EQ(0, oc_tls_num_peers(deviceId_));
}

TEST_F(TestTLSPeer, ResetDeviceImmediately)
{
  auto clients = getClients();
  auto servers = getServers();

#ifndef OC_DYNAMIC_ALLOCATION
  size_t max_peers = OC_MAX_TLS_PEERS;
  if (clients.size() > max_peers) {
    clients.resize(max_peers);
  }
  max_peers -= clients.size();
  if (servers.size() > max_peers) {
    servers.resize(max_peers);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(clients);
  addPeers(servers);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(deviceId_));
  oc_reset();
  poolEvents(1);
  ASSERT_EQ(0, oc_tls_num_peers(deviceId_));
}

TEST_F(TestTLSPeer, ResetDevice)
{
  auto clients = getClients();
  auto servers = getServers();

#ifndef OC_DYNAMIC_ALLOCATION
  size_t max_peers = OC_MAX_TLS_PEERS;
  if (clients.size() > max_peers) {
    clients.resize(max_peers);
  }
  max_peers -= clients.size();
  if (servers.size() > max_peers) {
    servers.resize(max_peers);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(clients);
  addPeers(servers);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(deviceId_));
  oc_reset_v1(false);
  poolEvents(1);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(deviceId_));
  poolEvents(2);
  ASSERT_EQ(0, oc_tls_num_peers(deviceId_));
}

#ifdef OC_PKI
TEST_F(TestTLSPeer, VerifyCertificate)
{
  oc_endpoint_t ep = getEndpoint("coaps://[ff02::43]:1338");
  oc_tls_peer_t *peer = oc_tls_add_peer(&ep, MBEDTLS_SSL_IS_SERVER);
  ASSERT_NE(nullptr, peer);
  ASSERT_NE(nullptr, peer->ssl_conf.f_vrfy);
  ASSERT_EQ(-1, peer->ssl_conf.f_vrfy(nullptr, nullptr, 0, nullptr));

  oc_pki_verify_certificate_cb_t verify_certificate = peer->verify_certificate;
  peer->verify_certificate = nullptr;
  ASSERT_EQ(-1, peer->ssl_conf.f_vrfy(peer, nullptr, 0, nullptr));

  mbedtls_x509_crt crt{};
  peer->verify_certificate = verify_certificate;
  ASSERT_EQ(-1, peer->ssl_conf.f_vrfy(peer, &crt, 1, nullptr));
}
#endif /* OC_PKI */

#endif /* OC_SECURITY */

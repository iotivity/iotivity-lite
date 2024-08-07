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

#include "api/oc_core_res_internal.h"
#include "api/oc_endpoint_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_api.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "port/oc_network_event_handler_internal.h"
#include "port/oc_log_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_svr_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/tls/Peer.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include "gtest/gtest.h"
#include "mbedtls/build_info.h"
#include "mbedtls/x509_crt.h"

#include <array>
#include <string>
#include <vector>

#ifdef _WIN32
#include <WinSock2.h>
#endif /* _WIN32 */

static constexpr size_t kDeviceID{ 0 };
static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };
class TestTLSPeer : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif /* _WIN32 */

    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(),
                               kDeviceName.c_str(), kOCFSpecVersion.c_str(),
                               kOCFDataModelVersion.c_str(), nullptr, nullptr));
    oc_sec_svr_create();

    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;
  }

  static void TearDownTestCase()
  {
    oc_sec_svr_free();
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(0);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();

#ifdef _WIN32
    WSACleanup();
#endif /* _WIN32 */
  }

  void SetUp() override { oc_tls_init_context(); }

  void TearDown() override { oc_tls_shutdown(); }

  static std::vector<oc::tls::Peer> getClients()
  {
    std::vector<oc::tls::Peer> clients{ oc::tls::MakePeer(
      "coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT) };
#ifdef OC_IPV4
    clients.emplace_back(
      oc::tls::MakePeer("coaps://1.3.3.6:41", MBEDTLS_SSL_IS_CLIENT));
#endif /* OC_IPV4 */

#ifdef OC_TCP
    clients.emplace_back(
      oc::tls::MakePeer("coaps+tcp://[ff02::42]:1337", MBEDTLS_SSL_IS_CLIENT));
#ifdef OC_IPV4
    clients.emplace_back(
      oc::tls::MakePeer("coaps+tcp://1.3.3.7:42", MBEDTLS_SSL_IS_CLIENT));
#endif /* OC_IPV4 */
#endif /* OC_TCP */

    return clients;
  }

  static std::vector<oc::tls::Peer> getServers()
  {
    std::vector<oc::tls::Peer> servers{ oc::tls::MakePeer(
      "coaps://[ff02::43]:1338", MBEDTLS_SSL_IS_SERVER) };
#ifdef OC_IPV4
    servers.emplace_back(
      oc::tls::MakePeer("coaps://1.3.3.8:43", MBEDTLS_SSL_IS_SERVER));
#endif /* OC_IPV4 */

#ifdef OC_TCP
    servers.emplace_back(
      oc::tls::MakePeer("coaps+tcp://[ff02::44]:1339", MBEDTLS_SSL_IS_SERVER));
#ifdef OC_IPV4
    servers.emplace_back(
      oc::tls::MakePeer("coaps+tcp://1.3.3.9:44", MBEDTLS_SSL_IS_SERVER));
#endif /* OC_IPV4 */
#endif /* OC_TCP */

    return servers;
  }

  static void addPeers(const std::vector<oc::tls::Peer> &peers)
  {
    for (const auto &p : peers) {
      oc_endpoint_t ep = oc::endpoint::FromString(p.address);
      oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, p.role, nullptr);
      ASSERT_NE(nullptr, peer);
      ASSERT_EQ(p.role, peer->role);
      peer->uuid = p.uuid;
#ifdef OC_PKI
      peer->user_data.data = calloc(1 /* dummy */, 1);
      ASSERT_NE(nullptr, peer->user_data.data);
      peer->user_data.free = free;
#endif /* OC_PKI */
    }
  }
};

TEST_F(TestTLSPeer, CountPeers)
{
  ASSERT_EQ(0, oc_tls_num_peers(0));

  auto endpoints = getClients();
#ifndef OC_DYNAMIC_ALLOCATION
  if (endpoints.size() > OC_MAX_TLS_PEERS) {
    endpoints.resize(OC_MAX_TLS_PEERS);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(endpoints);
  ASSERT_EQ(endpoints.size(), oc_tls_num_peers(kDeviceID));
}

TEST_F(TestTLSPeer, GetPeer)
{
  ASSERT_EQ(0, oc_tls_num_peers(kDeviceID));
  auto servers = getServers();
#ifndef OC_DYNAMIC_ALLOCATION
  if (servers.size() > OC_MAX_TLS_PEERS) {
    servers.resize(OC_MAX_TLS_PEERS);
  }
#endif /* OC_DYNAMIC_ALLOCATION */

  addPeers(servers);
  ASSERT_EQ(servers.size(), oc_tls_num_peers(kDeviceID));

  auto clients = getClients();
  for (const auto &c : clients) {
    oc_endpoint_t ep = oc::endpoint::FromString(c.address);
    ASSERT_EQ(nullptr, oc_tls_get_peer(&ep));
    ASSERT_EQ(nullptr, oc_tls_get_peer_uuid(&ep));
  }

  for (const auto &s : servers) {
    oc_endpoint_t ep = oc::endpoint::FromString(s.address);
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
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(kDeviceID));

  oc_tls_close_peers([](const oc_tls_peer_t *peer,
                        void *) { return peer->role == MBEDTLS_SSL_IS_CLIENT; },
                     nullptr);
  ASSERT_EQ(servers.size(), oc_tls_num_peers(kDeviceID));

  oc_tls_close_peers(nullptr, nullptr);
  ASSERT_EQ(0, oc_tls_num_peers(kDeviceID));
}

#ifdef OC_PKI

TEST_F(TestTLSPeer, VerifyCertificate)
{
  oc_endpoint_t ep = oc::endpoint::FromString("coaps://[ff02::43]:1338");
  oc_tls_peer_t *peer =
    oc_tls_add_or_get_peer(&ep, MBEDTLS_SSL_IS_SERVER, nullptr);
  ASSERT_NE(nullptr, peer);
  ASSERT_EQ(MBEDTLS_SSL_IS_SERVER, peer->role);
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

class TestTLSPeerWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;
  }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void TearDown() override
  {
    oc_tls_close_peers(nullptr, nullptr);
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
    pstat->s = OC_DOS_RFNOP;

    oc::TestDevice::Reset();
  }
};

TEST_F(TestTLSPeerWithServer, ResetDeviceImmediately)
{
  auto clients = TestTLSPeer::getClients();
  auto servers = TestTLSPeer::getServers();

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

  TestTLSPeer::addPeers(clients);
  TestTLSPeer::addPeers(servers);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(kDeviceID));
  oc_reset();
  oc::TestDevice::PoolEventsMs(200);
  ASSERT_EQ(0, oc_tls_num_peers(kDeviceID));
}

TEST_F(TestTLSPeerWithServer, ResetDevice)
{
  auto clients = TestTLSPeer::getClients();
  auto servers = TestTLSPeer::getServers();

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

  TestTLSPeer::addPeers(clients);
  TestTLSPeer::addPeers(servers);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(kDeviceID));
  oc_reset_v1(false);
  oc::TestDevice::PoolEventsMs(500);
  ASSERT_EQ(clients.size() + servers.size(), oc_tls_num_peers(kDeviceID));
  // TLS sessions are closed after 2 seconds
  oc::TestDevice::PoolEvents(2);
  ASSERT_EQ(0, oc_tls_num_peers(kDeviceID));
}

#endif /* OC_SECURITY */

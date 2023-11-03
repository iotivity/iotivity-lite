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

#if defined(OC_SECURITY) && defined(OC_PKI)

#include "api/oc_ri_internal.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "security/oc_certs_generate_internal.h"
#include "security/oc_certs_internal.h"
#include "security/oc_obt_internal.h"
#include "security/oc_roles_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Role.h"
#include "util/oc_macros_internal.h"
#include "util/oc_secure_string_internal.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <string>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

class TestRolesWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_SEC_ROLES, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

    g_uuid = oc_core_get_device_id(kDeviceID);
    ASSERT_NE(nullptr, g_uuid);
#ifdef OC_DYNAMIC_ALLOCATION
    g_root_keypair = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1);
    g_root_credid = generateSelfSignedRootCertificate(
      g_root_keypair, g_root_subject, MBEDTLS_MD_SHA256);
    ASSERT_GT(g_root_credid, 0);
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }

  void TearDown() override
  {
    for (auto &peer : peers_) {
      oc_tls_remove_peer(&peer->endpoint);
    }
    peers_.clear();
  }

  oc_tls_peer_t *addPeer(const oc_endpoint_t *ep);

#ifdef OC_DYNAMIC_ALLOCATION
  static int generateSelfSignedRootCertificate(const oc::keypair_t &kp,
                                               const std::string &subject_name,
                                               mbedtls_md_type_t sig_alg);

  static std::vector<unsigned char> generateRoleCertificatePEM(
    const oc::keypair_t &kp, const oc::Roles &roles,
    const std::string &subject_name, const std::string &issuer_name,
    mbedtls_md_type_t sig_alg);

  static bool addRolesByCertificate(const oc_uuid_t *uuid,
                                    const oc::keypair_t &kp,
                                    const oc::Roles &roles,
                                    const std::string &subject_name,
                                    const oc_endpoint_t *ep);

  static size_t countRoles(const oc_tls_peer_t *peer);
#endif /* OC_DYNAMIC_ALLOCATION */

  std::vector<oc_tls_peer_t *> peers_{};

  static oc_uuid_t *g_uuid;
  static std::string g_root_subject_name;
  static std::string g_root_subject;
  static oc::keypair_t g_root_keypair;
  static int g_root_credid;
};

std::string TestRolesWithServer::g_root_subject_name{ "IoTivity-Lite Test" };
std::string TestRolesWithServer::g_root_subject{ "C=US, O=OCF, CN=" +
                                                 g_root_subject_name };
oc::keypair_t TestRolesWithServer::g_root_keypair{};
int TestRolesWithServer::g_root_credid{ -1 };
oc_uuid_t *TestRolesWithServer::g_uuid{};

oc_tls_peer_t *
TestRolesWithServer::addPeer(const oc_endpoint_t *ep)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  if (pstat == nullptr) {
    return nullptr;
  }
  pstat->s = OC_DOS_RFNOP;
  oc_tls_peer_t *peer =
    oc_tls_add_or_get_peer(ep, MBEDTLS_SSL_IS_SERVER, nullptr);
  pstat->s = OC_DOS_RFOTM;
  if (peer == nullptr) {
    return nullptr;
  }
  memcpy(peer->uuid.id, g_uuid->id, sizeof(g_uuid->id));
  peers_.push_back(peer);
  return peer;
}

#ifdef OC_DYNAMIC_ALLOCATION

static std::vector<unsigned char>
getPEM(std::vector<unsigned char> &data)
{
  auto it =
    std::find(data.begin(), data.end(), static_cast<unsigned char>('\0'));
  size_t data_len =
    std::distance(data.begin(), it) + 1; // size with NULL terminator
  EXPECT_NE(data.end(), it);

  EXPECT_TRUE(oc_certs_is_PEM(&data[0], data_len));
  data.resize(data_len);
  return data;
}

int
TestRolesWithServer::generateSelfSignedRootCertificate(
  const oc::keypair_t &kp, const std::string &subject_name,
  mbedtls_md_type_t sig_alg)
{
  oc_obt_generate_root_cert_data_t cert_data = {
    /*.subject_name = */ subject_name.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.private_key =*/kp.private_key.data(),
    /*.private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/sig_alg,
  };

  return oc_obt_generate_self_signed_root_cert(cert_data, kDeviceID);
}

std::vector<unsigned char>
TestRolesWithServer::generateRoleCertificatePEM(const oc::keypair_t &kp,
                                                const oc::Roles &roles,
                                                const std::string &subject_name,
                                                const std::string &issuer_name,
                                                mbedtls_md_type_t sig_alg)
{
  oc_obt_generate_role_cert_data_t cert_data = {
    /*.roles =*/roles.Head(),
    /*.subject_name =*/subject_name.c_str(),
    /*.public_key =*/kp.public_key.data(),
    /*.public_key_size =*/kp.public_key_size,
    /*.issuer_name =*/issuer_name.c_str(),
    /*.issuer_private_key =*/kp.private_key.data(),
    /*.issuer_private_key_size =*/kp.private_key_size,
    /*.signature_md_alg=*/sig_alg,
  };

  std::vector<unsigned char> cert_buf{};
  cert_buf.resize(4096, '\0');
  EXPECT_EQ(0, oc_obt_generate_role_cert_pem(cert_data, cert_buf.data(),
                                             cert_buf.size()));
  return getPEM(cert_buf);
}

bool
TestRolesWithServer::addRolesByCertificate(const oc_uuid_t *uuid,
                                           const oc::keypair_t &kp,
                                           const oc::Roles &roles,
                                           const std::string &subject_name,
                                           const oc_endpoint_t *ep)
{
  std::array<char, 50> uuid_buf{};
  if (!oc_certs_encode_CN_with_UUID(uuid, uuid_buf.data(), uuid_buf.size())) {
    return false;
  }
  auto role_pem = generateRoleCertificatePEM(kp, roles, uuid_buf.data(),
                                             subject_name, MBEDTLS_MD_SHA256);
  if (role_pem.empty()) {
    return false;
  }

  const oc_resource_t *roles_resource =
    oc_core_get_resource_by_index(OCF_SEC_ROLES, kDeviceID);
  if (roles_resource == nullptr) {
    return false;
  }

  oc::RepPool pool{};
  oc_rep_start_root_object();
  oc_rep_set_array(root, creds);
  oc_rep_object_array_start_item(creds);

  oc_rep_set_int(creds, credtype, OC_CREDTYPE_CERT);
  std::string subjectuuid{ "*" };
  oc_rep_set_text_string_v1(creds, subjectuuid, subjectuuid.c_str(),
                            subjectuuid.length());

  oc_rep_set_object(creds, publicdata);
  oc_rep_set_text_string_v1(publicdata, data,
                            reinterpret_cast<const char *>(&role_pem[0]),
                            role_pem.size() - 1);

  std::string encoding{ OC_ENCODING_PEM_STR };
  oc_rep_set_text_string_v1(publicdata, encoding, encoding.c_str(),
                            encoding.length());
  oc_rep_close_object(creds, publicdata);
  std::string credusage{ OC_CREDUSAGE_ROLE_CERT_STR };
  oc_rep_set_text_string_v1(creds, credusage, credusage.c_str(),
                            credusage.length());
  oc_rep_object_array_end_item(creds);
  oc_rep_close_array(root, creds);
  oc_rep_end_root_object();

  return oc_sec_apply_cred(pool.ParsePayload().get(), roles_resource, ep,
                           nullptr, nullptr) == 0;
}

size_t
TestRolesWithServer::countRoles(const oc_tls_peer_t *peer)
{
  size_t count = 0;
  auto roles = oc_sec_roles_get(peer);
  while (roles != nullptr) {
    ++count;
    roles = roles->next;
  }
  return count;
}

#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestRolesWithServer, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_SEC_ROLES, kDeviceID));
}

TEST_F(TestRolesWithServer, GetResourceByURI)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_uri_v1(
                       OCF_SEC_ROLES_URI, OC_CHAR_ARRAY_LEN(OCF_SEC_ROLES_URI),
                       kDeviceID));
}

#ifdef OC_DYNAMIC_ALLOCATION

TEST_F(TestRolesWithServer, AddRole)
{
  oc::Roles roles{};
  roles.Add("user1", "role1");
  roles.Add("user1", "role2");
  roles.Add("user2", "role3");

  oc_endpoint_t ep = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer = addPeer(&ep);
  ASSERT_NE(nullptr, peer);

  EXPECT_TRUE(
    addRolesByCertificate(g_uuid, g_root_keypair, roles, g_root_subject, &ep));
  EXPECT_EQ(1, countRoles(peer));
}

// using roles with "oic.role" prefix is prohibited, except for those defined in
// g_allowed_roles array
TEST_F(TestRolesWithServer, AddRole_FailAssertion)
{
  oc::Roles roles{};
  roles.Add("oic.role.fail");

  oc_endpoint_t ep = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer = addPeer(&ep);
  ASSERT_NE(nullptr, peer);

  EXPECT_FALSE(
    addRolesByCertificate(g_uuid, g_root_keypair, roles, g_root_subject, &ep));
  EXPECT_EQ(0, countRoles(peer));
}

TEST_F(TestRolesWithServer, AddRole_AssertAllowed)
{
  oc::Roles roles{};
  roles.Add("oic.role.owner");

  oc_endpoint_t ep = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer = addPeer(&ep);
  ASSERT_NE(nullptr, peer);

  EXPECT_TRUE(
    addRolesByCertificate(g_uuid, g_root_keypair, roles, g_root_subject, &ep));
  EXPECT_EQ(1, countRoles(peer));
}

TEST_F(TestRolesWithServer, FreeRole)
{
  oc_endpoint_t ep1 = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer1 = addPeer(&ep1);
  ASSERT_NE(nullptr, peer1);
  oc_sec_cred_t *role1 = oc_sec_roles_add(peer1, kDeviceID);
  ASSERT_NE(nullptr, role1);
  oc_sec_cred_t *role2 = oc_sec_roles_add(peer1, kDeviceID);
  ASSERT_NE(nullptr, role2);

  oc_endpoint_t ep2 = oc::endpoint::FromString("coaps://[::2]:42");
  const auto *peer2 = addPeer(&ep2);
  ASSERT_NE(nullptr, peer2);
  oc_sec_cred_t *role3 = oc_sec_roles_add(peer2, kDeviceID);
  ASSERT_NE(nullptr, role3);

  oc_endpoint_t ep3 = oc::endpoint::FromString("coaps://[::3]:42");
  const auto *peer3 = addPeer(&ep3);
  ASSERT_NE(nullptr, peer3);

  EXPECT_FALSE(oc_sec_free_role(role1, peer3));
  EXPECT_FALSE(oc_sec_free_role(role1, peer2));
  EXPECT_EQ(1, countRoles(peer2));

  EXPECT_EQ(2, countRoles(peer1));
  EXPECT_TRUE(oc_sec_free_role(role1, peer1));
  EXPECT_EQ(1, countRoles(peer1));
  EXPECT_TRUE(oc_sec_free_role(role2, peer1));
  EXPECT_EQ(0, countRoles(peer1));
}

TEST_F(TestRolesWithServer, FreeRoles)
{
  size_t deviceID1 = 1;
  oc_endpoint_t ep1 = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer1 = addPeer(&ep1);
  ASSERT_NE(nullptr, peer1);
  oc_sec_cred_t *role1 = oc_sec_roles_add(peer1, deviceID1);
  ASSERT_NE(nullptr, role1);
  oc_sec_cred_t *role2 = oc_sec_roles_add(peer1, deviceID1);
  ASSERT_NE(nullptr, role2);
  size_t deviceID2 = 2;
  oc_sec_cred_t *role3 = oc_sec_roles_add(peer1, deviceID2);
  ASSERT_NE(nullptr, role3);

  oc_endpoint_t ep2 = oc::endpoint::FromString("coaps://[::2]:42");
  const auto *peer2 = addPeer(&ep2);
  ASSERT_NE(nullptr, peer2);
  EXPECT_EQ(0, oc_sec_free_roles(peer2));

  EXPECT_EQ(3, countRoles(peer1));
  EXPECT_EQ(3, oc_sec_free_roles(peer1));
  EXPECT_EQ(0, countRoles(peer1));
}

TEST_F(TestRolesWithServer, FreeRoleForDevice)
{
  oc_endpoint_t ep1 = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer1 = addPeer(&ep1);
  size_t deviceID1 = 1;
  oc_sec_cred_t *role1 = oc_sec_roles_add(peer1, deviceID1);
  ASSERT_NE(nullptr, role1);
  oc_sec_cred_t *role2 = oc_sec_roles_add(peer1, deviceID1);
  ASSERT_NE(nullptr, role2);
  EXPECT_EQ(2, countRoles(peer1));

  oc_endpoint_t ep2 = oc::endpoint::FromString("coaps://[::2]:42");
  const auto *peer2 = addPeer(&ep2);
  ASSERT_NE(nullptr, peer2);
  size_t deviceID2 = 2;
  oc_sec_cred_t *role3 = oc_sec_roles_add(peer2, deviceID2);
  ASSERT_NE(nullptr, role3);
  EXPECT_EQ(1, countRoles(peer2));

  size_t deviceID3 = 3;
  EXPECT_EQ(0, oc_sec_free_roles_for_device(deviceID3));
  EXPECT_EQ(1, oc_sec_free_roles_for_device(deviceID2));
  EXPECT_EQ(2, oc_sec_free_roles_for_device(deviceID1));
}

TEST_F(TestRolesWithServer, FreeRoleByCredID)
{
  oc_endpoint_t ep1 = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer1 = addPeer(&ep1);
  size_t deviceID1 = 1;
  oc_sec_cred_t *role1 = oc_sec_roles_add(peer1, deviceID1);
  ASSERT_NE(nullptr, role1);
  role1->credid = 1;
  oc_sec_cred_t *role2 = oc_sec_roles_add(peer1, deviceID1);
  ASSERT_NE(nullptr, role2);
  role2->credid = 2;
  EXPECT_EQ(2, countRoles(peer1));

  oc_endpoint_t ep2 = oc::endpoint::FromString("coaps://[::2]:42");
  const auto *peer2 = addPeer(&ep2);
  ASSERT_NE(nullptr, peer2);

  EXPECT_FALSE(oc_sec_free_role_by_credid(1, peer2));
  EXPECT_FALSE(oc_sec_free_role_by_credid(3, peer1));
  EXPECT_TRUE(oc_sec_free_role_by_credid(1, peer1));
}

#else /* !OC_DYNAMIC_ALLOCATION */

TEST_F(TestRolesWithServer, AddRole_FailAllocation)
{
  oc_endpoint_t ep = oc::endpoint::FromString("coaps://[::1]:42");
  const auto *peer = addPeer(&ep);
  ASSERT_NE(nullptr, peer);

  for (int i = 0; i < OC_MAX_NUM_DEVICES; ++i) {
    oc_sec_cred_t *role = oc_sec_roles_add(peer, kDeviceID);
    EXPECT_NE(nullptr, role);
  }

  oc_sec_cred_t *role = oc_sec_roles_add(peer, kDeviceID);
  EXPECT_EQ(nullptr, role);
}

#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

TEST_F(TestRolesWithServer, GetRequest)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto get_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_OK, data->code);
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  // TODO: need communication API to send add validlty role certificates and
  // have a peer, connecting device to itself seems to break the TLS handshake

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_get_with_timeout(OCF_SEC_ROLES_URI, &ep,
                                     "if=" OC_IF_BASELINE_STR, timeout.count(),
                                     get_handler, HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

#if 0

TEST_F(TestRolesWithServer, PostRequest)
{
  // TODO: need communication API to send POST request, connecting device to
  // itself seems to break the TLS handshake

  // roles_resource_post
}


TEST_F(TestRolesWithServer, DeleteRequest)
{
  // TODO: need a peer connection to test this
}

#endif

TEST_F(TestRolesWithServer, DeleteRequest_FailNoPeer)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto delete_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_NOT_FOUND, data->code);
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_delete_with_timeout(OCF_SEC_ROLES_URI, &ep, nullptr,
                                        timeout.count(), delete_handler,
                                        HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  // TODO add roles and verify that they are all deleted
}

#if 0

// TODO: must create a peer connection

TEST_F(TestRolesWithServer, DeleteRequest_FailInvalidCredid)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto delete_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_NOT_FOUND, data->code);
    *static_cast<bool *>(data->user_data) = true;
  };

  // invalid format
  std::string query = "credid=abc";
  bool invoked = false;
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_delete_with_timeout(OCF_SEC_ROLES_URI, &ep, query.c_str(),
                                        timeout.count(), delete_handler,
                                        HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  // negative
  invoked = false;
  query = "credid=-1";
  ASSERT_TRUE(oc_do_delete_with_timeout(OCF_SEC_ROLES_URI, &ep, query.c_str(),
                                        timeout.count(), delete_handler,
                                        HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  // too big
  invoked = false;
  query = "credid=" +
          std::to_string(
            static_cast<int64_t>(std::numeric_limits<int32_t>::max()) + 1);
  ASSERT_TRUE(oc_do_delete_with_timeout(OCF_SEC_ROLES_URI, &ep, query.c_str(),
                                        timeout.count(), delete_handler,
                                        HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);

  // not found
  invoked = false;
  query = "credid=42";
  ASSERT_TRUE(oc_do_delete_with_timeout(OCF_SEC_ROLES_URI, &ep, query.c_str(),
                                        timeout.count(), delete_handler,
                                        HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(invoked);
}

#endif

#else /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestRolesWithServer, GetRequest_FailMethodNotAuthorized)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_GET, &ep, OCF_SEC_ROLES_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

TEST_F(TestRolesWithServer, PostRequest_FailMethodNotAuthorized)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_POST, &ep, OCF_SEC_ROLES_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

TEST_F(TestRolesWithServer, DeleteRequest_FailMethodNotAuthorized)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
  oc::testNotSupportedMethod(OC_DELETE, &ep, OCF_SEC_ROLES_URI, nullptr,
                             OC_STATUS_UNAUTHORIZED);
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestRolesWithServer, PutRequest_Fail)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED;
#else  /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t error_code = OC_STATUS_UNAUTHORIZED;
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_SEC_ROLES_URI, nullptr,
                             error_code);
}

#ifdef OC_CLIENT

class TestRoleCreds : public testing::Test {
public:
  void TearDown() override { oc_sec_role_creds_free(); }

  static size_t countRoleCreds()
  {
    size_t count = 0;
    const oc_role_t *role = oc_sec_role_creds_get();
    while (role != nullptr) {
      ++count;
      role = role->next;
    }
    return count;
  }
};

TEST_F(TestRoleCreds, Add)
{
  ASSERT_EQ(0, countRoleCreds());

  std::string role = "role";
  std::string authority = "authority";
  oc_role_t *role_cred = oc_sec_role_cred_add_or_get(
    { role.c_str(), role.length() }, { authority.c_str(), authority.length() });
  EXPECT_NE(nullptr, role_cred);
  EXPECT_EQ(1, countRoleCreds());

  // adding the same role-authority pair should return the same role_cred
  oc_role_t *role_cred2 = oc_sec_role_cred_add_or_get(
    { role.c_str(), role.length() }, { authority.c_str(), authority.length() });
  EXPECT_NE(nullptr, role_cred2);
  EXPECT_EQ(1, countRoleCreds());
  EXPECT_EQ(role_cred, role_cred2);

#ifdef OC_DYNAMIC_ALLOCATION
  // different role
  std::string role2 = "role2";
  oc_role_t *role_cred3 =
    oc_sec_role_cred_add_or_get({ role2.c_str(), role2.length() },
                                { authority.c_str(), authority.length() });
  EXPECT_NE(nullptr, role_cred3);
  EXPECT_EQ(2, countRoleCreds());
  EXPECT_NE(role_cred, role_cred3);

  // different authority
  std::string authority2 = "authority2";
  oc_role_t *role_cred4 =
    oc_sec_role_cred_add_or_get({ role.c_str(), role.length() },
                                { authority2.c_str(), authority2.length() });
  EXPECT_NE(nullptr, role_cred4);
  EXPECT_EQ(3, countRoleCreds());
  EXPECT_NE(role_cred, role_cred4);
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestRoleCreds, Add_Fail)
{
  ASSERT_EQ(0, countRoleCreds());

  // missing role
  std::string authority = "authority";
  EXPECT_EQ(nullptr,
            oc_sec_role_cred_add_or_get(
              { nullptr, 0 }, { authority.c_str(), authority.length() }));
  EXPECT_EQ(0, countRoleCreds());

  // missing authority
  std::string role = "role";
  EXPECT_EQ(nullptr, oc_sec_role_cred_add_or_get(
                       { role.c_str(), role.length() }, { nullptr, 0 }));
  EXPECT_EQ(0, countRoleCreds());

#ifndef OC_DYNAMIC_ALLOCATION
  // without dynamic allocation, we can allocate only OC_ROLES_NUM_ROLE_CREDS
  // role creds
  for (int i = 0; i < OC_ROLES_NUM_ROLE_CREDS; ++i) {
    std::string role = "role" + std::to_string(i);
    std::string authority = "authority" + std::to_string(i);
    oc_role_t *role_cred =
      oc_sec_role_cred_add_or_get({ role.c_str(), role.length() },
                                  { authority.c_str(), authority.length() });
    EXPECT_NE(nullptr, role_cred);
    EXPECT_EQ(i + 1, countRoleCreds());
  }
  // adding one more should fail
  EXPECT_EQ(nullptr, oc_sec_role_cred_add_or_get(
                       { role.c_str(), role.length() },
                       { authority.c_str(), authority.length() }));
  EXPECT_EQ(OC_ROLES_NUM_ROLE_CREDS, countRoleCreds());
#endif /* !OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestRoleCreds, Remove)
{
  for (int i = 0; i < OC_ROLES_NUM_ROLE_CREDS; ++i) {
    std::string role = "role" + std::to_string(i);
    std::string authority = "authority" + std::to_string(i);
    oc_role_t *role_cred =
      oc_sec_role_cred_add_or_get({ role.c_str(), role.length() },
                                  { authority.c_str(), authority.length() });
    EXPECT_NE(nullptr, role_cred);
  }
  EXPECT_EQ(OC_ROLES_NUM_ROLE_CREDS, countRoleCreds());

  for (int i = 0; i < OC_ROLES_NUM_ROLE_CREDS; ++i) {
    std::string role = "role" + std::to_string(i);
    std::string authority = "authority" + std::to_string(i);
    EXPECT_TRUE(
      oc_sec_role_cred_remove({ role.c_str(), role.length() },
                              { authority.c_str(), authority.length() }));
    EXPECT_EQ(OC_ROLES_NUM_ROLE_CREDS - i - 1, countRoleCreds());
  }
  EXPECT_EQ(0, countRoleCreds());
}

TEST_F(TestRoleCreds, RemoveFail)
{
  for (int i = 0; i < OC_ROLES_NUM_ROLE_CREDS; ++i) {
    std::string role = "role" + std::to_string(i);
    std::string authority = "authority" + std::to_string(i);
    oc_role_t *role_cred =
      oc_sec_role_cred_add_or_get({ role.c_str(), role.length() },
                                  { authority.c_str(), authority.length() });
    EXPECT_NE(nullptr, role_cred);
  }
  EXPECT_EQ(OC_ROLES_NUM_ROLE_CREDS, countRoleCreds());

  // missing role
  std::string authority = "authority0";
  EXPECT_FALSE(oc_sec_role_cred_remove(
    { nullptr, 0 }, { authority.c_str(), authority.length() }));

  // missing authority
  std::string role = "role0";
  EXPECT_FALSE(
    oc_sec_role_cred_remove({ role.c_str(), role.length() }, { nullptr, 0 }));

  // non-existing role-authority pair
  std::string role2 = "role2";
  std::string authority2 = "authority2";
  EXPECT_FALSE(
    oc_sec_role_cred_remove({ role.c_str(), role.length() },
                            { authority2.c_str(), authority2.length() }));
  EXPECT_FALSE(
    oc_sec_role_cred_remove({ role2.c_str(), role2.length() },
                            { authority.c_str(), authority.length() }));
  EXPECT_FALSE(
    oc_sec_role_cred_remove({ role2.c_str(), role2.length() },
                            { authority2.c_str(), authority2.length() }));
}

// TODO: test oc_assert_role
// TODO: test oc_assert_all_roles

#endif /* OC_CLIENT */

#endif /* OC_SECURITY && OC_PKI */

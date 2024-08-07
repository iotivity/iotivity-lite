/******************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_ace_internal.h"
#include "security/oc_acl_internal.h"
#include "security/oc_acl_util_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_svr_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"
#include "tests/gtest/tls/Peer.h"
#include "util/oc_list.h"

#ifdef OC_PKI
#include "security/oc_certs_internal.h"
#include "security/oc_obt_internal.h"
#include "security/oc_roles_internal.h"
#include "tests/gtest/KeyPair.h"
#include "tests/gtest/PKI.h"
#include "tests/gtest/Role.h"
#endif /* OC_PKI */

#ifdef OC_SOFTWARE_UPDATE
#include "api/oc_swupdate_internal.h"
#endif /* OC_SOFTWARE_UPDATE */

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "api/plgd/plgd_time_internal.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include "gtest/gtest.h"

#include <array>
#include <string>
#include <vector>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID = 0;

static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };

class TestAcl : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_random_init();
#if defined(OC_DYNAMIC_ALLOCATION) && defined(OC_PKI)
    g_root_keypair = oc::GetECPKeyPair(MBEDTLS_ECP_DP_SECP256R1);
#endif /* OC_DYNAMIC_ALLOCATION && OC_PKI */
    oc_set_con_res_announced(true);
  }

  static void TearDownTestCase() { oc_random_destroy(); }

  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    ASSERT_EQ(0, oc_init_platform("plgd", nullptr, nullptr));
    ASSERT_EQ(0, oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(),
                               kDeviceName.c_str(), kOCFSpecVersion.c_str(),
                               kOCFDataModelVersion.c_str(), nullptr, nullptr));
#ifdef OC_HAS_FEATURE_PLGD_TIME
    plgd_time_create_resource();
#endif /* OC_HAS_FEATURE_PLGD_TIME */
    oc_sec_svr_create();
#ifdef OC_SOFTWARE_UPDATE
    oc_swupdate_create();
#endif /* OC_SOFTWARE_UPDATE */

    oc_mbedtls_init();

#if defined(OC_DYNAMIC_ALLOCATION) && defined(OC_PKI)
    g_root_credid = oc::pki::obt::GenerateSelfSignedRootCertificate(
      kDeviceID, g_root_subject, g_root_keypair);
    ASSERT_GT(g_root_credid, 0);
#endif /* OC_DYNAMIC_ALLOCATION && OC_PKI */
  }

  void TearDown() override
  {
#ifdef OC_SOFTWARE_UPDATE
    oc_swupdate_free();
#endif /* OC_SOFTWARE_UPDATE */
    oc_sec_svr_free();
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_connectivity_shutdown(kDeviceID);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }

  template<typename Filter>
  static std::vector<oc_resource_t *> getResources(size_t device, Filter filter)
  {
    std::vector<oc_resource_t *> resources;
    for (int i = OCF_P; i <= OCF_D; ++i) {
      oc_resource_t *resource = oc_core_get_resource_by_index(i, device);
      EXPECT_NE(nullptr, resource);
      if (filter(device, resource)) {
        resources.push_back(resource);
      }
    }
    return resources;
  }

  static std::vector<oc_resource_t *> getSVRs(size_t device)
  {
    return getResources(device, [](size_t dev, const oc_resource_t *resource) {
      return oc_core_is_SVR(resource, dev);
    });
  }

#if defined(OC_DYNAMIC_ALLOCATION) && defined(OC_PKI)
  static std::string g_root_subject_name;
  static std::string g_root_subject;
  static oc::keypair_t g_root_keypair;
  static int g_root_credid;
#endif /* OC_DYNAMIC_ALLOCATION && OC_PKI */
};

#if defined(OC_DYNAMIC_ALLOCATION) && defined(OC_PKI)
std::string TestAcl::g_root_subject_name{ "IoTivity-Lite Test" };
std::string TestAcl::g_root_subject{ "C=US, O=OCF, CN=" + g_root_subject_name };
oc::keypair_t TestAcl::g_root_keypair{};
int TestAcl::g_root_credid{ -1 };
#endif /* OC_DYNAMIC_ALLOCATION && OC_PKI */

static size_t
oc_sec_ace_count(size_t device)
{
  size_t count = 0;
  const auto *ace =
    static_cast<oc_sec_ace_t *>(oc_list_head(oc_sec_get_acl(device)->subjects));
  for (; ace != nullptr; ace = ace->next) {
    ++count;
  }
  return count;
}

TEST_F(TestAcl, oc_sec_acl_add_bootstrap_acl)
{
  EXPECT_EQ(true, oc_sec_acl_add_bootstrap_acl(kDeviceID));
  const oc_sec_acl_t *acl = oc_sec_get_acl(kDeviceID);
  EXPECT_NE(nullptr, acl);
  EXPECT_EQ(1, oc_sec_ace_count(kDeviceID));
}

TEST_F(TestAcl, oc_sec_acl_find_subject)
{
  oc_ace_subject_view_t anon_clear{};
  anon_clear.conn = OC_CONN_ANON_CLEAR;
  auto tag = OC_STRING_VIEW("tag");
  EXPECT_EQ(true, oc_sec_acl_update_res(OC_SUBJECT_CONN, anon_clear, -1,
                                        OC_PERM_RETRIEVE, tag,
                                        OC_STRING_VIEW("/test/a"), OC_ACE_NO_WC,
                                        kDeviceID, nullptr));

  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  oc_ace_subject_view_t subject_uuid{};
  subject_uuid.uuid = uuid;
  EXPECT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_UUID, subject_uuid, -1, OC_PERM_UPDATE,
                    /*tag*/ OC_STRING_VIEW_NULL, OC_STRING_VIEW("/test/b"),
                    OC_ACE_NO_WC, kDeviceID, nullptr));

  oc_ace_subject_view_t subject_role{};
  auto testRole = OC_STRING_VIEW("test.role");
  subject_role.role = { testRole, {} };
  EXPECT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_ROLE, subject_role, -1, OC_PERM_NOTIFY,
                    /*tag*/ OC_STRING_VIEW_NULL, OC_STRING_VIEW("/test/c"),
                    OC_ACE_NO_WC, kDeviceID, nullptr));

  oc_ace_subject_view_t subject_role2{};
  auto testAuthority = OC_STRING_VIEW("test.authority");
  subject_role2.role = { testRole, testAuthority };
  EXPECT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_ROLE, subject_role2, -1, OC_PERM_RETRIEVE,
                    /*tag*/ OC_STRING_VIEW_NULL, OC_STRING_VIEW("/test/d"),
                    OC_ACE_NO_WC, kDeviceID, nullptr));

  oc_ace_subject_view_t subject_role3{};
  auto testAuthority2 = OC_STRING_VIEW("test.newauthority");
  subject_role3.role = { testRole, testAuthority2 };
  EXPECT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_ROLE, subject_role3, -1, OC_PERM_RETRIEVE,
                    /*tag*/ OC_STRING_VIEW_NULL, OC_STRING_VIEW("/test/e"),
                    OC_ACE_NO_WC, kDeviceID, nullptr));

  oc_ace_subject_view_t subject_role4{};
  auto testRole2 = OC_STRING_VIEW("test.newrole");
  subject_role4.role = { testRole2, testAuthority };
  EXPECT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_ROLE, subject_role4, -1, OC_PERM_RETRIEVE,
                    /*tag*/ OC_STRING_VIEW_NULL, OC_STRING_VIEW("/test/f"),
                    OC_ACE_NO_WC, kDeviceID, nullptr));

  ASSERT_EQ(6, oc_sec_ace_count(kDeviceID));

  oc_sec_acl_clear(
    kDeviceID, [](const oc_sec_ace_t *, void *) { return false; }, nullptr);
  EXPECT_EQ(6, oc_sec_ace_count(kDeviceID));

  oc_sec_ace_t *ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, anon_clear, /*aceid*/
                            -1,
                            /*permission*/ 0, tag,
                            /*match_tag*/ true, kDeviceID);
  EXPECT_NE(nullptr, ace);

  // must match aceid
  ASSERT_NE(-1, ace->aceid);
  ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, anon_clear, ace->aceid,
                            /*permission*/ 0, tag,
                            /*match_tag*/ true, kDeviceID);
  EXPECT_NE(nullptr, ace);

  // non-matching aceid
  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, anon_clear,
                                ace->aceid + 1,
                                /*permission*/ 0, tag,
                                /*match_tag*/ true, kDeviceID);
  EXPECT_EQ(nullptr, ace);

  // non-matching tag
  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, anon_clear, /*aceid*/
                                -1,
                                /*permission*/ 0, /*tag*/ OC_STRING_VIEW_NULL,
                                /*match_tag*/ true, kDeviceID);
  EXPECT_EQ(nullptr, ace);

  // ignore non-matching tag
  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, anon_clear, /*aceid*/
                                -1,
                                /*permission*/ 0, /*tag*/ OC_STRING_VIEW_NULL,
                                /*match_tag*/ false, kDeviceID);
  EXPECT_NE(nullptr, ace);

  oc_sec_acl_clear(
    kDeviceID,
    [](const oc_sec_ace_t *entry, void *) {
      return entry->subject_type == OC_SUBJECT_CONN;
    },
    nullptr);
  ASSERT_EQ(5, oc_sec_ace_count(kDeviceID));
  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, anon_clear, /*aceid*/
                                -1,
                                /*permission*/ 0, /*tag*/ OC_STRING_VIEW_NULL,
                                /*match_tag*/ false, kDeviceID);
  EXPECT_EQ(nullptr, ace);

  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_ROLE, subject_role,
                                /*aceid*/ -1, /*permission*/ 0,
                                /*tag*/ OC_STRING_VIEW_NULL,
                                /*match_tag*/ false, kDeviceID);
  EXPECT_NE(nullptr, ace);

  int aceid{ ace->aceid };
  oc_sec_acl_clear(
    kDeviceID,
    [](const oc_sec_ace_t *entry, void *data) {
      const auto *id = static_cast<int *>(data);
      return entry->aceid == *id;
    },
    &aceid);
  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_ROLE, subject_role,
                                /*aceid*/ -1, /*permission*/ 0,
                                /*tag*/ OC_STRING_VIEW_NULL,
                                /*match_tag*/ false, kDeviceID);
  EXPECT_EQ(nullptr, ace);

  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  ASSERT_EQ(0, oc_sec_ace_count(kDeviceID));
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
static const std::string kResourceURI = "/LightResourceURI";
static const std::string kResourceName = "roomlights";

static void
onGet(oc_request_t *, oc_interface_mask_t, void *)
{
  // no-op
}

TEST_F(TestAcl, oc_sec_check_acl_in_RFOTM)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  EXPECT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_request_handler(res, OC_GET, onGet, nullptr);
  oc_resource_set_access_in_RFOTM(res, true, OC_PERM_RETRIEVE);
  bool add_check = oc_ri_add_resource(res);
  EXPECT_EQ(true, add_check);

  oc_endpoint_t endpoint;
  memset(&endpoint, 0, sizeof(oc_endpoint_t));
  EXPECT_EQ(true, oc_sec_check_acl(OC_GET, res, &endpoint));

  EXPECT_EQ(false, oc_sec_check_acl(OC_POST, res, &endpoint));

  oc_resource_set_access_in_RFOTM(res, false, OC_PERM_NONE);
  EXPECT_EQ(false, oc_sec_check_acl(OC_GET, res, &endpoint));

  oc_resource_set_access_in_RFOTM(res, true, OC_PERM_NONE);
  EXPECT_EQ(false, oc_sec_check_acl(OC_GET, res, &endpoint));
  EXPECT_EQ(false, oc_sec_check_acl(OC_POST, res, &endpoint));
  EXPECT_EQ(false, oc_sec_check_acl(OC_PUT, res, &endpoint));
  EXPECT_EQ(false, oc_sec_check_acl(OC_DELETE, res, &endpoint));
  EXPECT_EQ(false, oc_sec_check_acl(OC_FETCH, res, &endpoint));

  bool del_check = oc_ri_delete_resource(res);
  EXPECT_EQ(true, del_check);
  oc_sec_pstat_free();
}
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestAcl, oc_sec_check_acl_FailInsecureDOC)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  auto tlsPeer =
    oc::tls::MakePeer("coap://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_EQ(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, tlsPeer.role, nullptr);
  ASSERT_NE(nullptr, peer);
  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));
  oc_resource_t resource{};
  resource.device = kDeviceID;
  EXPECT_FALSE(oc_sec_check_acl(OC_GET, &resource, &ep));

  oc_tls_remove_peer(&ep, true);
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

TEST_F(TestAcl, oc_sec_check_acl_AccessInRFOTM)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  oc_resource_t resource{};
  resource.device = kDeviceID;
  ASSERT_TRUE(
    oc::SetAccessInRFOTM(&resource, false, OC_PERM_RETRIEVE | OC_PERM_UPDATE));
  oc_endpoint_t ep{};
  ep.device = kDeviceID;
  EXPECT_TRUE(oc_sec_check_acl(OC_GET, &resource, &ep));
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestAcl, oc_sec_check_acl_FailNCRInNonRFNOP)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);

  oc_resource_t resource{};
  resource.device = kDeviceID;
  ASSERT_FALSE(oc_core_is_DCR(&resource, kDeviceID));
  oc_endpoint_t ep{};
  ep.device = kDeviceID;
  // device in non-RFNOP cannot access NCRs
  std::vector<oc_dostype_t> states{ OC_DOS_RESET, OC_DOS_RFOTM, OC_DOS_RFPRO,
                                    OC_DOS_SRESET };
  for (auto state : states) {
    pstat->s = state;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, &resource, &ep));
  }
}

TEST_F(TestAcl, oc_sec_check_acl_FailInsecureAccessToVerticalResource)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFNOP;
  oc_resource_t resource{};
  resource.device = kDeviceID;
  ASSERT_FALSE(oc_core_is_DCR(&resource, kDeviceID));
  ASSERT_TRUE(oc_core_is_vertical_resource(&resource, kDeviceID));
  oc_endpoint_t ep{};
  ep.device = kDeviceID;
  EXPECT_FALSE(oc_sec_check_acl(OC_GET, &resource, &ep));
}

TEST_F(TestAcl, oc_sec_check_acl_DOCAccessToDCR)
{
  // DCR
  oc_resource_t *resource = oc_core_get_resource_by_index(OCF_P, kDeviceID);
  ASSERT_NE(nullptr, resource);
  ASSERT_TRUE(oc_core_is_DCR(resource, kDeviceID));
  // DOC peer
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, tlsPeer.role, nullptr);
  ASSERT_NE(nullptr, peer);
  ASSERT_TRUE(peer->doc);
  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));

  EXPECT_TRUE(oc_sec_check_acl(OC_GET, resource, &ep));

  oc_tls_remove_peer(&ep, true);
}

TEST_F(TestAcl, oc_sec_check_acl_GETinRFOTM)
{
  // oic/d, oic/p and oic/res are accessible to GET requests in RFOTM
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  std::vector<oc_core_resource_t> resources{ OCF_P, OCF_D, OCF_RES };
#ifdef OC_HAS_FEATURE_PLGD_TIME
  resources.push_back(PLGD_TIME);
#endif /* OC_HAS_FEATURE_PLGD_TIME */
#ifdef OC_WKCORE
  resources.push_back(WELLKNOWNCORE);
#endif /* OC_WKCORE */

  for (auto type : resources) {
    oc_resource_t *resource = oc_core_get_resource_by_index(type, kDeviceID);
    ASSERT_NE(nullptr, resource);
    oc_endpoint_t ep{};
    ep.device = kDeviceID;
    EXPECT_TRUE(oc_sec_check_acl(OC_GET, resource, &ep));
  }
}

TEST_F(TestAcl, oc_sec_check_acl_PriorToDOCAccessToDoxmInRFOTM)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;
  oc_resource_t *resource =
    oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID);
  ASSERT_NE(nullptr, resource);
  oc_endpoint_t ep{};
  ep.device = kDeviceID;
  std::vector<oc_method_t> methods{ OC_GET, OC_POST, OC_PUT, OC_DELETE };
  for (auto method : methods) {
    EXPECT_TRUE(oc_sec_check_acl(method, resource, &ep));
  }
}

TEST_F(TestAcl, oc_sec_check_acl_PriorToDOCGetAccessToPstatInRFOTM)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;
  oc_resource_t *resource =
    oc_core_get_resource_by_index(OCF_SEC_PSTAT, kDeviceID);
  ASSERT_NE(nullptr, resource);
  oc_endpoint_t ep{};
  ep.device = kDeviceID;
  EXPECT_TRUE(oc_sec_check_acl(OC_GET, resource, &ep));
  std::vector<oc_method_t> methods{ OC_POST, OC_PUT, OC_DELETE };
  for (auto method : methods) {
    EXPECT_FALSE(oc_sec_check_acl(method, resource, &ep));
  }
}

TEST_F(TestAcl, oc_sec_check_acl_FailInsecureAccessToSecurityVerticalResource)
{
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);

  /* anon-clear requests to SVRs while the dos is RFPRO, RFNOP or SRESET should
   * not be authorized regardless of the ACL configuration */

  auto svrs = getSVRs(kDeviceID);
  for (auto svr : svrs) {
    ASSERT_TRUE(oc_core_is_SVR(svr, kDeviceID));
    oc_endpoint_t ep{};
    ep.device = kDeviceID;
    ASSERT_EQ(0, ep.flags & SECURED);

    pstat->s = OC_DOS_RFPRO;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, svr, &ep));
    pstat->s = OC_DOS_RFNOP;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, svr, &ep));
    pstat->s = OC_DOS_SRESET;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, svr, &ep));
  }
}

TEST_F(TestAcl, oc_sec_check_acl_AccessByOwner)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  ep.di = uuid;

  oc_sec_own_resources(kDeviceID, uuid);
  struct input_t
  {
    oc_resource_t *resource;
    oc_method_t method;
  };
  std::vector<input_t> inputs{
    {
      oc_core_get_resource_by_index(OCF_SEC_ACL, kDeviceID),
      OC_GET,
    },
    {
      oc_core_get_resource_by_index(OCF_SEC_CRED, kDeviceID),
      OC_POST,
    },
    {
      oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID),
      OC_PUT,
    },
    {
      oc_core_get_resource_by_index(OCF_SEC_PSTAT, kDeviceID),
      OC_DELETE,
    },
  };
  for (auto input : inputs) {
    EXPECT_TRUE(oc_sec_check_acl(input.method, input.resource, &ep));
  }

  // when owned by different uuid, it should fail
  oc_uuid_t uuid2{};
  do {
    oc_gen_uuid(&uuid2);
  } while (oc_uuid_is_equal(uuid, uuid2));
  ep.di = uuid2;
  for (auto input : inputs) {
    EXPECT_FALSE(oc_sec_check_acl(input.method, input.resource, &ep));
  }
}

#ifdef OC_PKI

TEST_F(TestAcl, oc_sec_check_acl_AccessToRoles)
{
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);

  oc_resource_t *roles =
    oc_core_get_resource_by_index(OCF_SEC_ROLES, kDeviceID);
  // peer has implicit access to /oic/sec/roles in RFPRO, RFNOP, SRESET
  ASSERT_NE(nullptr, roles);
  pstat->s = OC_DOS_RFPRO;
  EXPECT_TRUE(oc_sec_check_acl(OC_GET, roles, &ep));
  pstat->s = OC_DOS_RFNOP;
  EXPECT_TRUE(oc_sec_check_acl(OC_POST, roles, &ep));
  pstat->s = OC_DOS_SRESET;
  EXPECT_TRUE(oc_sec_check_acl(OC_DELETE, roles, &ep));

  // but not in RESET and RFOTM
  pstat->s = OC_DOS_RESET;
  EXPECT_FALSE(oc_sec_check_acl(OC_GET, roles, &ep));
  pstat->s = OC_DOS_RFOTM;
  EXPECT_FALSE(oc_sec_check_acl(OC_GET, roles, &ep));
}

#endif /* OC_PKI */

static void
assertUnauthorizedAccessToResource(const oc_resource_t *resource, size_t device,
                                   const oc_endpoint_t *ep, bool isSVR)
{
  ASSERT_EQ(isSVR, oc_core_is_SVR(resource, device));
  ASSERT_FALSE(oc_sec_check_acl(OC_GET, resource, ep));
  ASSERT_FALSE(oc_sec_check_acl(OC_POST, resource, ep));
  ASSERT_FALSE(oc_sec_check_acl(OC_PUT, resource, ep));
  ASSERT_FALSE(oc_sec_check_acl(OC_DELETE, resource, ep));
}

static void
checkAccessToResource(const oc_resource_t *resource, const oc_endpoint_t *ep,
                      bool allowGet = true, bool allowPost = true,
                      bool allowPut = true, bool allowDelete = true)
{
  EXPECT_EQ(allowGet, oc_sec_check_acl(OC_GET, resource, ep));
  EXPECT_EQ(allowPost, oc_sec_check_acl(OC_POST, resource, ep));
  EXPECT_EQ(allowPut, oc_sec_check_acl(OC_PUT, resource, ep));
  EXPECT_EQ(allowDelete, oc_sec_check_acl(OC_DELETE, resource, ep));
}

TEST_F(TestAcl, oc_sec_check_acl_AccessToSVRBySubject)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  ep.di = uuid;

  oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, tlsPeer.role, nullptr);
  ASSERT_NE(nullptr, peer);
  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  // we use doxm to represent all SVRs
  auto *doxm = oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID);
  ASSERT_NE(nullptr, doxm);
  assertUnauthorizedAccessToResource(doxm, kDeviceID, &ep, true);

  oc_ace_subject_view_t subject{};
  subject.uuid = uuid;

  // allowing retrieve or notify should allow GET access
  for (auto perm : std::vector<oc_ace_permissions_t>(
         { OC_PERM_RETRIEVE, OC_PERM_NOTIFY })) {
    ASSERT_EQ(true, oc_sec_acl_update_res(OC_SUBJECT_UUID, subject, -1, perm,
                                          /*tag*/ OC_STRING_VIEW_NULL,
                                          oc_string_view2(&doxm->uri),
                                          OC_ACE_NO_WC, kDeviceID, nullptr));
    checkAccessToResource(doxm, &ep, true, false, false, false);
    EXPECT_FALSE(oc_sec_check_acl(OC_FETCH, doxm, &ep));
    oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  }

  // allowing create or update should allow POST and PUT access
  for (auto perm :
       std::vector<oc_ace_permissions_t>({ OC_PERM_CREATE, OC_PERM_UPDATE })) {
    ASSERT_EQ(true, oc_sec_acl_update_res(OC_SUBJECT_UUID, subject, -1, perm,
                                          /*tag*/ OC_STRING_VIEW_NULL,
                                          oc_string_view2(&doxm->uri),
                                          OC_ACE_NO_WC, kDeviceID, nullptr));
    checkAccessToResource(doxm, &ep, false, true, true, false);
    EXPECT_FALSE(oc_sec_check_acl(OC_FETCH, doxm, &ep));
    oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  }

  // allowing delete should allow DELETE access
  ASSERT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_UUID, subject, -1, OC_PERM_DELETE,
                    /*tag*/ OC_STRING_VIEW_NULL, oc_string_view2(&doxm->uri),
                    OC_ACE_NO_WC, kDeviceID, nullptr));
  checkAccessToResource(doxm, &ep, false, false, false, true);
  EXPECT_FALSE(oc_sec_check_acl(OC_FETCH, doxm, &ep));
  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);

  oc_tls_remove_peer(&ep, true);
}

TEST_F(TestAcl, oc_sec_check_acl_AccessToSVRByPSK)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  ep.di = uuid;

  oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, tlsPeer.role, nullptr);
  ASSERT_NE(nullptr, peer);
  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));
  // pretend that we have a PSK session
  mbedtls_ssl_session session{};
  session.ciphersuite = MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256;
  peer->ssl_ctx.session = &session;
  ASSERT_TRUE(oc_tls_uses_psk_cred(peer));

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  // we use doxm to represent all SVRs
  auto *doxm = oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID);
  ASSERT_NE(nullptr, doxm);
  assertUnauthorizedAccessToResource(doxm, kDeviceID, &ep, true);

  // add PSK cred
  std::vector<unsigned char> pin{ '1', '2', '3' };
  // 16 = SYMMETRIC_KEY_128BIT_LEN
  std::array<uint8_t, 16> key{};
  ASSERT_EQ(0, oc_tls_pbkdf2(pin.data(), pin.size(), &uuid, 100,
                             MBEDTLS_MD_SHA256, &key[0], key.size()));
  std::array<char, OC_UUID_LEN> uuid_str{};
  ASSERT_NE(-1, oc_uuid_to_str_v1(&uuid, &uuid_str[0], uuid_str.size()));
  oc_sec_encoded_data_t privatedata = { key.data(), key.size(),
                                        OC_ENCODING_RAW };
  auto role = OC_STRING_VIEW("role");
  auto authority = OC_STRING_VIEW("authority");
  int credid = oc_sec_add_new_cred(
    kDeviceID, false, nullptr, -1, OC_CREDTYPE_PSK, OC_CREDUSAGE_NULL,
    uuid_str.data(), privatedata, { nullptr, 0, OC_ENCODING_UNSUPPORTED }, role,
    authority, OC_STRING_VIEW_NULL, nullptr);
  ASSERT_NE(-1, credid);

  // allowing retrieve or notify should allow GET access
  for (auto perm : std::vector<oc_ace_permissions_t>(
         { OC_PERM_RETRIEVE, OC_PERM_NOTIFY })) {
    oc_ace_subject_view_t subject{};
    subject.role = { role, authority };
    ASSERT_EQ(true, oc_sec_acl_update_res(OC_SUBJECT_ROLE, subject, -1, perm,
                                          /*tag*/ OC_STRING_VIEW_NULL,
                                          oc_string_view2(&doxm->uri),
                                          OC_ACE_NO_WC, kDeviceID, nullptr));
    checkAccessToResource(doxm, &ep, true, false, false, false);
    EXPECT_FALSE(oc_sec_check_acl(OC_FETCH, doxm, &ep));
    oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  }

  // allowing create or update should allow POST and PUT access
  for (auto perm :
       std::vector<oc_ace_permissions_t>({ OC_PERM_CREATE, OC_PERM_UPDATE })) {
    oc_ace_subject_view_t subject{};
    subject.role = { role, authority };
    ASSERT_EQ(true, oc_sec_acl_update_res(OC_SUBJECT_ROLE, subject, -1, perm,
                                          /*tag*/ OC_STRING_VIEW_NULL,
                                          oc_string_view2(&doxm->uri),
                                          OC_ACE_NO_WC, kDeviceID, nullptr));
    checkAccessToResource(doxm, &ep, false, true, true, false);
    EXPECT_FALSE(oc_sec_check_acl(OC_FETCH, doxm, &ep));
    oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  }

  // allowing delete should allow DELETE access
  oc_ace_subject_view_t subject{};
  subject.role = { role, authority };
  ASSERT_EQ(true, oc_sec_acl_update_res(
                    OC_SUBJECT_ROLE, subject, -1, OC_PERM_DELETE,
                    /*tag*/ OC_STRING_VIEW_NULL, oc_string_view2(&doxm->uri),
                    OC_ACE_NO_WC, kDeviceID, nullptr));
  checkAccessToResource(doxm, &ep, false, false, false, true);
  EXPECT_FALSE(oc_sec_check_acl(OC_FETCH, doxm, &ep));
  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);

  peer->ssl_ctx.session = nullptr;
  oc_tls_remove_peer(&ep, true);
}

#if defined(OC_DYNAMIC_ALLOCATION) && defined(OC_PKI)

TEST_F(TestAcl, oc_sec_check_acl_AccessToSVRByOwnerRoleCred)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  ep.di = uuid;

  oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, tlsPeer.role, nullptr);
  ASSERT_NE(nullptr, peer);
  peer->uuid = uuid;
  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  // we use doxm to represent all SVRs
  auto *doxm = oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID);
  ASSERT_NE(nullptr, doxm);
  assertUnauthorizedAccessToResource(doxm, kDeviceID, &ep, true);

  std::array<char, 50> uuid_buf{};
  ASSERT_TRUE(
    oc_certs_encode_CN_with_UUID(&uuid, uuid_buf.data(), uuid_buf.size()));

  oc::Roles roles{};
  roles.Add(OCF_SEC_ROLE_OWNER, "owner");

  auto role_pem = oc::pki::obt::GenerateRoleCertificate(
    uuid_buf.data(), g_root_subject, g_root_keypair, roles);
  ASSERT_FALSE(role_pem.empty());

  oc_sec_encoded_data_t publicdata = { role_pem.data(), role_pem.size() - 1,
                                       OC_ENCODING_PEM };
  int credid = oc_sec_add_new_cred(
    kDeviceID, true, peer, -1, OC_CREDTYPE_CERT, OC_CREDUSAGE_ROLE_CERT, "*",
    { nullptr, 0, OC_ENCODING_UNSUPPORTED }, publicdata, OC_STRING_VIEW_NULL,
    OC_STRING_VIEW_NULL, OC_STRING_VIEW_NULL, nullptr);
  ASSERT_NE(-1, credid);
  checkAccessToResource(doxm, &ep);

  oc_tls_remove_peer(&ep, true);
}

TEST_F(TestAcl, oc_sec_check_acl_AccessToSVRByNonOwnerRoleCred)
{
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  auto tlsPeer =
    oc::tls::MakePeer("coaps://[ff02::41]:1336", MBEDTLS_SSL_IS_CLIENT);
  oc_endpoint_t ep = oc::endpoint::FromString(tlsPeer.address);
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;
  ep.di = uuid;

  oc_tls_peer_t *peer = oc_tls_add_or_get_peer(&ep, tlsPeer.role, nullptr);
  ASSERT_NE(nullptr, peer);
  peer->uuid = uuid;
  ASSERT_EQ(1, oc_tls_num_peers(kDeviceID));

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  // we use doxm to represent all SVRs
  auto *doxm = oc_core_get_resource_by_index(OCF_SEC_DOXM, kDeviceID);
  ASSERT_NE(nullptr, doxm);
  assertUnauthorizedAccessToResource(doxm, kDeviceID, &ep, true);

  std::array<char, 50> uuid_buf{};
  ASSERT_TRUE(
    oc_certs_encode_CN_with_UUID(&uuid, uuid_buf.data(), uuid_buf.size()));

  auto role = OC_STRING_VIEW("user");
  auto writeAuth = OC_STRING_VIEW("write");
  oc::Roles roles{};
  roles.Add(role.data, writeAuth.data);

  auto role_pem = oc::pki::obt::GenerateRoleCertificate(
    uuid_buf.data(), g_root_subject, g_root_keypair, roles);
  ASSERT_FALSE(role_pem.empty());

  oc_sec_encoded_data_t publicdata = { role_pem.data(), role_pem.size() - 1,
                                       OC_ENCODING_PEM };
  int credid = oc_sec_add_new_cred(
    kDeviceID, true, peer, -1, OC_CREDTYPE_CERT, OC_CREDUSAGE_ROLE_CERT, "*",
    { nullptr, 0, OC_ENCODING_UNSUPPORTED }, publicdata, OC_STRING_VIEW_NULL,
    OC_STRING_VIEW_NULL, OC_STRING_VIEW_NULL, nullptr);
  ASSERT_NE(-1, credid);

  oc_ace_subject_view_t write{};
  write.role = { role, writeAuth };
  ASSERT_TRUE(oc_sec_acl_update_res(OC_SUBJECT_ROLE, write, -1, OC_PERM_UPDATE,
                                    /*tag*/ OC_STRING_VIEW_NULL,
                                    oc_string_view2(&doxm->uri), OC_ACE_NO_WC,
                                    kDeviceID, nullptr));
  checkAccessToResource(doxm, &ep, false, true, true, false);

  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  oc_tls_remove_peer(&ep, true);
}

#endif /* OC_DYNAMIC_ALLOCATION && OC_PKI */

TEST_F(TestAcl, oc_sec_check_acl_AccessToNonSVRByCryptConn)
{
  oc_endpoint_t ep = oc::endpoint::FromString("coaps://[ff02::41]:1336");
  ASSERT_NE(0, ep.flags & SECURED);
  ep.device = kDeviceID;

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFNOP;

  auto resources =
    getResources(kDeviceID, [](size_t device, const oc_resource_t *resource) {
      oc_string_view_t uriv = oc_string_view2(&resource->uri);
#ifdef OC_HAS_FEATURE_PLGD_TIME
      if (plgd_is_time_resource_uri(uriv)) {
        return false;
      }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
#ifdef OC_WKCORE
      if (oc_is_wkcore_resource_uri(uriv)) {
        return false;
      }
#endif /* OC_WKCORE */
      return !oc_core_is_SVR(resource, device);
    });
  for (auto res : resources) {
    assertUnauthorizedAccessToResource(res, kDeviceID, &ep, false);
  }

  auto setAnonConnPermission = [&resources](oc_ace_permissions_t permission) {
    for (auto res : resources) {
      oc_ace_subject_view_t anon_crypt{};
      anon_crypt.conn = OC_CONN_AUTH_CRYPT;
      if (!oc_sec_acl_update_res(OC_SUBJECT_CONN, anon_crypt, -1, permission,
                                 /*tag*/ OC_STRING_VIEW_NULL,
                                 oc_string_view2(&res->uri), OC_ACE_NO_WC,
                                 kDeviceID, nullptr)) {
        return false;
      }
    }
    return true;
  };

  // allow delete access to all resources
  ASSERT_TRUE(setAnonConnPermission(OC_PERM_DELETE));
  for (auto res : resources) {
    checkAccessToResource(res, &ep, false, false, false, true);
  }

  // allow update access to all resources
  ASSERT_TRUE(setAnonConnPermission(OC_PERM_UPDATE));
  for (auto res : resources) {
    checkAccessToResource(res, &ep, false, true, true, true);
  }

  // allow retrieve access to all resources
  ASSERT_TRUE(setAnonConnPermission(OC_PERM_RETRIEVE));
  for (auto res : resources) {
    checkAccessToResource(res, &ep);
  }

  // but using anon connection shouldn't work
  oc_endpoint_t epAnon = oc::endpoint::FromString("coap://[ff02::41]:1336");
  ASSERT_EQ(0, epAnon.flags & SECURED);
  epAnon.device = kDeviceID;
  for (auto res : resources) {
    checkAccessToResource(res, &epAnon, false, false, false, false);
  }

  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
}

TEST_F(TestAcl, oc_sec_check_acl_AccessToNonSVRByAnonConn)
{
  oc_endpoint_t ep = oc::endpoint::FromString("coap://[ff02::41]:1336");
  ASSERT_EQ(0, ep.flags & SECURED);
  ep.device = kDeviceID;

  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFNOP;

  auto resources =
    getResources(kDeviceID, [](size_t device, const oc_resource_t *resource) {
      oc_string_view_t uriv = oc_string_view2(&resource->uri);
#ifdef OC_HAS_FEATURE_PLGD_TIME
      if (plgd_is_time_resource_uri(uriv)) {
        return false;
      }
#endif /* OC_HAS_FEATURE_PLGD_TIME */
#ifdef OC_WKCORE
      if (oc_is_wkcore_resource_uri(uriv)) {
        return false;
      }
#endif /* OC_WKCORE */
      return !oc_core_is_SVR(resource, device);
    });
  for (auto res : resources) {
    assertUnauthorizedAccessToResource(res, kDeviceID, &ep, false);
  }

  auto setAnonConnPermission = [&resources](oc_ace_permissions_t permission) {
    for (auto res : resources) {
      oc_ace_subject_view_t anon_clear{};
      anon_clear.conn = OC_CONN_ANON_CLEAR;
      if (!oc_sec_acl_update_res(OC_SUBJECT_CONN, anon_clear, -1, permission,
                                 /*tag*/ OC_STRING_VIEW_NULL,
                                 oc_string_view2(&res->uri), OC_ACE_NO_WC,
                                 kDeviceID, nullptr)) {
        return false;
      }
    }
    return true;
  };

  // allow retrieve access to all resources
  ASSERT_TRUE(setAnonConnPermission(OC_PERM_RETRIEVE));
  for (auto res : resources) {
    checkAccessToResource(res, &ep, true, false, false, false);
  }

  // allow update access to all resources
  ASSERT_TRUE(setAnonConnPermission(OC_PERM_UPDATE));
  for (auto res : resources) {
    checkAccessToResource(res, &ep, true, true, true, false);
  }

  // allow delete access to all resources
  ASSERT_TRUE(setAnonConnPermission(OC_PERM_DELETE));
  for (auto res : resources) {
    checkAccessToResource(res, &ep, true, true, true, true);
  }

  // using secure connection should also work
  oc_endpoint_t epCrypt = oc::endpoint::FromString("coaps://[ff02::41]:1336");
  ASSERT_NE(0, epCrypt.flags & SECURED);
  epCrypt.device = kDeviceID;
  for (auto res : resources) {
    checkAccessToResource(res, &epCrypt);
  }

  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
}

class TestAclWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Config());
#endif // OC_STORAGE

    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(
      oc::SetAccessInRFOTM(OCF_SEC_ACL, kDeviceID, true,
                           OC_PERM_RETRIEVE | OC_PERM_UPDATE | OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Clear());
#endif // OC_STORAGE
  }

  void TearDown() override { oc::TestDevice::Reset(); }
};

TEST_F(TestAclWithServer, PutRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED;
#else  /* !OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc_status_t error_code = OC_STATUS_UNAUTHORIZED;
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  oc::testNotSupportedMethod(OC_PUT, &ep, OCF_SEC_ACL_URI, nullptr, error_code);
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

TEST_F(TestAclWithServer, GetRequest)
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

  bool invoked = false;
  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OCF_SEC_ACL_URI, &ep, nullptr,
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &invoked));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestAclWithServer, PostRequest_EmptyArray)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };
  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_ACL_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  // {"aclist2": [{"subject": {"uuid": "11111111-2222-3333-4444-555555555555"},
  // "permission": 31, "resources": null}]}
  oc_rep_begin_root_object();
  oc_rep_set_array(root, aclist2);
  oc_rep_object_array_begin_item(aclist2);
  oc_rep_set_object(aclist2, subject);
  oc_rep_set_text_string(subject, uuid, "11111111-2222-3333-4444-555555555555");
  oc_rep_close_object(aclist2, subject);
  oc_rep_set_int(aclist2, permission,
                 OC_PERM_CREATE | OC_PERM_RETRIEVE | OC_PERM_UPDATE |
                   OC_PERM_DELETE | OC_PERM_NOTIFY);
  oc_rep_set_array(aclist2, resources);
  oc_rep_close_array(aclist2, resources);
  oc_rep_object_array_end_item(aclist2);
  oc_rep_close_array(root, aclist2);
  oc_rep_end_root_object();

  auto timeout = 1s;
  EXPECT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(invoked);
}

TEST_F(TestAclWithServer, PostRequest_CTT1_1_11)
{
  // currently the test case CTT1.1.11: Resource Discovery by Security Domain
  // Identifier sends an invalid POST request payload:
  //
  // {"aclist2":
  //    [{
  //      "subject": {
  //        "conntype": "anon-clear"
  //      },
  //      "href": "/oic/sec/res",
  //      "permission": 2
  //    }]
  // }
  // This should be fixed in the CTT, but for now we must avoid returning an
  // error to not break CTT verification.

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };
  bool invoked = false;
  ASSERT_TRUE(oc_init_post(OCF_SEC_ACL_URI, &ep, nullptr, post_handler,
                           HIGH_QOS, &invoked));

  oc_rep_begin_root_object();
  oc_rep_set_array(root, aclist2);
  oc_rep_object_array_begin_item(aclist2);
  oc_rep_set_object(aclist2, subject);
  oc_rep_set_text_string(subject, conntype, "anon-clear");
  oc_rep_close_object(aclist2, subject);
  oc_rep_set_text_string(aclist2, href, "/oic/sec/res");
  oc_rep_set_int(aclist2, permission, OC_PERM_RETRIEVE);
  oc_rep_object_array_end_item(aclist2);
  oc_rep_close_array(root, aclist2);
  oc_rep_end_root_object();

  auto timeout = 1s;
  EXPECT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);

  EXPECT_TRUE(invoked);
}

TEST_F(TestAclWithServer, DeleteRequest)
{
  // TODO
}

#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#endif /* OC_SECURITY */

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
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_uuid.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_acl_internal.h"
#include "security/oc_acl_util_internal.h"
#include "security/oc_pstat_internal.h"
#include "security/oc_security_internal.h"
#include "security/oc_svr_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/tls/Peer.h"
#include "util/oc_list.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include "gtest/gtest.h"
#include <string>

static constexpr size_t kDeviceID = 0;

static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };

class TestAcl : public testing::Test {
protected:
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
    oc_sec_svr_create();

    oc_mbedtls_init();

    oc_log_set_level(OC_LOG_LEVEL_DEBUG);
  }

  void TearDown() override
  {
    oc_log_set_level(OC_LOG_LEVEL_INFO);

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

  static std::vector<oc_resource_t *> getSVRs(size_t device)
  {
    std::vector<oc_resource_t *> svrs;
    for (size_t i = OCF_SEC_DOXM; i < OCF_D; ++i) {
      oc_resource_t *resource = oc_core_get_resource_by_index(i, device);
      if (oc_core_is_SVR(resource, device)) {
        svrs.push_back(resource);
      }
    }
    return svrs;
  }
};

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

TEST_F(TestAcl, oc_sec_acl_clear)
{
  oc_ace_subject_t anon_clear;
  memset(&anon_clear, 0, sizeof(oc_ace_subject_t));
  anon_clear.conn = OC_CONN_ANON_CLEAR;
  EXPECT_EQ(true, oc_sec_ace_update_res(OC_SUBJECT_CONN, &anon_clear, -1,
                                        OC_PERM_RETRIEVE, nullptr, "/test/a",
                                        OC_ACE_NO_WC, kDeviceID, nullptr));

  oc_uuid_t uuid = { { 0 } };
  oc_gen_uuid(&uuid);
  oc_ace_subject_t subject;
  memset(&subject, 0, sizeof(oc_ace_subject_t));
  memcpy(&subject.uuid, &uuid, sizeof(oc_uuid_t));
  EXPECT_EQ(true, oc_sec_ace_update_res(OC_SUBJECT_UUID, &subject, -1,
                                        OC_PERM_UPDATE, nullptr, "/test/b",
                                        OC_ACE_NO_WC, kDeviceID, nullptr));

  memset(&subject, 0, sizeof(oc_ace_subject_t));
  std::string testRole{ "test.role" };
  std::string testAuthority{ "test.authority" };
  oc_new_string(&subject.role.role, testRole.c_str(), testRole.length());
  oc_new_string(&subject.role.authority, testAuthority.c_str(),
                testAuthority.length());
  EXPECT_EQ(true, oc_sec_ace_update_res(OC_SUBJECT_ROLE, &subject, -1,
                                        OC_PERM_NOTIFY, nullptr, "/test/c",
                                        OC_ACE_NO_WC, kDeviceID, nullptr));
  EXPECT_EQ(3, oc_sec_ace_count(kDeviceID));

  oc_sec_acl_clear(
    kDeviceID, [](const oc_sec_ace_t *, void *) { return false; }, nullptr);
  EXPECT_EQ(3, oc_sec_ace_count(kDeviceID));

  oc_sec_ace_t *ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, &anon_clear, /*aceid*/
                            -1,
                            /*permission*/ 0, /*tag*/ nullptr,
                            /*match_tag*/ false, kDeviceID);
  EXPECT_NE(nullptr, ace);
  oc_sec_acl_clear(
    kDeviceID,
    [](const oc_sec_ace_t *entry, void *) {
      return entry->subject_type == OC_SUBJECT_CONN;
    },
    nullptr);
  EXPECT_EQ(2, oc_sec_ace_count(kDeviceID));
  ace = oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, &anon_clear, /*aceid*/
                                -1,
                                /*permission*/ 0, /*tag*/ nullptr,
                                /*match_tag*/ false, kDeviceID);
  EXPECT_EQ(nullptr, ace);

  ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_ROLE, &subject,
                            /*aceid*/ -1, /*permission*/ 0,
                            /*tag*/ nullptr, /*match_tag*/ false, kDeviceID);
  EXPECT_NE(nullptr, ace);
  int aceid{ ace->aceid };
  oc_sec_acl_clear(
    kDeviceID,
    [](const oc_sec_ace_t *entry, void *data) {
      const auto *id = static_cast<int *>(data);
      return entry->aceid == *id;
    },
    &aceid);
  ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_ROLE, &subject,
                            /*aceid*/ -1, /*permission*/ 0,
                            /*tag*/ nullptr, /*match_tag*/ false, kDeviceID);
  EXPECT_EQ(nullptr, ace);

  oc_sec_acl_clear(kDeviceID, nullptr, nullptr);
  EXPECT_EQ(0, oc_sec_ace_count(kDeviceID));

  oc_free_string(&subject.role.authority);
  oc_free_string(&subject.role.role);
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

  oc_tls_remove_peer(&ep);
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

  oc_tls_remove_peer(&ep);
}

TEST_F(TestAcl, oc_sec_check_acl_GETinRFOTM)
{
  // oic/d, oic/p and oic/res are accessible to GET requests in RFOTM
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(kDeviceID);
  ASSERT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;

  std::vector<oc_core_resource_t> resources{ OCF_P, OCF_D, OCF_RES };
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

    pstat->s = OC_DOS_RFPRO;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, svr, &ep));
    pstat->s = OC_DOS_RFNOP;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, svr, &ep));
    pstat->s = OC_DOS_SRESET;
    EXPECT_FALSE(oc_sec_check_acl(OC_GET, svr, &ep));
  }
}

#endif /* OC_SECURITY */

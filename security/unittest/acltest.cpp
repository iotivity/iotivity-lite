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

#include "port/oc_network_event_handler_internal.h"
#include "security/oc_acl_internal.h"
#include "security/oc_pstat.h"
#include "util/oc_list.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_tls.h"
#include "oc_uuid.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include "gtest/gtest.h"
#include <string>

#ifdef OC_SECURITY

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
    oc_ri_init();
    oc_network_event_handler_mutex_init();
    oc_core_init();
    oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr);
    oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(), kDeviceName.c_str(),
                  kOCFSpecVersion.c_str(), kOCFDataModelVersion.c_str(),
                  nullptr, nullptr);
    device_id_ = 0;
    oc_sec_acl_init();
  }

  void TearDown() override
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_sec_acl_free();
    oc_ri_shutdown();
    oc_tls_shutdown();
    oc_connectivity_shutdown(0);
    oc_network_event_handler_mutex_destroy();
    oc_core_shutdown();
  }

public:
  size_t device_id_;
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
  EXPECT_EQ(true, oc_sec_acl_add_bootstrap_acl(device_id_));
  const oc_sec_acl_t *acl = oc_sec_get_acl(device_id_);
  EXPECT_NE(nullptr, acl);
  EXPECT_EQ(1, oc_sec_ace_count(device_id_));
}

TEST_F(TestAcl, oc_sec_acl_clear)
{
  oc_ace_subject_t anon_clear;
  memset(&anon_clear, 0, sizeof(oc_ace_subject_t));
  anon_clear.conn = OC_CONN_ANON_CLEAR;
  EXPECT_EQ(true, oc_sec_ace_update_res(OC_SUBJECT_CONN, &anon_clear, -1,
                                        OC_PERM_RETRIEVE, nullptr, "/test/a",
                                        OC_ACE_NO_WC, device_id_, nullptr));

  oc_uuid_t uuid = { { 0 } };
  oc_gen_uuid(&uuid);
  oc_ace_subject_t subject;
  memset(&subject, 0, sizeof(oc_ace_subject_t));
  memcpy(&subject.uuid, &uuid, sizeof(oc_uuid_t));
  EXPECT_EQ(true, oc_sec_ace_update_res(OC_SUBJECT_UUID, &subject, -1,
                                        OC_PERM_UPDATE, nullptr, "/test/b",
                                        OC_ACE_NO_WC, device_id_, nullptr));

  memset(&subject, 0, sizeof(oc_ace_subject_t));
  std::string testRole{ "test.role" };
  std::string testAuthority{ "test.authority" };
  oc_new_string(&subject.role.role, testRole.c_str(), testRole.length());
  oc_new_string(&subject.role.authority, testAuthority.c_str(),
                testAuthority.length());
  EXPECT_EQ(true, oc_sec_ace_update_res(OC_SUBJECT_ROLE, &subject, -1,
                                        OC_PERM_NOTIFY, nullptr, "/test/c",
                                        OC_ACE_NO_WC, device_id_, nullptr));
  EXPECT_EQ(3, oc_sec_ace_count(device_id_));

  oc_sec_acl_clear(
    device_id_, [](const oc_sec_ace_t *, void *) { return false; }, nullptr);
  EXPECT_EQ(3, oc_sec_ace_count(device_id_));

  oc_sec_ace_t *ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, &anon_clear, /*aceid*/ -1,
                            /*permission*/ 0, /*tag*/ nullptr,
                            /*match_tag*/ false, device_id_);
  EXPECT_NE(nullptr, ace);
  oc_sec_acl_clear(
    device_id_,
    [](const oc_sec_ace_t *entry, void *) {
      return entry->subject_type == OC_SUBJECT_CONN;
    },
    nullptr);
  EXPECT_EQ(2, oc_sec_ace_count(device_id_));
  ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_CONN, &anon_clear, /*aceid*/ -1,
                            /*permission*/ 0, /*tag*/ nullptr,
                            /*match_tag*/ false, device_id_);
  EXPECT_EQ(nullptr, ace);

  ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_ROLE, &subject,
                            /*aceid*/ -1, /*permission*/ 0,
                            /*tag*/ nullptr, /*match_tag*/ false, device_id_);
  EXPECT_NE(nullptr, ace);
  int aceid{ ace->aceid };
  oc_sec_acl_clear(
    device_id_,
    [](const oc_sec_ace_t *entry, void *data) {
      const auto *id = static_cast<int *>(data);
      return entry->aceid == *id;
    },
    &aceid);
  ace =
    oc_sec_acl_find_subject(nullptr, OC_SUBJECT_ROLE, &subject,
                            /*aceid*/ -1, /*permission*/ 0,
                            /*tag*/ nullptr, /*match_tag*/ false, device_id_);
  EXPECT_EQ(nullptr, ace);

  oc_sec_acl_clear(device_id_, nullptr, nullptr);
  EXPECT_EQ(0, oc_sec_ace_count(device_id_));

  oc_free_string(&subject.role.authority);
  oc_free_string(&subject.role.role);
}

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
static const std::string kResourceURI = "/LightResourceURI";
static const std::string kResourceName = "roomlights";

static void
onGet(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)request;
  (void)iface_mask;
  (void)user_data;
}

TEST_F(TestAcl, oc_sec_check_acl_in_RFOTM)
{
  oc_sec_pstat_init();
  oc_sec_pstat_t *pstat = oc_sec_get_pstat(device_id_);
  EXPECT_NE(nullptr, pstat);
  pstat->s = OC_DOS_RFOTM;
  oc_resource_t *res =
    oc_new_resource(kResourceName.c_str(), kResourceURI.c_str(), 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
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

#endif /* OC_SECURITY */

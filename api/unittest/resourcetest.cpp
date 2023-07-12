/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include "oc_enums.h"
#include "oc_ri.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "util/oc_features.h"

#include <array>
#include <gtest/gtest.h>
#include <vector>

static constexpr size_t kDeviceID = 0;

class TestResource : public testing::Test {};

TEST_F(TestResource, SetDiscoverable)
{
  oc_resource_t res{};
  oc_resource_set_discoverable(&res, true);
  EXPECT_NE(0, res.properties & OC_DISCOVERABLE);

  oc_resource_set_discoverable(&res, false);
  EXPECT_EQ(0, res.properties & OC_DISCOVERABLE);
}

#ifdef OC_HAS_FEATURE_PUSH

TEST_F(TestResource, SetPushable)
{
  oc_resource_t res{};
  oc_resource_set_pushable(&res, true);
  EXPECT_NE(0, res.properties & OC_PUSHABLE);

  oc_resource_set_pushable(&res, false);
  EXPECT_EQ(0, res.properties & OC_PUSHABLE);
}

#endif /* OC_HAS_FEATURE_PUSH */

TEST_F(TestResource, SetObservable)
{
  oc_resource_t res{};
  oc_resource_set_observable(&res, true);
  EXPECT_NE(0, res.properties & OC_OBSERVABLE);

  oc_resource_set_observable(&res, false);
  EXPECT_EQ(0, res.properties & OC_OBSERVABLE);
}

TEST_F(TestResource, SetPeriodicObservable)
{
  oc_resource_t res{};
  oc_resource_set_periodic_observable(&res, 42);
  EXPECT_EQ(OC_OBSERVABLE | OC_PERIODIC,
            res.properties & (OC_OBSERVABLE | OC_PERIODIC));
  EXPECT_EQ(42, res.observe_period_seconds);

  oc_resource_set_observable(&res, false);
  EXPECT_EQ(0, res.properties & (OC_OBSERVABLE | OC_PERIODIC));
}

#ifdef OC_OSCORE

TEST_F(TestResource, SetSecureMcast)
{
  oc_resource_set_secure_mcast(nullptr, true);
  oc_resource_set_secure_mcast(nullptr, false);

  oc_resource_t res{};
  oc_resource_set_secure_mcast(&res, true);
  EXPECT_NE(0, res.properties & OC_SECURE_MCAST);

  oc_resource_set_secure_mcast(&res, false);
  EXPECT_EQ(0, res.properties & OC_SECURE_MCAST);
}

#endif /* OC_OSCORE */

class TestResourceWithDevice : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_set_send_response_callback(SendResponseCallback);
    EXPECT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_t *con = oc_core_get_resource_by_index(OCF_CON, kDeviceID);
    ASSERT_NE(nullptr, con);
    oc_resource_set_access_in_RFOTM(con, true, OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
    oc_set_send_response_callback(nullptr);
    m_send_response_cb_invoked = false;
  }
  static void SendResponseCallback(oc_request_t *request,
                                   oc_status_t response_code)
  {
    (void)request;
    (void)response_code;
    m_send_response_cb_invoked = true;
  }
  static bool IsSendResponseCallbackInvoked()
  {
    return m_send_response_cb_invoked;
  }

private:
  static bool m_send_response_cb_invoked;
};

bool TestResourceWithDevice::m_send_response_cb_invoked = false;

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

constexpr oc_pos_description_t kBaselinePosDesc = OC_POS_CENTRE;
constexpr oc_enum_t kBaselineFuncDesc = OC_ENUM_TESTING;
constexpr struct oc_pos_rel_t
{
  double x;
  double y;
  double z;
} kBaselinePosRel{ 42.0, 13.37, 10.01 };
constexpr oc_locn_t kBaselineLocn = OCF_LOCN_DUNGEON;

static void
checkBaselineProperties(const oc_rep_t *rep)
{
  // if
  // rt
  // tag-pos-desc
  // tag-func-desc
  // tag-locn
  // tag-pos-rel

  char *str = nullptr;
  size_t size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "n", &str, &size));
  EXPECT_STREQ("Test Device", str);

  oc_string_array_t arr{};
  size = 0;
  EXPECT_TRUE(oc_rep_get_string_array(rep, "rt", &arr, &size));
  EXPECT_EQ(1, size);
  EXPECT_STREQ("oic.wk.con", oc_string_array_get_item(arr, 0));

  str = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "tag-pos-desc", &str, &size));
  EXPECT_STREQ(oc_enum_pos_desc_to_str(kBaselinePosDesc), str);

  double *darr = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_double_array(rep, "tag-pos-rel", &darr, &size));
  EXPECT_EQ(3, size);
  EXPECT_EQ(kBaselinePosRel.x, darr[0]);
  EXPECT_EQ(kBaselinePosRel.y, darr[1]);
  EXPECT_EQ(kBaselinePosRel.z, darr[2]);

  str = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "tag-func-desc", &str, &size));
  EXPECT_STREQ(oc_enum_to_str(kBaselineFuncDesc), str);

  str = nullptr;
  size = 0;
  EXPECT_TRUE(oc_rep_get_string(rep, "tag-locn", &str, &size));
  EXPECT_STREQ(oc_enum_locn_to_str(kBaselineLocn), str);
}

TEST_F(TestResourceWithDevice, BaselineInterfaceProperties)
{
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  auto get_handler = [](oc_client_response_t *data) {
    ASSERT_EQ(OC_STATUS_OK, data->code);
    oc::TestDevice::Terminate();
    auto *invoked = static_cast<bool *>(data->user_data);
    *invoked = true;

    oc_rep_t *rep = data->payload;
    while (rep != nullptr) {
      EXPECT_TRUE(oc_rep_is_baseline_interface_property(rep));
      rep = rep->next;
    }
    checkBaselineProperties(data->payload);
  };

  oc_resource_t *con = oc_core_get_resource_by_index(OCF_CON, kDeviceID);
  EXPECT_NE(nullptr, con);

  oc_resource_tag_pos_desc(con, kBaselinePosDesc);
  oc_resource_tag_pos_rel(con, kBaselinePosRel.x, kBaselinePosRel.y,
                          kBaselinePosRel.z);
  oc_resource_tag_func_desc(con, kBaselineFuncDesc);
  oc_resource_tag_locn(con, kBaselineLocn);

  bool invoked = false;
  EXPECT_TRUE(oc_do_get("/oc/con", ep, "if=" OC_IF_BASELINE_STR, get_handler,
                        HIGH_QOS, &invoked));
  oc::TestDevice::PoolEvents(5);

  EXPECT_TRUE(IsSendResponseCallbackInvoked());

  EXPECT_TRUE(invoked);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

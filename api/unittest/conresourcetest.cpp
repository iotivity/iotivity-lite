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

#include "api/oc_con_resource_internal.h"
#include "api/oc_core_res_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_core_res.h"
#include "oc_enums.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_macros_internal.h"

#include <functional>
#include <gtest/gtest.h>
#include <optional>
#include <string>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };

static constexpr std::string_view kDeviceName{ "Test Device 1" };

struct ConResourceData
{
  std::string name;
  oc_locn_t locn;
};

class TestConResourceWithDevice : public ::testing::Test {
public:
  static void SetUpTestCase()
  {
    oc::TestDevice::SetServerDevices({
      {
        /*rt=*/"oic.d.test1",
        /*name=*/std::string(kDeviceName),
        /*spec_version=*/"ocf.1.0.0",
        /*data_model_version=*/"ocf.res.1.0.0",
        /*uri=*/"/oic/d",
      },
    });
    oc_set_con_res_announced(true);
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_CON, kDeviceID, false,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
  }

  void SetUp() override
  {
    oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, kDeviceID);
    ASSERT_NE(nullptr, dev);
    oc_resource_tag_locn(dev, OCF_LOCN_UNKNOWN);
    oc_core_device_set_name(kDeviceID, kDeviceName.data(),
                            kDeviceName.length());
    oc_set_con_write_cb(nullptr);
  }

  static ConResourceData decodePayload(const oc_rep_t *rep)
  {
    ConResourceData crd{};
    for (; rep != nullptr; rep = rep->next) {
      if (rep->type != OC_REP_STRING) {
        continue;
      }
      if (oc_rep_is_property(rep, OC_CON_PROP_NAME,
                             OC_CHAR_ARRAY_LEN(OC_CON_PROP_NAME))) {
        crd.name = std::string(oc_string(rep->value.string));
        continue;
      }
      if (oc_rep_is_property(rep, OC_CON_PROP_LOCATION,
                             OC_CHAR_ARRAY_LEN(OC_CON_PROP_LOCATION))) {
        bool is_valid = false;
        crd.locn = oc_str_to_enum_locn(rep->value.string, &is_valid);
        continue;
      }
    }
    return crd;
  }

  static void checkConData(std::string_view name,
                           oc_locn_t locn = OCF_LOCN_UNKNOWN)
  {
    const oc_device_info_t *info = oc_core_get_device_info(kDeviceID);
    ASSERT_NE(nullptr, info);
    EXPECT_STREQ(name.data(), oc_string(info->name));
    const oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, kDeviceID);
    ASSERT_NE(nullptr, dev);
    EXPECT_EQ(locn, dev->tag_locn);
  }
};

TEST_F(TestConResourceWithDevice, GetResourceByIndex_F)
{
  EXPECT_EQ(nullptr,
            oc_core_get_resource_by_index(OCF_CON, /*device*/ SIZE_MAX));
}

TEST_F(TestConResourceWithDevice, GetResourceByIndex)
{
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_CON, kDeviceID));
}

TEST_F(TestConResourceWithDevice, GetResourceByURI_F)
{
  oc_set_con_res_announced(false);
  EXPECT_NE(nullptr, oc_core_get_resource_by_index(OCF_CON, kDeviceID));
  oc_set_con_res_announced(true);

  EXPECT_EQ(nullptr, oc_core_get_resource_by_uri_v1(
                       OC_CON_URI, OC_CHAR_ARRAY_LEN(OC_CON_URI),
                       /*device*/ SIZE_MAX));
}

TEST_F(TestConResourceWithDevice, GetResourceByURI)
{
  oc_resource_t *res = oc_core_get_resource_by_uri_v1(
    OC_CON_URI, OC_CHAR_ARRAY_LEN(OC_CON_URI), kDeviceID);
  EXPECT_NE(nullptr, res);

  EXPECT_STREQ(OC_CON_URI, oc_string(res->uri));
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

template<oc_status_t CODE>
static std::optional<ConResourceData>
getRequest(const std::string &query)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  if (!epOpt.has_value()) {
    return {};
  }
  auto ep = std::move(*epOpt);

  ConResourceData crd{};
  auto get_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(CODE, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<ConResourceData *>(data->user_data) =
      TestConResourceWithDevice::decodePayload(data->payload);
  };

  auto timeout = 1s;
  EXPECT_TRUE(oc_do_get_with_timeout(OC_CON_URI, &ep, query.c_str(),
                                     timeout.count(), get_handler, HIGH_QOS,
                                     &crd));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  return crd;
}

TEST_F(TestConResourceWithDevice, GetRequest)
{
  oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  ASSERT_NE(nullptr, dev);
  oc_resource_tag_locn(dev, OCF_LOCN_MASTERBEDROOM);

  auto crd = getRequest<OC_STATUS_OK>("if=" OC_IF_BASELINE_STR);
  ASSERT_TRUE(crd.has_value());
  EXPECT_STREQ(kDeviceName.data(), crd->name.c_str());
  EXPECT_EQ(OCF_LOCN_MASTERBEDROOM, crd->locn);
}

TEST_F(TestConResourceWithDevice, GetRequest_NoLocation)
{
  oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  ASSERT_NE(nullptr, dev);
  oc_resource_tag_locn(dev, static_cast<oc_locn_t>(0));

  auto crd = getRequest<OC_STATUS_OK>("");
  ASSERT_TRUE(crd.has_value());
  EXPECT_STREQ(kDeviceName.data(), crd->name.c_str());
  EXPECT_EQ(0, crd->locn);
}

template<oc_status_t CODE>
static void
updateRequest(oc_method_t method, const std::function<void()> &payloadFn)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(CODE, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  if (method == OC_POST) {
    ASSERT_TRUE(
      oc_init_post(OC_CON_URI, &ep, nullptr, post_handler, HIGH_QOS, &invoked));
  } else {
    ASSERT_TRUE(
      oc_init_put(OC_CON_URI, &ep, nullptr, post_handler, HIGH_QOS, &invoked));
  }

  payloadFn();

  auto timeout = 1s;
  if (method == OC_POST) {
    ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  } else {
    ASSERT_TRUE(oc_do_put_with_timeout(timeout.count()));
  }

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestConResourceWithDevice, PostRequest)
{
  static constexpr std::string_view kNewName = "new name";

  static bool conWriteCBInvoked = false;
  oc_set_con_write_cb([](size_t device, const oc_rep_t *rep) {
    EXPECT_EQ(kDeviceID, device);
    auto crd = decodePayload(rep);
    EXPECT_STREQ(kNewName.data(), crd.name.c_str());
    conWriteCBInvoked = true;
  });

  updateRequest<OC_STATUS_CHANGED>(OC_POST, []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string_v1(root, n, kNewName.data(), kNewName.length());
    oc_rep_end_root_object();
  });

  EXPECT_TRUE(conWriteCBInvoked);
  checkConData(kNewName);
}

TEST_F(TestConResourceWithDevice, PostRequest_FailEmpty)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_POST, []() {
    oc_rep_start_root_object();
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PostRequest_FailEmptyName)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_POST, []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string_v1(root, n, "", 0);
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PostRequest_InvalidNameType)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_POST, []() {
    oc_rep_start_root_object();
    oc_rep_set_int(root, n, 42);
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PostRequest_FailInvalidProperty)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_POST, []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, n, "new name");
    oc_rep_set_text_string(root, locn, oc_enum_locn_to_str(OCF_LOCN_SPA));
    oc_rep_set_text_string(root, invalid, "invalid");
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PutRequest)
{
  oc_locn_t locn = OCF_LOCN_YARD;
  updateRequest<OC_STATUS_CHANGED>(OC_PUT, [locn]() {
    oc_rep_start_root_object();
    const auto *locn_str = oc_enum_locn_to_str(locn);
    ASSERT_NE(nullptr, locn_str);
    oc_rep_set_text_string(root, locn, locn_str);
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName, locn);
}

TEST_F(TestConResourceWithDevice, PutRequest_FailEmptyLocation)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_PUT, []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string_v1(root, locn, "", 0);
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PutRequest_FailInvalidLocationType)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_PUT, []() {
    oc_rep_start_root_object();
    oc_rep_set_int(root, locn, 42);
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PutRequest_FailInvalidLocationValue)
{
  updateRequest<OC_STATUS_BAD_REQUEST>(OC_PUT, []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, locn, "invalid");
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName);
}

TEST_F(TestConResourceWithDevice, PutRequest_FailDisabledLocation)
{
  oc_resource_t *dev = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  ASSERT_NE(nullptr, dev);
  oc_resource_tag_locn(dev, static_cast<oc_locn_t>(0));

  updateRequest<OC_STATUS_BAD_REQUEST>(OC_PUT, []() {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, locn, oc_enum_locn_to_str(OCF_LOCN_ATTIC));
    oc_rep_end_root_object();
  });

  checkConData(kDeviceName, static_cast<oc_locn_t>(0));
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

TEST_F(TestConResourceWithDevice, DeleteRequest_FailMethodNotSupported)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);
#ifdef OC_SECURITY
  oc_status_t code = OC_STATUS_UNAUTHORIZED;
#else  /* !OC_SECURITY */
  oc_status_t code = OC_STATUS_METHOD_NOT_ALLOWED;
#endif /* OC_SECURITY */
  oc::testNotSupportedMethod(OC_DELETE, &ep, OC_CON_URI, nullptr, code);
}

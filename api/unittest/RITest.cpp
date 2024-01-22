/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *           2021 CASCODA LTD        All Rights Reserved.
 *           2024 ETRI               All Rights Reserved.
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

#ifdef _WIN32
// don't define max() macro
#define NOMINMAX
#endif /* _WIN32 */

#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "port/oc_network_event_handler_internal.h"

#ifdef OC_HAS_FEATURE_BRIDGE
#include "oc_api.h"
#include "oc_core_res.h"
#include "security/oc_svr_internal.h"
#include "api/oc_core_res_internal.h"
#include <set>
#endif /* OC_HAS_FEATURE_BRIDGE */

#ifdef OC_TCP
#include "messaging/coap/signal_internal.h"
#endif /* OC_TCP */

#include <gtest/gtest.h>
#include <limits>
#include <set>
#include <string>
#include <vector>

class TestOcRi : public testing::Test {
public:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
#ifdef OC_HAS_FEATURE_BRIDGE
    oc_core_init();
    oc_sec_svr_create();
#endif /* OC_HAS_FEATURE_BRIDGE */
  }

  void TearDown() override
  {
#ifdef OC_HAS_FEATURE_BRIDGE
    oc_core_shutdown();
#endif /* OC_HAS_FEATURE_BRIDGE */
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

#ifdef OC_HAS_FEATURE_BRIDGE
static void
get_handler(oc_request_t *request, oc_interface_mask_t iface_mask,
            void *user_data)
{
}

TEST_F(TestOcRi, GetNDeleteAppResourceByIndex)
{
  std::string deviceName{ "Device1" };
  std::string deviceURI{ "/oic/d" };
  std::string deviceType{ "oic.d.light" };
  std::string OCFSpecVersion{ "ocf.2.2.6" };
  std::string OCFDataModelVersion{ "ocf.res.1.0.0" };

  /* -------------------------------------------------*/
  /*
   * oc_ri_get_app_resource_by_device(device, reset)
   */
  /*--------------------------------------------------*/

  auto deviceIndex = oc_add_device(
    deviceURI.c_str(), deviceType.c_str(), deviceName.c_str(),
    OCFSpecVersion.c_str(), OCFDataModelVersion.c_str(), nullptr, nullptr);

  auto deviceInfo = oc_core_get_device_info(deviceIndex);

  ASSERT_NE(deviceInfo, nullptr);
  EXPECT_STREQ(deviceName.c_str(), oc_string(deviceInfo->name));
  EXPECT_EQ(0, deviceIndex);

  /*
   * add Resources
   */
  std::string rscURI1{ "/rsc1" };
  auto resource1 = oc_new_resource(nullptr, rscURI1.c_str(), 0, deviceIndex);
  oc_resource_set_request_handler(resource1, OC_GET, get_handler, nullptr);
  ASSERT_NE(nullptr, resource1);
  EXPECT_EQ(deviceIndex, resource1->device);
  oc_add_resource(resource1);

  std::string rscURI2{ "/rsc2" };
  auto resource2 = oc_new_resource(nullptr, rscURI2.c_str(), 0, deviceIndex);
  oc_resource_set_request_handler(resource2, OC_GET, get_handler, nullptr);
  ASSERT_NE(nullptr, resource2);
  EXPECT_EQ(deviceIndex, resource2->device);
  oc_add_resource(resource2);

  /*
   * add collection Resource
   */
  std::string colURI1 = "/col1";
  auto colResource3 =
    oc_new_collection(nullptr, colURI1.c_str(), 0, deviceIndex);
  ASSERT_NE(nullptr, colResource3);
  EXPECT_STREQ(colURI1.c_str(), oc_string(colResource3->uri));
  EXPECT_EQ(deviceIndex, colResource3->device);
  oc_add_collection_v1(colResource3);

  /*
   * try to find from the first entry...
   */
  auto rsc1 = oc_ri_get_app_resource_by_device(deviceIndex, true);
  ASSERT_NE(rsc1, nullptr);

  auto rsc2 = oc_ri_get_app_resource_by_device(deviceIndex, true);
  ASSERT_NE(rsc2, nullptr);
  EXPECT_STREQ(oc_string(rsc1->uri), oc_string(rsc2->uri));

  /*
   * try to resume search from the entry which was seen last...
   */
  rsc1 = oc_ri_get_app_resource_by_device(deviceIndex, true);
  ASSERT_NE(rsc1, nullptr);

  rsc2 = oc_ri_get_app_resource_by_device(deviceIndex, false);
  ASSERT_NE(rsc2, nullptr);
  EXPECT_STRNE(oc_string(rsc1->uri), oc_string(rsc2->uri));

  /*
   * try to find all app resources mapped to a Device
   */
  std::set<std::string> rscSet{ rscURI1.c_str(), rscURI2.c_str(),
                                colURI1.c_str() };

  rsc1 = oc_ri_get_app_resource_by_device(deviceIndex, true);
  while (rsc1) {
    rscSet.erase(oc_string(rsc1->uri));
    rsc1 = oc_ri_get_app_resource_by_device(deviceIndex, false);
  }

  EXPECT_EQ(true, rscSet.empty());

  /* -------------------------------------------------*/
  /*
   * oc_ri_delete_app_resources_per_device(index)
   */
  /*--------------------------------------------------*/
  oc_ri_delete_app_resources_per_device(deviceIndex);
  rsc1 = oc_ri_get_app_resource_by_device(deviceIndex, true);

  EXPECT_EQ(nullptr, rsc1);
}

#endif /* OC_HAS_FEATURE_BRIDGE */

TEST_F(TestOcRi, StatusCodeToCoapCode)
{
  for (int i = OC_STATUS_OK; i < __NUM_OC_STATUS_CODES__; ++i) {
    EXPECT_EQ(oc_status_code_unsafe(static_cast<oc_status_t>(i)),
              oc_status_code(static_cast<oc_status_t>(i)));
  }

  // OC_IGNORE is a special value that translates to CLEAR_TRANSACTION
  // others return -1
  for (int i = __NUM_OC_STATUS_CODES__; i < OC_CANCELLED; ++i) {
    if (i == OC_IGNORE) {
      EXPECT_EQ(CLEAR_TRANSACTION, oc_status_code(OC_IGNORE));
      continue;
    }
    EXPECT_EQ(-1, oc_status_code(static_cast<oc_status_t>(i)));
  }
}

TEST_F(TestOcRi, CoapCodeToStatusCode)
{
  std::vector<coap_status_t> coapCodes{
    CREATED_2_01,
    DELETED_2_02,
    VALID_2_03,
    CHANGED_2_04,
    CONTENT_2_05,

    BAD_REQUEST_4_00,
    UNAUTHORIZED_4_01,
    BAD_OPTION_4_02,
    FORBIDDEN_4_03,
    NOT_FOUND_4_04,
    METHOD_NOT_ALLOWED_4_05,
    NOT_ACCEPTABLE_4_06,
    REQUEST_ENTITY_TOO_LARGE_4_13,

    INTERNAL_SERVER_ERROR_5_00,
    NOT_IMPLEMENTED_5_01,
    BAD_GATEWAY_5_02,
    SERVICE_UNAVAILABLE_5_03,
    GATEWAY_TIMEOUT_5_04,
    PROXYING_NOT_SUPPORTED_5_05,

#ifdef OC_TCP
    static_cast<coap_status_t>(PONG_7_03),
#endif /* OC_TCP */
  };

  for (auto coapCode : coapCodes) {
    EXPECT_NE(-1, oc_coap_status_to_status(coapCode));
  }
}

TEST_F(TestOcRi, CoapCodeToStatusCode_F)
{
  std::vector<coap_status_t> coapCodesWithoutConversion{
    COAP_NO_ERROR,
    CONTINUE_2_31,
    PRECONDITION_FAILED_4_12,

#ifdef OC_TCP
    static_cast<coap_status_t>(CSM_7_01),
    static_cast<coap_status_t>(PING_7_02),
    static_cast<coap_status_t>(RELEASE_7_04),
    static_cast<coap_status_t>(ABORT_7_05),
#endif /* OC_TCP */
  };

  for (auto coapCode : coapCodesWithoutConversion) {
    EXPECT_EQ(-1, oc_coap_status_to_status(coapCode));
  }
}

TEST_F(TestOcRi, StatusCodeToStr)
{
  for (int i = OC_STATUS_OK; i < __NUM_OC_STATUS_CODES__; ++i) {
    std::string str = oc_status_to_str(static_cast<oc_status_t>(i));
    EXPECT_FALSE(str.empty());
  }
  for (int i = __NUM_OC_STATUS_CODES__; i < OC_CANCELLED; ++i) {
    std::string str = oc_status_to_str(static_cast<oc_status_t>(i));
    EXPECT_TRUE(str.empty());
  }
}

TEST_F(TestOcRi, MethodToStr)
{
  for (int i = OC_GET; i <= OC_FETCH; ++i) {
    std::string str = oc_method_to_str(static_cast<oc_method_t>(i));
    EXPECT_FALSE(str.empty());
  }

  std::string str = oc_method_to_str(static_cast<oc_method_t>(0));
  EXPECT_TRUE(str.empty());
  str = oc_method_to_str(std::numeric_limits<oc_method_t>::min());
  EXPECT_TRUE(str.empty());
  str = oc_method_to_str(std::numeric_limits<oc_method_t>::max());
  EXPECT_TRUE(str.empty());
}

static std::vector<oc_interface_mask_t>
getAllInterfaces()
{
  return {
    OC_IF_BASELINE,
    OC_IF_LL,
    OC_IF_B,
    OC_IF_R,
    OC_IF_RW,
    OC_IF_A,
    OC_IF_S,
    OC_IF_CREATE,
    OC_IF_W,
    OC_IF_STARTUP,
    OC_IF_STARTUP_REVERT,
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
    PLGD_IF_ETAG,
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  };
}

static std::vector<std::string>
getAllInterfaceStrings()
{
  return {
    OC_IF_BASELINE_STR,
    OC_IF_LL_STR,
    OC_IF_B_STR,
    OC_IF_R_STR,
    OC_IF_RW_STR,
    OC_IF_A_STR,
    OC_IF_S_STR,
    OC_IF_CREATE_STR,
    OC_IF_W_STR,
    OC_IF_STARTUP_STR,
    OC_IF_STARTUP_REVERT_STR,
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
    PLGD_IF_ETAG_STR,
#endif /* OC_HAS_FEATURE_ETAG_INTERFACE */
  };
}

TEST_F(TestOcRi, GetInterfaceMask_P)
{
  EXPECT_EQ(0, oc_ri_get_interface_mask("", 0));

  std::vector<oc_interface_mask_t> all_interfaces{ getAllInterfaces() };
  std::vector<std::string> all_interface_strs{ getAllInterfaceStrings() };
  ASSERT_EQ(all_interfaces.size(), all_interface_strs.size());

  for (size_t i = 0; i < all_interface_strs.size(); ++i) {
    oc_interface_mask_t ifm = oc_ri_get_interface_mask(
      all_interface_strs[i].c_str(), all_interface_strs[i].length());
    EXPECT_EQ(all_interfaces[i], ifm);
  }
}

TEST_F(TestOcRi, InterfaceSupportsMethod)
{
  // read-only -> GET
  std::vector<oc_interface_mask_t> readOnlyInterfaces{
    OC_IF_LL,
    OC_IF_S,
    OC_IF_R,
#ifdef OC_HAS_FEATURE_ETAG_INTERFACE
    PLGD_IF_ETAG,
#endif
  };

  for (auto ifm : readOnlyInterfaces) {
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_GET));
    EXPECT_FALSE(oc_ri_interface_supports_method(ifm, OC_POST));
    EXPECT_FALSE(oc_ri_interface_supports_method(ifm, OC_PUT));
    EXPECT_FALSE(oc_ri_interface_supports_method(ifm, OC_DELETE));
  }

  // write-only -> POST/PUT/DELETE
  std::vector<oc_interface_mask_t> writeOnlyInterfaces{ OC_IF_W };
  for (auto ifm : writeOnlyInterfaces) {
    EXPECT_FALSE(oc_ri_interface_supports_method(ifm, OC_GET));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_POST));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_PUT));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_DELETE));
  }

  // create -> GET/POST/PUT
  std::vector<oc_interface_mask_t> createInterfaces{ OC_IF_CREATE };
  for (auto ifm : createInterfaces) {
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_GET));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_POST));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_PUT));
    EXPECT_FALSE(oc_ri_interface_supports_method(ifm, OC_DELETE));
  }

  // read-write -> GET/POST/PUT/DELETE
  std::vector<oc_interface_mask_t> readWriteInterfaces{
    OC_IF_RW, OC_IF_B,       OC_IF_BASELINE,
    OC_IF_A,  OC_IF_STARTUP, OC_IF_STARTUP_REVERT,
  };
  for (auto ifm : readWriteInterfaces) {
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_GET));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_POST));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_PUT));
    EXPECT_TRUE(oc_ri_interface_supports_method(ifm, OC_DELETE));
  }
}

TEST_F(TestOcRi, InterfaceSupportsMethod_F)
{
  auto invalid = static_cast<oc_interface_mask_t>(0);
  EXPECT_FALSE(oc_ri_interface_supports_method(invalid, OC_GET));
  EXPECT_FALSE(oc_ri_interface_supports_method(invalid, OC_POST));
  EXPECT_FALSE(oc_ri_interface_supports_method(invalid, OC_PUT));
  EXPECT_FALSE(oc_ri_interface_supports_method(invalid, OC_DELETE));
}

static oc_event_callback_retval_t
test_timed_callback(void *data)
{
  (void)data;
  return OC_EVENT_DONE;
}

TEST_F(TestOcRi, RiTimedCallbacks_P)
{
  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
  int data;
  oc_ri_add_timed_event_callback_seconds(&data, test_timed_callback, 0);

  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, false));
  EXPECT_TRUE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
  EXPECT_TRUE(
    oc_ri_has_timed_event_callback(&data, test_timed_callback, false));

  oc_ri_remove_timed_event_callback(&data, test_timed_callback);
  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
}

TEST_F(TestOcRi, RiTimedCallbacksFilter_P)
{
  struct thing_t
  {
    int value;
  };
  thing_t a{ 1 };
  thing_t b = a;
  oc_ri_add_timed_event_callback_seconds(&a, test_timed_callback, 0);
  oc_ri_remove_timed_event_callback(&b, test_timed_callback);
  // comparison by pointer address will fail to match the data, so the
  // callback won't be removed
  EXPECT_TRUE(oc_ri_has_timed_event_callback(&a, test_timed_callback, false));

  auto match_by_value_filter = [](const void *cb_data,
                                  const void *filter_data) {
    const auto *first = static_cast<const thing_t *>(cb_data);
    const auto *second = static_cast<const thing_t *>(filter_data);
    return first->value == second->value;
  };
  oc_ri_remove_timed_event_callback_by_filter(
    test_timed_callback, match_by_value_filter, &b, false, nullptr);
  // matching by value removes the callback
  EXPECT_FALSE(oc_ri_has_timed_event_callback(&a, test_timed_callback, false));
}

TEST_F(TestOcRi, RiTimedCallbacksFilterMatchAll_P)
{
  struct thing_t
  {
    int value;
  };
  thing_t a{ 1 };
  thing_t b = a;
  thing_t c = a;
  oc_ri_add_timed_event_callback_seconds(&a, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(&b, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(&c, test_timed_callback, 0);

  auto match_by_value_filter = [](const void *cb_data,
                                  const void *filter_data) {
    const auto *first = static_cast<const thing_t *>(cb_data);
    const auto *second = static_cast<const thing_t *>(filter_data);
    return first->value == second->value;
  };
  oc_ri_remove_timed_event_callback_by_filter(
    test_timed_callback, match_by_value_filter, &a, true, nullptr);

  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
}

TEST_F(TestOcRi, RiTimedCallbacksFilterDealloc_P)
{
  struct thing_t
  {
    int value;
  };
  thing_t m{ 1 };
  auto *a = new thing_t{ m };
  auto *b = new thing_t{ m };
  auto *c = new thing_t{ m };

  oc_ri_add_timed_event_callback_seconds(a, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(b, test_timed_callback, 0);
  oc_ri_add_timed_event_callback_seconds(c, test_timed_callback, 0);

  auto match_by_value_filter = [](const void *cb_data,
                                  const void *filter_data) {
    const auto *first = static_cast<const thing_t *>(cb_data);
    const auto *second = static_cast<const thing_t *>(filter_data);
    return first->value == second->value;
  };

  auto free_thing = [](void *data) {
    auto *t = static_cast<thing_t *>(data);
    delete t;
  };

  oc_ri_remove_timed_event_callback_by_filter(
    test_timed_callback, match_by_value_filter, &m, true, free_thing);

  EXPECT_FALSE(
    oc_ri_has_timed_event_callback(nullptr, test_timed_callback, true));
}

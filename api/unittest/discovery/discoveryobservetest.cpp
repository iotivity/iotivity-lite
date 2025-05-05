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

#include "util/oc_features.h"

#ifdef OC_DISCOVERY_RESOURCE_OBSERVABLE

#include "discovery.h"

#include "api/oc_con_resource_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/observe_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "tests/gtest/RepPool.h"

using namespace std::chrono_literals;

// payloads are too large for static buffers
#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_APP_DATA_BUFFER_SIZE)

constexpr std::string_view kDynamicURI = "/dyn/observable";

// observe with default (LL) interface
TEST_F(TestDiscoveryWithServer, Observe)
{
  ASSERT_TRUE(oc_get_con_res_announced());

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct observeData
  {
    oc::discovery::LinkDataMap links;
    int observe;
  };
  auto onObserve = [](oc_client_response_t *cr) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, cr->code);
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload, true).data());
    auto *od = static_cast<observeData *>(cr->user_data);
    od->observe = cr->observe_option;
    if (cr->observe_option == OC_COAP_OPTION_OBSERVE_REGISTER ||
        cr->observe_option >= OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
#ifdef OC_HAS_FEATURE_ETAG
      oc::discovery::AssertETag(cr->etag, cr->endpoint, cr->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
      od->links = oc::discovery::ParseLinks(cr->payload);
    }
  };
  observeData od{};
  ASSERT_TRUE(
    oc_do_observe(OCF_RES_URI, &ep, nullptr, onObserve, HIGH_QOS, &od));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, od.observe);
  ASSERT_FALSE(od.links.empty());
  verifyLinks(od.links);
  od.observe = 0;
  od.links.clear();

  // adding a resource should trigger an observe notification
  oc::DynamicResourceHandler handlers{};
  dynamicResources[std::string(kDynamicURI)] = { 2001 };
  handlers.onGet = onGetDynamicResource;
  handlers.onGetData = &dynamicResources[std::string(kDynamicURI)];
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd("Dynamic Resource Observable",
                                 std::string(kDynamicURI),
                                 { "oic.d.observable", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, handlers),
    kDeviceID);
  ASSERT_NE(nullptr, res);
  oc_resource_set_observable(res, true);

  int repeats = 0;
  while (od.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, od.observe);
  ASSERT_FALSE(od.links.empty());
  verifyLinks(od.links);
  od.observe = 0;
  od.links.clear();

  // deleting the resource should also trigger an observe notification
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(res, true));
  repeats = 0;
  while (od.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1, od.observe);
  ASSERT_FALSE(od.links.empty());
  verifyLinks(od.links);
  od.observe = 0;
  od.links.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (od.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, od.observe);
}

// observe with baseline interface
TEST_F(TestDiscoveryWithServer, ObserveBaseline)
{
  ASSERT_TRUE(oc_get_con_res_announced());

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  struct observeBaselineData
  {
    oc::discovery::BaselineData baseline;
    int observe;
  };
  auto onObserve = [](oc_client_response_t *cr) {
    oc::TestDevice::Terminate();
    ASSERT_EQ(OC_STATUS_OK, cr->code);
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload, true).data());
    auto *obd = static_cast<observeBaselineData *>(cr->user_data);
    obd->observe = cr->observe_option;
    if (cr->observe_option == OC_COAP_OPTION_OBSERVE_REGISTER ||
        cr->observe_option >= OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
#ifdef OC_HAS_FEATURE_ETAG
      oc::discovery::AssertETag(cr->etag, cr->endpoint, cr->endpoint->device);
#endif /* OC_HAS_FEATURE_ETAG */
      obd->baseline = oc::discovery::ParseBaseline(cr->payload);
    }
  };
  observeBaselineData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_BASELINE_STR,
                            onObserve, HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.baseline.links.empty());
  verifyLinks(obd.baseline.links);
  obd.observe = 0;
  obd.baseline.links.clear();

  // adding a resource should trigger an observe notification
  oc::DynamicResourceHandler handlers{};
  dynamicResources[std::string(kDynamicURI)] = { 2001 };
  handlers.onGet = onGetDynamicResource;
  handlers.onGetData = &dynamicResources[std::string(kDynamicURI)];
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd(
      "Dynamic Resource Observable", std::string(kDynamicURI),
      { "oic.d.observable", "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
      handlers, OC_DISCOVERABLE | OC_OBSERVABLE),
    kDeviceID);
  ASSERT_NE(nullptr, res);

  int repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, obd.observe);
  ASSERT_FALSE(obd.baseline.links.empty());
  verifyLinks(obd.baseline.links);
  obd.observe = 0;
  obd.baseline.links.clear();

  // deleting the resource should also trigger an observe notification
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(res, true));
  repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1, obd.observe);
  ASSERT_FALSE(obd.baseline.links.empty());
  verifyLinks(obd.baseline.links);
  obd.observe = 0;
  obd.baseline.links.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, obd.observe);
}

#ifdef OC_RES_BATCH_SUPPORT

#ifdef OC_SECURITY

TEST_F(TestDiscoveryWithServer, ObserveBatch_F)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto onObserve = [](oc_client_response_t *cr) {
    oc::TestDevice::Terminate();
    OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
           oc::RepPool::GetJson(cr->payload, true).data());
    *static_cast<bool *>(cr->user_data) = true;
    // insecure batch interface requests are unsupported
    EXPECT_EQ(OC_STATUS_BAD_REQUEST, cr->code);
    EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, cr->observe_option);
  };

  bool invoked = false;
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onObserve,
                            HIGH_QOS, &invoked));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_TRUE(invoked);

  // no observers should exist
  ASSERT_EQ(0, oc_list_length(coap_get_observers()));
}

TEST_F(TestDiscoveryWithServer, ObserveBatch)
{
  // TODO: add support for using secure endpoints for communication in tests
}

#else /* !OC_SECURITY */

struct observeBatchData
{
  oc::discovery::BatchData batch;
  int observe;
};

static void
onBatchObserve(oc_client_response_t *cr)
{
  oc::TestDevice::Terminate();
  OC_DBG("OBSERVE(%d) payload: %s", cr->observe_option,
         oc::RepPool::GetJson(cr->payload, true).data());
  ASSERT_EQ(OC_STATUS_OK, cr->code);
  auto *obd = static_cast<observeBatchData *>(cr->user_data);
  obd->observe = cr->observe_option;
  obd->batch = oc::discovery::ParseBatch(cr->payload);
#ifdef OC_HAS_FEATURE_ETAG
  oc::discovery::AssertETag(cr->etag, cr->endpoint, cr->endpoint->device, true);
  if (cr->observe_option == OC_COAP_OPTION_OBSERVE_REGISTER ||
      cr->observe_option == OC_COAP_OPTION_OBSERVE_NOT_SET) {
    // we have a full payload and the response etag should be the highest etag
    // contained the payload
    oc::discovery::AssertBatchETag(cr->etag, cr->endpoint->device, obd->batch);
  }
#endif /* OC_HAS_FEATURE_ETAG */
}

static void
updateResourceByPost(std::string_view uri, const oc_endpoint_t *endpoint,
                     const std::function<void()> &payloadFn)
{
  auto post_handler = [](oc_client_response_t *data) {
    oc::TestDevice::Terminate();
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  ASSERT_TRUE(oc_init_post(uri.data(), endpoint, nullptr, post_handler, LOW_QOS,
                           &invoked));
  payloadFn();
  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

TEST_F(TestDiscoveryWithServer, ObserveBatchWithResourceUpdate)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  observeBatchData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onBatchObserve,
                            HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  // all resources should be in the first payload
  verifyBatchPayload(obd.batch, &ep);
  obd.observe = 0;
  obd.batch.clear();

  oc_device_info_t *info = oc_core_get_device_info(kDeviceID);
  ASSERT_NE(nullptr, info);
  std::string deviceName = oc_string(info->name);
  // updating the name by the /oc/con resource should trigger a batch observe
  // notification with /oc/con and /oic/d resources
  updateResourceByPost(OC_CON_URI, &ep, [deviceName]() {
    oc_rep_start_root_object();
    oc_rep_set_text_string_v1(root, n, deviceName.c_str(), deviceName.length());
    oc_rep_end_root_object();
  });

  int repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_LE(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  std::vector<const oc_resource_t *> expected{};
  auto *device = oc_core_get_resource_by_index(OCF_D, kDeviceID);
  ASSERT_NE(nullptr, device);
  if ((device->properties & OC_DISCOVERABLE) != 0) {
    expected.emplace_back(device);
  }
  auto *con = oc_core_get_resource_by_index(OCF_CON, kDeviceID);
  ASSERT_NE(nullptr, con);
  if ((con->properties & OC_DISCOVERABLE) != 0) {
    expected.emplace_back(con);
  }
  verifyBatchPayload(obd.batch, expected);
  obd.observe = 0;
  obd.batch.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  // response should be a full batch GET payload with observe option not set
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  verifyBatchPayload(obd.batch, &ep);
}

TEST_F(TestDiscoveryWithServer, ObserveBatchWithResourceAdded)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  observeBatchData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onBatchObserve,
                            HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  // all resources should be in the first payload
  verifyBatchPayload(obd.batch, &ep);
  obd.observe = 0;
  obd.batch.clear();

  // adding a resource should trigger an observe notification
  oc::DynamicResourceHandler handlers{};
  dynamicResources[std::string(kDynamicURI)] = { 2001 };
  handlers.onGet = onGetDynamicResource;
  handlers.onGetData = &dynamicResources[std::string(kDynamicURI)];
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd(
      "Dynamic Resource Observable", std::string(kDynamicURI),
      { "oic.d.observable", "oic.d.test" }, { OC_IF_BASELINE, OC_IF_R },
      handlers, OC_DISCOVERABLE | OC_OBSERVABLE),
    kDeviceID);
  ASSERT_NE(nullptr, res);

  int repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_LE(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  obd.observe = 0;
  obd.batch.clear();

  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(res, true));
  repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  obd.observe = 0;
  obd.batch.clear();

  ASSERT_TRUE(oc_stop_observe(OCF_RES_URI, &ep));
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  // response should be a full batch GET payload with observe option not set
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_NOT_SET, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  verifyBatchPayload(obd.batch, &ep);
}

TEST_F(TestDiscoveryWithServer, ObserveBatchSkipEmptyResourceChange)
{
  ASSERT_TRUE(oc_get_con_res_announced());

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  observeBatchData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onBatchObserve,
                            HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  // all resources should be in the first payload
  verifyBatchPayload(obd.batch, &ep);
  obd.observe = 0;
  obd.batch.clear();

  auto *res = oc_ri_get_app_resource_by_uri(kDynamicURI3.c_str(),
                                            kDynamicURI3.size(), kDeviceID);
  ASSERT_NE(nullptr, res);
  // notification with empty payload should be ignored
  oc_notify_resource_changed(res);
  int repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(0, obd.observe);
  EXPECT_TRUE(obd.batch.empty());
}

TEST_F(TestDiscoveryWithServer, ObserveBatchSkipIgnoreResourceChange)
{
  ASSERT_TRUE(oc_get_con_res_announced());

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  observeBatchData obd{};
  ASSERT_TRUE(oc_do_observe(OCF_RES_URI, &ep, "if=" OC_IF_B_STR, onBatchObserve,
                            HIGH_QOS, &obd));
  oc::TestDevice::PoolEventsMsV1(1s);
  EXPECT_EQ(OC_COAP_OPTION_OBSERVE_REGISTER, obd.observe);
  ASSERT_FALSE(obd.batch.empty());
  // all resources should be in the first payload
  verifyBatchPayload(obd.batch, &ep);
  obd.observe = 0;
  obd.batch.clear();

  auto *res = oc_ri_get_app_resource_by_uri(
    kDynamicURIIgnored.c_str(), kDynamicURIIgnored.size(), kDeviceID);
  ASSERT_NE(nullptr, res);
  // notification with payload from resource that returns OC_IGNORE should be
  // ignored
  oc_notify_resource_changed(res);
  int repeats = 0;
  while (obd.observe == 0 && repeats < 30) {
    oc::TestDevice::PoolEventsMsV1(10ms);
    ++repeats;
  }
  EXPECT_EQ(0, obd.observe);
  EXPECT_TRUE(obd.batch.empty());
}

TEST_F(TestDiscoveryWithServer, ObserveBatchWithEmptyPayload)
{
  // TODO: remove resource from payload -> make it undiscoverable in runtime
  // and see what happens
}

#endif /* OC_SECURITY */

#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_DYNAMIC_ALLOCATION && !OC_APP_DATA_BUFFER_SIZE */

#endif /* OC_DISCOVERY_RESOURCE_OBSERVABLE */

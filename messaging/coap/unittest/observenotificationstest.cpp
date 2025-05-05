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
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ***************************************************************************/

#include "util/oc_features.h"

#ifdef OC_TCP

#include "api/oc_core_res_internal.h"
#include "api/oc_discovery_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_ri_internal.h"
#include "messaging/coap/observe_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_buffer.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/coap/Message.h"
#include "tests/gtest/coap/TCPClient.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#include "tests/gtest/Collection.h"
#endif // OC_COLLECTIONS

#ifdef OC_SECURITY
#include "security/oc_security_internal.h"
#endif // OC_SECURITY

#include "gtest/gtest.h"

#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using namespace oc::coap;

static constexpr size_t kDeviceID{ 0 };

static const std::string kDynamicURI1 = "/dyn/empty";

#ifdef OC_COLLECTIONS
static const std::string powerSwitchRT = "oic.d.power";

static const std::string kCollectionURI1 = "/empty";
static const std::string kColDynamicURI1 = "/empty/1";
#endif // OC_COLLECTIONS

class TestObservationWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    ASSERT_TRUE(oc::TestDevice::StartServer());

    addDynamicResources();

#ifdef OC_COLLECTIONS
    addCollections();
#endif // OC_COLLECTIONS
  }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }

  void SetUp() override { coap_observe_counter_reset(); }

  void TearDown() override { oc::TestDevice::Reset(); }

  static void onGetEmptyResource(oc_request_t *request, oc_interface_mask_t,
                                 void *)
  {
    oc_rep_start_root_object();
    oc_rep_end_root_object();
    oc_send_response(request, OC_STATUS_OK);
  }

  static void addDynamicResources();

#ifdef OC_COLLECTIONS
  static void addCollections();
#endif // OC_COLLECTIONS

  static coap_packet_t getPacket(oc_message_t *msg)
  {
    coap_packet_t packet;
    EXPECT_EQ(COAP_NO_ERROR,
              coap_tcp_parse_message(&packet, msg->data, msg->length, false));
    return packet;
  }

  static void printObservation(const coap_packet_t &packet, int32_t observe)
  {
    (void)packet;
    (void)observe;
#if OC_DBG_IS_ENABLED
    const uint8_t *payload = nullptr;
    size_t payload_len = coap_get_payload(&packet, &payload);

    oc::RepPool pool{};
    oc::oc_rep_unique_ptr rep{ nullptr, nullptr };
    if (payload_len > 0) {
      rep = pool.ParsePayload(payload, payload_len);
    }
    OC_DBG("OBSERVE(%d) payload: %s", observe,
           oc::RepPool::GetJson(rep.get(), true).data());
#endif // OC_DBG_IS_ENABLED
  }

  static void assertObservation(const coap_packet_t &packet, coap_status_t code,
                                const message::token_t &token,
                                bool is_observable, int32_t observe)
  {
    ASSERT_EQ(code, packet.code);
    ASSERT_EQ(token.size(), packet.token_len);
    ASSERT_EQ(0, memcmp(&token[0], packet.token, token.size()));
    int32_t pkt_observe;
    ASSERT_EQ(is_observable, coap_options_get_observe(&packet, &pkt_observe));
    printObservation(packet, pkt_observe);
    if (is_observable) {
      ASSERT_EQ(observe, pkt_observe);
    }
  }

  static void assertObservation(oc_message_t *msg, coap_status_t code,
                                const message::token_t &token,
                                bool is_observable, int32_t observe)
  {
    auto packet = getPacket(msg);
    assertObservation(packet, code, token, is_observable, observe);
  }
};

void
TestObservationWithServer::addDynamicResources()
{
#ifndef OC_DYNAMIC_ALLOCATION
  static_assert(OC_MAX_APP_RESOURCES >= 1, "OC_MAX_APP_RESOURCES >= 1");
#endif // OC_DYNAMIC_ALLOCATION

  oc::DynamicResourceHandler handlers1{};
  handlers1.onGet = onGetEmptyResource;
  auto dynResource1 = oc::makeDynamicResourceToAdd(
    "Dynamic Resource 1", kDynamicURI1, { "oic.d.dynamic", "oic.d.test" },
    { OC_IF_BASELINE, OC_IF_R }, handlers1, OC_OBSERVABLE);
  oc_resource_t *res1 =
    oc::TestDevice::AddDynamicResource(dynResource1, kDeviceID);
  ASSERT_NE(nullptr, res1);
}

#ifdef OC_COLLECTIONS

void
TestObservationWithServer::addCollections()
{
  auto col = oc::NewCollection("col", kCollectionURI1, kDeviceID, "oic.wk.col");
  ASSERT_NE(nullptr, col.get());
#ifdef OC_SECURITY
  oc_resource_make_public(&col->res);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
  oc_resource_set_access_in_RFOTM(&col->res, true, OC_PERM_RETRIEVE);
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
#endif /* OC_SECURITY */
  oc_resource_set_discoverable(&col->res, true);
  oc_resource_set_observable(&col->res, true);
  oc_collection_add_supported_rt(&col->res, powerSwitchRT.c_str());
  oc_collection_add_mandatory_rt(&col->res, powerSwitchRT.c_str());
  ASSERT_TRUE(oc_add_collection_v1(&col->res));
  col.release();
}

#endif // OC_COLLECTIONS

TEST_F(TestObservationWithServer, ObserveDeviceName)
{
  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP, SECURED);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

#ifdef OC_SECURITY
  oc_sec_self_own(kDeviceID);
#endif // OC_SECURITY

  message::SyncQueue messages{};
  TCPClient client([&messages](message::oc_message_unique_ptr &&msg) {
    messages.Push(std::move(msg));
    oc::TestDevice::Terminate();
  });
  message::token_t token{ 0x01, 0x03, 0x03, 0x07, 0x04, 0x02 };
  std::thread workerThread([&ep, &client, &token]() {
    ASSERT_TRUE(client.Connect(&ep));

    auto message = message::tcp::RegisterObserve(token, OCF_D_URI, "", &ep);
    ASSERT_NE(nullptr, message.get());
    ASSERT_TRUE(client.Send(message->data, message->length));

    client.Run();
  });

  bool is_observable =
    (oc_core_get_resource_by_index(OCF_D, kDeviceID)->properties &
     OC_OBSERVABLE) != 0;

  // wait for response to observe registration
  auto msg = message::WaitForMessage(messages, 1s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, is_observable,
                    OC_COAP_OPTION_OBSERVE_REGISTER);
  if (is_observable) {
    std::string deviceName{ "new test name" };
    oc_core_device_set_name(kDeviceID, deviceName.c_str(), deviceName.length());
    oc_notify_resource_changed(oc_core_get_resource_by_index(OCF_D, kDeviceID));
    // wait for first notification
    msg = message::WaitForMessage(messages, 1s);
    ASSERT_NE(nullptr, msg.get());
    assertObservation(msg.get(), CONTENT_2_05, token, is_observable,
                      OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE);
  }

  client.Terminate();
  workerThread.join();

#ifdef OC_SECURITY
  oc_sec_self_disown(kDeviceID);
#endif // OC_SECURITY
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

TEST_F(TestObservationWithServer, ObserveEmptyResource)
{
  auto *res = oc_ri_get_app_resource_by_uri(kDynamicURI1.c_str(),
                                            kDynamicURI1.size(), kDeviceID);
  ASSERT_NE(nullptr, res);

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP, SECURED);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  message::SyncQueue messages{};
  TCPClient client([&messages](message::oc_message_unique_ptr &&msg) {
    messages.Push(std::move(msg));
    oc::TestDevice::Terminate();
  });
  message::token_t token{ 0x01, 0x03, 0x03, 0x07, 0x04, 0x02 };
  std::thread workerThread([&ep, &client, &token]() {
    ASSERT_TRUE(client.Connect(&ep));

    auto message = message::tcp::RegisterObserve(token, kDynamicURI1, "", &ep);
    ASSERT_NE(nullptr, message.get());
    ASSERT_TRUE(client.Send(message->data, message->length));

    client.Run();
  });

  // wait for response to observe registration
  auto msg = message::WaitForMessage(messages, 100s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, true,
                    OC_COAP_OPTION_OBSERVE_REGISTER);

#ifdef OC_SECURITY
  // must be in RFNOP to send obsevations
  oc_sec_self_own(kDeviceID);
#endif // OC_SECURITY

  oc_notify_resource_changed(res);
  msg = message::WaitForMessage(messages, 300ms);
  ASSERT_EQ(nullptr, msg.get());

  client.Terminate();
  workerThread.join();

#ifdef OC_SECURITY
  oc_sec_self_disown(kDeviceID);
#endif // OC_SECURITY
}

#ifdef OC_COLLECTIONS

TEST_F(TestObservationWithServer, ObserveEmptyCollection)
{
  oc_collection_t *col = oc_get_collection_by_uri(
    kCollectionURI1.c_str(), kCollectionURI1.size(), kDeviceID);
  ASSERT_NE(nullptr, col);

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP, SECURED);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  message::SyncQueue messages{};
  TCPClient client([&messages](message::oc_message_unique_ptr &&msg) {
    messages.Push(std::move(msg));
    oc::TestDevice::Terminate();
  });
  message::token_t token{ 0x01, 0x03, 0x03, 0x07, 0x04, 0x02 };
  std::thread workerThread([&ep, &client, &token]() {
    ASSERT_TRUE(client.Connect(&ep));

    auto message =
      message::tcp::RegisterObserve(token, kCollectionURI1, "", &ep);
    ASSERT_NE(nullptr, message.get());
    ASSERT_TRUE(client.Send(message->data, message->length));

    client.Run();
  });

  // wait for response to observe registration
  auto msg = message::WaitForMessage(messages, 1s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, true,
                    OC_COAP_OPTION_OBSERVE_REGISTER);

  oc_collection_notify_resource_changed(col, false);
  msg = message::WaitForMessage(messages, 1s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, true,
                    OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE);

  client.Terminate();
  workerThread.join();
}

TEST_F(TestObservationWithServer, ObserveCollectionOnDelete)
{
  oc_collection_t *col = oc_get_collection_by_uri(
    kCollectionURI1.c_str(), kCollectionURI1.size(), kDeviceID);
  ASSERT_NE(nullptr, col);

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, TCP, SECURED);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  message::SyncQueue messages{};
  TCPClient client([&messages](message::oc_message_unique_ptr &&msg) {
    messages.Push(std::move(msg));
    oc::TestDevice::Terminate();
  });
  message::token_t token{ 0x01, 0x03, 0x03, 0x07, 0x04, 0x02 };
  std::thread workerThread([&ep, &client, &token]() {
    ASSERT_TRUE(client.Connect(&ep));

    auto message =
      message::tcp::RegisterObserve(token, kCollectionURI1, "", &ep);
    ASSERT_NE(nullptr, message.get());
    ASSERT_TRUE(client.Send(message->data, message->length));

    client.Run();
  });

  // wait for response to observe registration
  auto msg = message::WaitForMessage(messages, 1s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, true,
                    OC_COAP_OPTION_OBSERVE_REGISTER);

  // add resource
  oc::DynamicResourceHandler handlers{};
  handlers.onGet = onGetEmptyResource;
  auto dr = oc::makeDynamicResourceToAdd(
    "Collection Resource 2", kColDynamicURI1, { powerSwitchRT, "oic.d.test" },
    { OC_IF_BASELINE, OC_IF_R }, handlers);
  oc_resource_t *res = oc::TestDevice::AddDynamicResource(dr, kDeviceID);
  ASSERT_NE(nullptr, res);
  oc_link_t *link = oc_new_link(res);
  ASSERT_NE(link, nullptr);
  oc_collection_add_link(&col->res, link);

  msg = message::WaitForMessage(messages, 1s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, true,
                    OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE);

  // remove resource
  oc::TestDevice::ClearDynamicResource(res);
  msg = message::WaitForMessage(messages, 1s);
  ASSERT_NE(nullptr, msg.get());
  assertObservation(msg.get(), CONTENT_2_05, token, true,
                    OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE + 1);

  client.Terminate();
  workerThread.join();
}

TEST_F(TestObservationWithServer, BatchObserveCollectionWithEmptyResource)
{
  // TODO: batch observation over collections are not implemented yet
}

#endif // OC_COLLECTIONS

#endif // !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM

#endif // OC_TCP

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

#ifdef OC_SECURITY

#include "api/oc_core_res_internal.h"
#include "api/oc_events_internal.h"
#include "api/oc_message_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "messaging/coap/coap_signal.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_signal_event_loop.h"
#include "oc_core_res.h"
#include "port/oc_network_event_handler_internal.h"
#include "security/oc_tls_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/Endpoint.h"
#include "util/oc_process_internal.h"

#ifdef OC_HAS_FEATURE_PUSH
#include "api/oc_push_internal.h"
#endif /* OC_HAS_FEATURE_PUSH */

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>

static constexpr size_t kDeviceID{ 0 };
static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };

class TestTlsConnection : public testing::Test {
protected:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr);
    oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(), kDeviceName.c_str(),
                  kOCFSpecVersion.c_str(), kOCFDataModelVersion.c_str(),
                  nullptr, nullptr);
  }

  void TearDown() override
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_tls_shutdown();
    oc_connectivity_shutdown(0);
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

TEST_F(TestTlsConnection, InitTlsTest_P)
{
  int errorCode = oc_tls_init_context();
  EXPECT_EQ(0, errorCode) << "Failed to init TLS Connection";
}

TEST_F(TestTlsConnection, InitTlsTestTwice_P)
{
  int errorCode = oc_tls_init_context();
  ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
  oc_tls_shutdown();
  errorCode = oc_tls_init_context();
  EXPECT_EQ(0, errorCode) << "Failed to init TLS Connection";
}

TEST_F(TestTlsConnection, TlsConnectionTest_N)
{
  int errorCode = oc_tls_init_context();
  ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
  oc_endpoint_t *endpoint = oc_new_endpoint();
  bool isConnected = oc_tls_connected(endpoint);
  EXPECT_FALSE(isConnected) << "Failed to update";
  oc_free_endpoint(endpoint);
}

class TestEventsWithServer : public testing::Test {
public:
  static void SetUpTestCase() { ASSERT_TRUE(oc::TestDevice::StartServer()); }

  static void TearDownTestCase() { oc::TestDevice::StopServer(); }
};

static size_t
countInboundOrOutboundEvents()
{
  size_t count = 0;
  oc_process_iterate_events(
    [](const struct oc_process *, oc_process_event_t ev, oc_process_data_t,
       void *user_data) {
      if (oc_tls_event_is_inbound_or_outbound(ev)) {
        ++(*static_cast<size_t *>(user_data));
      }
      return true;
    },
    &count);
  return count;
}

TEST_F(TestEventsWithServer, DropOutputMessages)
{
  unsigned includeFlags = 0;
#ifdef OC_IPV4
  includeFlags |= IPV4;
  includeFlags |= SECURED;
#endif /* OC_IPV4 */

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, includeFlags, TCP);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  ASSERT_EQ(0, countInboundOrOutboundEvents());
  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  coap_packet_t packet = {};
  coap_udp_init_message(&packet, COAP_TYPE_RST, 0, 0);
  std::array<uint8_t, 8> payload{ "connect" };
  packet.payload = payload.data();
  packet.payload_len = payload.size();
  msg->length =
    coap_serialize_message(&packet, msg->data, oc_message_buffer_size());

  oc_send_message(msg);
  EXPECT_LT(0, countInboundOrOutboundEvents());

  oc_tls_remove_peer(&ep);
  ASSERT_EQ(0, countInboundOrOutboundEvents());
}

#ifdef OC_TCP

TEST_F(TestEventsWithServer, DropOutputMessagesTCP)
{
  unsigned includeFlags = TCP;
#ifdef OC_IPV4
  includeFlags |= IPV4;
  includeFlags |= SECURED;
#endif /* OC_IPV4 */

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID, includeFlags, 0);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  ASSERT_EQ(0, countInboundOrOutboundEvents());
  oc_message_t *msg = oc_allocate_message();
  memcpy(&msg->endpoint, &ep, sizeof(oc_endpoint_t));
  coap_packet_t packet = {};
  coap_tcp_init_message(&packet, CSM_7_01);
  std::array<uint8_t, 8> payload{ "connect" };
  packet.payload = payload.data();
  packet.payload_len = payload.size();
  msg->length =
    coap_serialize_message(&packet, msg->data, oc_message_buffer_size());

  oc_send_message(msg);
  EXPECT_LT(0, countInboundOrOutboundEvents());

  oc_tls_remove_peer(&ep);
  ASSERT_EQ(0, countInboundOrOutboundEvents());
}
#endif /* OC_TCP */

// TODO: tests for oscore
// TODO: tests for inbound data

#endif /* OC_SECURITY */

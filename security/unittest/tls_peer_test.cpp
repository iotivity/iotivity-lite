/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#if defined(OC_SECURITY)

#include "oc_api.h"
#include "messaging/coap/coap_signal.h"
#include "security/oc_tls.h"
#include "util/oc_features.h"
#include <atomic>
#include <gtest/gtest.h>
#include <pthread.h>

class TestTLSPeer : public testing::Test {
protected:
  void SetUp() override
  {
    s_handler.init = &appInit;
    s_handler.signal_event_loop = &signalEventLoop;
    int ret = oc_main_init(&s_handler);
    ASSERT_EQ(0, ret);
    ASSERT_EQ(0, oc_connectivity_init(0));
  }

  void TearDown() override
  {
    oc_connectivity_shutdown(0);
    oc_main_shutdown();
  }

public:
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
  static oc_handler_t s_handler;
  static std::atomic<bool> s_terminate;

  static int appInit(void)
  {
    int result = oc_init_platform("OCFCloud", nullptr, nullptr);
    result |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                            "ocf.res.1.0.0", nullptr, nullptr);
    return result;
  }

  static void signalEventLoop(void) { pthread_cond_signal(&s_cv); }

  static oc_event_callback_retval_t quitEvent(void *)
  {
    s_terminate = true;
    return OC_EVENT_DONE;
  }

  static void poolEvents(uint16_t seconds)
  {
    s_terminate = false;
    oc_set_delayed_callback(nullptr, quitEvent, seconds);

    while (!s_terminate) {
      pthread_mutex_lock(&s_mutex);
      oc_clock_time_t next_event = oc_main_poll();
      if (next_event == 0) {
        pthread_cond_wait(&s_cv, &s_mutex);
      } else {
        struct timespec ts;
        ts.tv_sec = (next_event / OC_CLOCK_SECOND);
        ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
        pthread_cond_timedwait(&s_cv, &s_mutex, &ts);
      }
      pthread_mutex_unlock(&s_mutex);
    }
  }

  static void connectEndpoint(oc_endpoint_t *ep)
  {
    // #ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT
    int ret = oc_tcp_connect(ep, nullptr, nullptr);
    ASSERT_LE(0, ret);
    if (ret == OC_TCP_SOCKET_STATE_CONNECTING) {
      poolEvents(10);
    }
    ASSERT_EQ(OC_TCP_SOCKET_STATE_CONNECTED, oc_tcp_connection_state(ep));
    // #else
    //     oc_message_t *msg = oc_allocate_message();
    //     memcpy(&msg->endpoint, ep, sizeof(oc_endpoint_t));
    //     coap_packet_t packet = {};
    //     coap_tcp_init_message(&packet, CSM_7_01);
    //     std::array<uint8_t, 8> payload{ "connect" };
    //     packet.payload = payload.data();
    //     packet.payload_len = payload.size();
    //     msg->length = coap_serialize_message(&packet, msg->data);
    //     oc_send_buffer(msg);
    //     oc_message_unref(msg);
    // #endif
  }
};

pthread_mutex_t TestTLSPeer::s_mutex;
pthread_cond_t TestTLSPeer::s_cv;
oc_handler_t TestTLSPeer::s_handler;
std::atomic<bool> TestTLSPeer::s_terminate{ 0 };

TEST_F(TestTLSPeer, CountPeers)
{
  size_t ep_count = 0;
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(0);
  while (ep != nullptr) {
    if ((ep->flags & (TCP | SECURED)) == (TCP | SECURED)) {
      ++ep_count;
      connectEndpoint(ep);
      break;
    }
    ep = ep->next;
  }

  if (ep_count == 0) {
    return;
  }

  ASSERT_LT(0, oc_tls_num_peers(0));
}

#endif /* OC_SECURITY */

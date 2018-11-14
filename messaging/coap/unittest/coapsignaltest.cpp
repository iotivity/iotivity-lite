/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 *
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

#include <cstdlib>
#include <string>
#include <gtest/gtest.h>
#include "oc_api.h"
#include "coap_signal.h"
#include "coap.h"

static const size_t device = 0;
static oc_endpoint_t *target_ep;

static void signal_event_loop(void)
{
}

static int app_init(void)
{
  int ret = oc_init_platform("Samsung", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static oc_handler_t handler = {.init = app_init,
                    .signal_event_loop = signal_event_loop,
                    .register_resources = NULL,
                    .requests_entry = NULL };

class TestCoapSignal: public testing::Test
{
    protected:
        static void SetUpTestCase()
        {
            oc_main_init(&handler);
            oc_endpoint_t *ep = oc_connectivity_get_endpoints(device);
            oc_endpoint_t *cur_ep = ep;
            while (cur_ep) {
                if (cur_ep->flags & TCP && !(cur_ep->flags & SECURED) &&
                    cur_ep->flags & IPV4)
                    break;
                cur_ep = cur_ep->next;
            }
            ASSERT_NE(NULL, cur_ep);
            target_ep = cur_ep;
        }

        static void TearDownTestCase()
        {
            oc_main_shutdown();
        }
};

#ifdef OC_TCP

TEST_F(TestCoapSignal, coap_send_csm_message_P)
{
    int ret = coap_send_csm_message(target_ep, 1);
    EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_csm_message_N)
{
    int ret = coap_send_csm_message(NULL, 0);
    EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_ping_message_P)
{
    uint8_t token[4] = {0x01, 0x02, 0x03, 0x04};
    int ret = coap_send_ping_message(target_ep, 1, token, 4);
    EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_ping_message_N)
{
    int ret = coap_send_ping_message(NULL, 0, NULL, 0);
    EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_pong_message_P)
{
    uint8_t token[4] = {0x01, 0x02, 0x03, 0x04};
    coap_packet_t packet[1];
    coap_tcp_init_message(packet, PING_7_02);
    coap_set_token(packet, token, 4);
    coap_signal_set_custody(packet, 1);

    int ret = coap_send_pong_message(target_ep, packet);
    EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_pong_message_N)
{
    int ret = coap_send_pong_message(NULL, NULL);
    EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_release_message_P)
{
    const char *addr = "coap+tcp://127.0.0.1:5683";
    size_t addr_len = strlen(addr) + 1;
    uint32_t hold_off = 10;

    int ret = coap_send_release_message(target_ep, addr, addr_len, hold_off);
    EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_release_message_N)
{
    int ret = coap_send_release_message(NULL, NULL, 0, 0);
    EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_send_abort_message_P)
{
    uint16_t opt = 10;
    const char *msg = "Abort!";
    size_t msg_len = strlen(msg) + 1;

    int ret = coap_send_abort_message(target_ep, opt, msg, msg_len);
    EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_send_abort_message_N)
{
    int ret = coap_send_abort_message(NULL, 0, NULL, 0);
    EXPECT_NE(1, ret);
}

TEST_F(TestCoapSignal, coap_check_is_signal_message_P)
{
    coap_packet_t packet[1];
    ASSERT_NO_THROW(coap_tcp_init_message(packet, CSM_7_01));

    int ret = coap_check_is_signal_message(packet);

    EXPECT_EQ(1, ret);
}

TEST_F(TestCoapSignal, coap_check_is_signal_message_N)
{
    coap_packet_t packet[1];
    ASSERT_NO_THROW(coap_tcp_init_message(packet, COAP_GET));

    int ret = coap_check_is_signal_message(packet);

    EXPECT_EQ(0, ret);
}

#endif /* OC_TCP */
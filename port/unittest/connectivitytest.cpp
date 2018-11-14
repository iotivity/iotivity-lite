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

extern "C" {
    #include "port/oc_connectivity.h"
    #include "oc_network_monitor.h"
}

static const size_t device = 0;
static bool is_callback_received = false;

class TestConnectivity: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            is_callback_received = false;
            oc_network_event_handler_mutex_init();
            oc_connectivity_init(device);
        }

        virtual void TearDown()
        {
            oc_connectivity_shutdown(device);
            oc_network_event_handler_mutex_destroy();
        }
};

TEST(TestConnectivity_init, oc_connectivity_init)
{
    int ret = oc_connectivity_init(device);
    EXPECT_EQ(0, ret);
    oc_connectivity_shutdown(device);
}

TEST_F(TestConnectivity, oc_connectivity_get_endpoints)
{
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(device);
    EXPECT_NE(NULL, ep);
}

static void interface_event_handler(oc_interface_event_t event)
{
    EXPECT_EQ(NETWORK_INTERFACE_UP, event);
    is_callback_received = true;
}

TEST_F(TestConnectivity, oc_add_network_interface_event_callback)
{
    int ret =
        oc_add_network_interface_event_callback(interface_event_handler);
    EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_network_interface_event_callback)
{
    oc_add_network_interface_event_callback(interface_event_handler);
    int ret =
        oc_remove_network_interface_event_callback(interface_event_handler);
    EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_network_interface_event_callback_invalid)
{
    int ret =
        oc_remove_network_interface_event_callback(interface_event_handler);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestConnectivity, handle_network_interface_event_callback)
{
    oc_add_network_interface_event_callback(interface_event_handler);
    handle_network_interface_event_callback(NETWORK_INTERFACE_UP);
    EXPECT_EQ(true, is_callback_received);
}

static void session_event_handler(const oc_endpoint_t *ep,
                                  oc_session_state_t state)
{
    EXPECT_NE(NULL, ep);
    EXPECT_EQ(OC_SESSION_CONNECTED, state);
    is_callback_received = true;
}

TEST_F(TestConnectivity, oc_add_session_event_callback)
{
    int ret =
        oc_add_session_event_callback(session_event_handler);
    EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_session_event_callback)
{
    oc_add_session_event_callback(session_event_handler);
    int ret =
        oc_remove_session_event_callback(session_event_handler);
    EXPECT_EQ(0, ret);
}

TEST_F(TestConnectivity, oc_remove_session_event_callback_invalid)
{
    int ret =
        oc_remove_session_event_callback(session_event_handler);
    EXPECT_EQ(-1, ret);
}

TEST_F(TestConnectivity, handle_session_event_callback)
{
    oc_add_session_event_callback(session_event_handler);
    oc_endpoint_t ep;
    handle_session_event_callback(&ep, OC_SESSION_CONNECTED);
    EXPECT_EQ(true, is_callback_received);
}

#ifdef OC_TCP
TEST_F(TestConnectivity, oc_tcp_get_csm_state_P)
{
    oc_endpoint_t ep;
    tcp_csm_state_t ret = oc_tcp_get_csm_state(&ep);

    EXPECT_EQ(CSM_NONE, ret);
}

TEST_F(TestConnectivity, oc_tcp_get_csm_state_N)
{
    tcp_csm_state_t ret = oc_tcp_get_csm_state(NULL);

    EXPECT_EQ(CSM_ERROR, ret);
}

TEST_F(TestConnectivity, oc_tcp_update_csm_state_P)
{
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(device);
    while (ep) {
        if (ep->flags & TCP && !(ep->flags & SECURED) &&
            ep->flags & IPV4)
            break;
        ep = ep->next;
    }

    ASSERT_NE(NULL, ep);

    oc_message_t message;
    uint8_t *data = (uint8_t *)"connect";
    memcpy(&message.endpoint, ep, sizeof(oc_endpoint_t));
    message.data = data;
    message.length = 7;
    oc_send_buffer(&message);

    oc_tcp_update_csm_state(ep, CSM_DONE);

    tcp_csm_state_t ret = oc_tcp_get_csm_state(ep);

    EXPECT_EQ(CSM_DONE, ret);
}

TEST_F(TestConnectivity, oc_tcp_update_csm_state_N)
{
    oc_endpoint_t *ep = oc_connectivity_get_endpoints(device);
    while (ep) {
        if (ep->flags & TCP && !(ep->flags & SECURED) &&
            ep->flags & IPV4)
            break;
        ep = ep->next;
    }

    ASSERT_NE(NULL, ep);

    oc_tcp_update_csm_state(ep, CSM_DONE);

    tcp_csm_state_t ret = oc_tcp_get_csm_state(ep);

    EXPECT_NE(CSM_DONE, ret);
}
#endif /* OC_TCP */
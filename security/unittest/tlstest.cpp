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
#include "gtest/gtest.h"

#include "oc_tls.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_signal_event_loop.h"
#define delete pseudo_delete
#include "oc_core_res.h"
#undef delete

#define MAX_WAIT_TIME 10
#define RESOURCE_URI "/LightResourceURI"
#define DEVICE_URI "/oic/d"
#define RESOURCE_TYPE "oic.r.light"
#define DEVICE_TYPE "oic.d.light"
#define RESOURCE_INTERFACE "oic.if.baseline"
#define MANUFACTURER_NAME "Samsung"
#define DEVICE_NAME "Table Lamp"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"


class TestTlsConnection: public testing::Test
{
    protected:
        virtual void SetUp()
        {
            oc_ri_init();
            oc_network_event_handler_mutex_init();
            oc_core_init();
            oc_init_platform(MANUFACTURER_NAME, NULL, NULL);
            oc_add_device(DEVICE_URI, DEVICE_TYPE, DEVICE_NAME,
                        OCF_SPEC_VERSION, OCF_DATA_MODEL_VERSION, NULL, NULL);
        }

        virtual void TearDown()
        {
           oc_ri_shutdown();
           oc_tls_shutdown();
           oc_connectivity_shutdown(0);
           oc_network_event_handler_mutex_destroy();
           oc_core_shutdown();
        }
};

#if defined(OC_TCP) && defined(OC_SECURITY)
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

TEST_F(TestTlsConnection, LoadCertTest_P)
{

    int errorCode = oc_tls_init_context();
    ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
    errorCode = oc_tls_update_psk_identity(0);
    EXPECT_EQ(0, errorCode) << "Failed to update";
}

TEST_F(TestTlsConnection, TlsConnectionTest_N)
{

    int errorCode = oc_tls_init_context();
    ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
    oc_endpoint_t *endpoint = oc_new_endpoint();
    bool isConnected = oc_tls_connected(endpoint);
    EXPECT_FALSE(isConnected ) << "Failed to update";
    oc_free_endpoint(endpoint);
}

#endif

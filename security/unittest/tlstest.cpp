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
#if defined(OC_TCP) && defined(OC_SECURITY)

#include <cstdlib>
#include "gtest/gtest.h"

#include "oc_tls.h"
#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_signal_event_loop.h"
#define delete pseudo_delete
#include "oc_core_res.h"
#undef delete
#include "oc_security.h"

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

void get_cpubkey_and_token(uint8_t *cpubkey, int *cpubkey_len, uint8_t *token, int *token_len)
{
  uint8_t key[32] = { 0x40, 0x71, 0x28, 0x53, 0xe7, 0x2e, 0xab, 0x64,
                      0xeb, 0x13, 0x24, 0x42, 0x84, 0x00, 0x24, 0x50,
                      0xcc, 0x74, 0x94, 0x21, 0x50, 0x2e, 0x89, 0x5d,
                      0x6c, 0x62, 0xea, 0x6e, 0x33, 0x77, 0x97, 0x41 };
  uint8_t tkn[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F };
  memcpy(cpubkey, key, 32);
  memcpy(token, tkn, 32);
  *cpubkey_len = 32;
  *token_len = 32;
  return;

}

void get_own_key(uint8_t *priv_key, int *priv_key_len)
{
  uint8_t prv[32] = { 0x28, 0x91, 0xcd, 0x69, 0xb2, 0xe9, 0xe9, 0x39,
                      0xb5, 0xa2, 0x8e, 0xcc, 0x64, 0x37, 0x6e, 0xf4,
                      0xf4, 0x59, 0xc7, 0x8a, 0xfc, 0x20, 0xb9, 0xaa,
                      0x63, 0xdc, 0x54, 0xf4, 0x56, 0x85, 0x70, 0x46 };
  memcpy(priv_key, prv, 32);
  *priv_key_len = 32;
  return;
}

bool
gen_master_key(uint8_t *master, int *master_len);


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
            oc_sec_set_cpubkey_and_token_load(get_cpubkey_and_token);
            oc_sec_set_own_key_load(get_own_key);
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

TEST_F(TestTlsConnection, TlsRawPublicKeyHmacTest_N)
{

    int errorCode = oc_tls_init_context();
    ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
    oc_endpoint_t *endpoint = oc_new_endpoint();
    uint8_t hmac[32];
    int hmac_len = 0;
    bool result = oc_sec_get_rpk_hmac(endpoint, hmac, &hmac_len);
    EXPECT_FALSE(result) << "Rpk hmac calculated but TLS session doesn't exists";
}

TEST_F(TestTlsConnection, TlsRawPublicKeyPskTest_N)
{

    int errorCode = oc_tls_init_context();
    ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
    oc_endpoint_t *endpoint = oc_new_endpoint();
    uint8_t psk[32];
    int psk_len = 0;
    bool result = oc_sec_get_rpk_psk(0, psk, &psk_len);
    EXPECT_TRUE(result) << "Failed to calculate rpk PSK";
}

#endif

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

#include "gtest/gtest.h"
#include <cstdlib>

#include "oc_api.h"
#include "oc_endpoint.h"
#include "oc_signal_event_loop.h"
#include "oc_tls.h"
#define delete pseudo_delete
#include "oc_core_res.h"
#undef delete
#include "port/oc_network_event_handler_internal.h"

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
    oc_ri_init();
    oc_network_event_handler_mutex_init();
    oc_core_init();
    oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr);
    oc_add_device(kDeviceURI.c_str(), kDeviceType.c_str(), kDeviceName.c_str(),
                  kOCFSpecVersion.c_str(), kOCFDataModelVersion.c_str(),
                  nullptr, nullptr);
  }

  void TearDown() override
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

TEST_F(TestTlsConnection, TlsConnectionTest_N)
{
  int errorCode = oc_tls_init_context();
  ASSERT_EQ(0, errorCode) << "Failed to init TLS Connection";
  oc_endpoint_t *endpoint = oc_new_endpoint();
  bool isConnected = oc_tls_connected(endpoint);
  EXPECT_FALSE(isConnected) << "Failed to update";
  oc_free_endpoint(endpoint);
}

#endif /* OC_TCP && OC_SECURITY */

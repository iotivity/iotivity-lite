/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
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
#include <gtest/gtest.h>
#include <stdio.h>
#include <string>

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_helpers.h"
#include "port/oc_network_event_handler_internal.h"

static const std::string kDeviceURI{ "/oic/d" };
static const std::string kDeviceType{ "oic.d.light" };
static const std::string kDeviceName{ "Table Lamp" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };

class TestCoreResource : public testing::Test {
protected:
  void SetUp() override
  {
    oc_core_init();
    oc_network_event_handler_mutex_init();
    oc_random_init();
  }
  void TearDown() override
  {
    oc_random_destroy();
    oc_network_event_handler_mutex_destroy();
    oc_core_shutdown();
  }
};

TEST_F(TestCoreResource, InitPlatform_P)
{
  int oc_platform_info =
    oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr);
  EXPECT_EQ(0, oc_platform_info);
}

TEST_F(TestCoreResource, CoreInitPlatform_P)
{
  const oc_platform_info_t *oc_platform_info =
    oc_core_init_platform(kManufacturerName.c_str(), nullptr, nullptr);
  EXPECT_EQ(kManufacturerName.length(),
            oc_string_len(oc_platform_info->mfg_name));
}

TEST_F(TestCoreResource, CoreDevice_P)
{
  oc_device_info_t *addcoredevice = oc_core_add_new_device(
    kDeviceURI.c_str(), kDeviceType.c_str(), kDeviceName.c_str(),
    kOCFSpecVersion.c_str(), kOCFDataModelVersion.c_str(), nullptr, nullptr);
  ASSERT_NE(addcoredevice, nullptr);
  size_t numcoredevice = oc_core_get_num_devices();
  EXPECT_EQ(1, numcoredevice);
  oc_connectivity_shutdown(0);
}

TEST_F(TestCoreResource, CoreGetResource_P)
{
  oc_core_init_platform(kManufacturerName.c_str(), nullptr, nullptr);

  std::string uri = "/oic/p";
  oc_resource_t *res = oc_core_get_resource_by_uri(uri.c_str(), 0);

  ASSERT_NE(nullptr, res);
  EXPECT_EQ(uri.length(), oc_string_len(res->uri));
}

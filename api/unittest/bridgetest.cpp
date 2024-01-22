/******************************************************************
 *
 * Copyright 2023 ETRI Joo-Chul Kevin Lee (rune@etri.re.kr)
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_BRIDGE

#include <gtest/gtest.h>
#include <sys/stat.h>

#include "oc_api.h"
#include "oc_bridge.h"
#include "oc_vod_map.h"
#include "port/oc_storage.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "api/oc_core_res_internal.h"
#include "security/oc_svr_internal.h"
#include "security/oc_doxm_internal.h"
#include "port/oc_network_event_handler_internal.h"

#include "tests/gtest/Device.h"

extern "C" {
void bridge_owned_changed(const oc_uuid_t *device_uuid, size_t device_index,
                          bool owned, void *user_data);
}

class TestBridge : public testing::Test {
public:
  void SetUp() override
  {
    oc_network_event_handler_mutex_init();
    oc_runtime_init();
    oc_ri_init();
    oc_core_init();
    oc_sec_svr_create();
  }

  void TearDown() override
  {
#ifdef OC_HAS_FEATURE_PUSH
    oc_push_free();
#endif /* OC_HAS_FEATURE_PUSH */
    oc_core_shutdown();
    oc_ri_shutdown();
    oc_runtime_shutdown();
    oc_network_event_handler_mutex_destroy();
  }
};

static const oc::DeviceToAdd kBridgeDevice = { "oic.d.bridge", "BridgeDevice",
                                               "ocf.1.0.0", "ocf.res.1.0.0",
                                               "/oic/d" };

static constexpr size_t kBridgeDeviceID{ 0 };

static const oc::DeviceToAdd kVODDevice = { "oic.d.virtual", "VOD1",
                                            "ocf.1.0.0", "ocf.res.1.0.0",
                                            "/oic/d" };

static const std::string kVODDeviceID{ "vod1" };
static const std::string kVODEconame{ "matter" };
static const std::string kVODlistRscURI{ "/bridge/vodlist" };

TEST_F(TestBridge, BridgeAPITest)
{
  /* -------------------------------------------------*/
  /*
   * oc_bridge_add_bridge_device()
   */
  /* -------------------------------------------------*/
  /*
   * add bridge device (oic.d.bridge)
   */
  ASSERT_EQ(oc_bridge_add_bridge_device(
              kBridgeDevice.name.c_str(), kBridgeDevice.spec_version.c_str(),
              kBridgeDevice.data_model_version.c_str(), nullptr, nullptr),
            0);

  auto bridgeDeviceInfo = oc_core_get_device_info(kBridgeDeviceID);
  ASSERT_NE(bridgeDeviceInfo, nullptr);

  /* check bridge device name */
  EXPECT_STREQ(kBridgeDevice.name.c_str(), oc_string(bridgeDeviceInfo->name));

  auto bridgeDeviceRsc = oc_core_get_resource_by_uri_v1(
    kBridgeDevice.uri.c_str(), kBridgeDevice.uri.size(), kBridgeDeviceID);
  ASSERT_NE(bridgeDeviceRsc, nullptr);

  /* check bridge device type */
  EXPECT_STREQ(kBridgeDevice.rt.c_str(),
               oc_string_array_get_item(bridgeDeviceRsc->types, 0));

  /* -------------------------------------------------*/
  /*
   * oc_bridge_add_virtual_device()
   * oc_bridge_get_virtual_device_index()
   */
  /* -------------------------------------------------*/
  size_t vodIndex = oc_bridge_add_virtual_device(
    kVODDeviceID.c_str(), kVODDeviceID.size(), kVODEconame.c_str(),
    kVODDevice.uri.c_str(), kVODDevice.rt.c_str(), kVODDevice.name.c_str(),
    kVODDevice.spec_version.c_str(), kVODDevice.data_model_version.c_str(),
    nullptr, nullptr);
  EXPECT_NE(vodIndex, 0);

  //  oc_device_info_t *vodDeviceInfo = oc_core_get_device_info(vodIndex);
  auto vodDeviceInfo = oc_core_get_device_info(vodIndex);
  ASSERT_NE(vodDeviceInfo, nullptr);

  /* check VOD device name */
  EXPECT_STREQ(kVODDevice.name.c_str(), oc_string(vodDeviceInfo->name));

  auto vodDeviceRsc = oc_core_get_resource_by_uri_v1(
    kVODDevice.uri.c_str(), kVODDevice.uri.size(), vodIndex);
  ASSERT_NE(vodDeviceRsc, nullptr);

  /* check bridge device type */
  EXPECT_STREQ(kVODDevice.rt.c_str(),
               oc_string_array_get_item(vodDeviceRsc->types, 0));

  /* check device index */
  EXPECT_EQ(oc_bridge_get_virtual_device_index(
              kVODDeviceID.c_str(), kVODDeviceID.size(), kVODEconame.c_str()),
            vodIndex);

  /* -------------------------------------------------*/
  /*
   * oc_bridge_remove_virtual_device()
   * oc_bridge_get_vod()
   * oc_bridge_get_vod_list()
   * oc_bridge_get_vod_mapping_info()
   * oc_bridge_get_vod_mapping_info2()
   */
  /* -------------------------------------------------*/
  /* get vodlist resource */
  auto vodListRsc = oc_ri_get_app_resource_by_uri(
    kVODlistRscURI.c_str(), kVODlistRscURI.size(), kBridgeDeviceID);
  ASSERT_NE(vodListRsc, nullptr);
  EXPECT_EQ(vodListRsc->device, kBridgeDeviceID);

  /* get vod item for VOD */
  //  oc_vods_t * vodItem = oc_bridge_get_vod(vodDeviceInfo->di);
  auto vodItem = oc_bridge_get_vod(vodDeviceInfo->di);
  EXPECT_EQ(vodItem, nullptr);

  /* get vodlist */
  vodItem = oc_bridge_get_vod_list();
  EXPECT_EQ(vodItem, nullptr);

  /* own bridge device */
  bridge_owned_changed(&bridgeDeviceInfo->di, kBridgeDeviceID, true, nullptr);
  auto bridgeDoxm = oc_sec_get_doxm(kBridgeDeviceID);
  bridgeDoxm->owned = true;

  /* own VODS */
  bridge_owned_changed(&vodDeviceInfo->di, vodIndex, true, nullptr);
  auto vodDoxm = oc_sec_get_doxm(vodIndex);
  vodDoxm->owned = true;

  /* get vod item for VOD */
  vodItem = oc_bridge_get_vod(vodDeviceInfo->di);
  EXPECT_NE(vodItem, nullptr);

  /* get vodlist */
  vodItem = oc_bridge_get_vod_list();
  EXPECT_NE(vodItem, nullptr);

  /* try to get vod map entry */
  auto vodMapEntry1 = oc_bridge_get_vod_mapping_info(vodIndex);
  auto vodMapEntry2 = oc_bridge_get_vod_mapping_info2(vodItem);
  EXPECT_EQ(vodMapEntry1, vodMapEntry2);

  /* remove vod from vod list */
  ASSERT_EQ(oc_bridge_remove_virtual_device(vodIndex), 0);

  /* get vod item for VOD */
  vodItem = oc_bridge_get_vod(vodDeviceInfo->di);
  EXPECT_EQ(vodItem, nullptr);

  /* get vodlist */
  vodItem = oc_bridge_get_vod_list();
  EXPECT_EQ(vodItem, nullptr);

  /* -------------------------------------------------*/
  /*
   * oc_bridge_add_vod()
   */
  /* -------------------------------------------------*/
  ASSERT_EQ(oc_bridge_add_vod(vodIndex), 0);

  /* get vod item for VOD */
  vodItem = oc_bridge_get_vod(vodDeviceInfo->di);
  EXPECT_NE(vodItem, nullptr);

  /* get vodlist */
  vodItem = oc_bridge_get_vod_list();
  EXPECT_NE(vodItem, nullptr);

  /* -------------------------------------------------*/
  /*
   * oc_bridge_delete_virtual_device()
   */
  /* -------------------------------------------------*/
  oc_uuid_t vodDi;
  memcpy(vodDi.id, vodDeviceInfo->di.id, OC_UUID_ID_SIZE);

  ASSERT_EQ(oc_bridge_delete_virtual_device(vodIndex), 0);

  /* check vod is removed from vod list */
  /* get vod item for VOD */
  vodItem = oc_bridge_get_vod(vodDi);
  EXPECT_EQ(vodItem, nullptr);

  /* get vodlist */
  vodItem = oc_bridge_get_vod_list();
  EXPECT_EQ(vodItem, nullptr);

  /* check vod is removed from vod mapping list */
  auto vodMapEntry3 = oc_bridge_get_vod_mapping_info(vodIndex);
  EXPECT_EQ(vodMapEntry3, nullptr);
}

#endif /* OC_HAS_FEATURE_BRIDGE */

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
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_ETAG

#include "api/oc_client_api_internal.h"
#include "api/oc_etag_internal.h"
#include "api/oc_resource_internal.h"
#include "messaging/coap/coap_options.h"
#include "oc_api.h"
#include "oc_config.h"
#include "oc_core_res.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Storage.h"

#ifdef OC_COLLECTIONS
#include "api/oc_collection_internal.h"
#include "tests/gtest/Collection.h"
#endif /* OC_COLLECTIONS */

#ifdef OC_STORAGE
#include "api/oc_storage_internal.h"
#endif /* OC_STORAGE */

#include <algorithm>
#include <array>
#include <filesystem>
#include <functional>
#include <gtest/gtest.h>
#include <string>
#include <vector>

static constexpr size_t kDeviceID1{ 0 };

#ifdef OC_DYNAMIC_ALLOCATION
static constexpr size_t kDeviceID2{ 1 };
#endif // OC_DYNAMIC_ALLOCATION

class TestETagWithServer : public ::testing::Test {
public:
  static void SetUpTestCase()
  {
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Config());
#endif // OC_STORAGE

    oc::TestDevice::SetServerDevices({
      {
        /*rt=*/"oic.d.test1",
        /*name=*/"Test Device 2",
        /*spec_version=*/"ocf.1.0.0",
        /*data_model_version=*/"ocf.res.1.0.0",
        /*uri=*/"/oic/d",
      },
#ifdef OC_DYNAMIC_ALLOCATION
      {
        /*rt=*/"oic.d.test2",
        /*name=*/"Test Device 2",
        /*spec_version=*/"ocf.1.0.0",
        /*data_model_version=*/"ocf.res.1.0.0",
        /*uri=*/"/oic/d",
      },
#endif // OC_DYNAMIC_ALLOCATION
    });
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_DYNAMIC_ALLOCATION
    addDynamicResources();
#endif // OC_DYNAMIC_ALLOCATION
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();
#ifdef OC_STORAGE
    ASSERT_EQ(0, oc::TestStorage.Clear());
#endif // OC_STORAGE
  }

  void TearDown() override
  {
#ifdef OC_STORAGE
    oc_etag_clear_storage();
#endif // OC_STORAGE
  }

#ifdef OC_DYNAMIC_ALLOCATION
  static void onRequest(oc_request_t *request, oc_interface_mask_t, void *)
  {
    oc_send_response(request, OC_STATUS_OK);
  }

  static oc_resource_t *addDynamicResource(
    const std::string &name, const std::string &uri,
    const std::vector<std::string> &rts,
    const std::vector<oc_interface_mask_t> &ifaces, size_t device);

  static void addDynamicResources();
#endif // OC_DYNAMIC_ALLOCATION
};

#ifdef OC_DYNAMIC_ALLOCATION

oc_resource_t *
TestETagWithServer::addDynamicResource(
  const std::string &name, const std::string &uri,
  const std::vector<std::string> &rts,
  const std::vector<oc_interface_mask_t> &ifaces, size_t device)
{
  oc::DynamicResourceHandler handlers{};
  handlers.onGet = onRequest;
  handlers.onPost = onRequest;
  return oc::TestDevice::AddDynamicResource(
    oc::makeDynamicResourceToAdd(name, uri, rts, ifaces, handlers), device);
}

void
TestETagWithServer::addDynamicResources()
{
  ASSERT_NE(nullptr,
            addDynamicResource("Dynamic Resource 1", "/dyn1",
                               { "oic.d.dynamic", "oic.d.test" },
                               { OC_IF_BASELINE, OC_IF_R }, kDeviceID1));
  ASSERT_NE(nullptr,
            addDynamicResource("Dynamic Resource 2", "/dyn2",
                               { "oic.d.dynamic", "oic.d.test" },
                               { OC_IF_BASELINE, OC_IF_RW }, kDeviceID2));
}
#endif // OC_DYNAMIC_ALLOCATION

// check that all resources have initialized etags
TEST_F(TestETagWithServer, ETagsInitialized)
{
  oc::IterateAllResources([](const oc_resource_t *resource) {
    EXPECT_NE(0, oc_resource_get_etag(resource));
  });
}

TEST_F(TestETagWithServer, ETagWrapAround)
{
  oc_etag_set_global(0);
  // TODO: check that all resources have reinitialized etags with the wrapped
  // value
}

#ifdef OC_DYNAMIC_ALLOCATION

// check that newly created resources have etags
TEST_F(TestETagWithServer, NewResources)
{
  auto *dyn = addDynamicResource("Dynamic Resource 3", "/dyn3",
                                 { "oic.d.dynamic", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, kDeviceID1);
  ASSERT_NE(nullptr, dyn);
  EXPECT_NE(0, oc_resource_get_etag(dyn));

#ifdef OC_COLLECTIONS
  auto col1 = oc::NewCollection("col1", "/col1", kDeviceID1);
  ASSERT_NE(nullptr, col1);
  EXPECT_NE(0, oc_resource_get_etag(&col1->res));
#endif /* OC_COLLECTIONS */

  // clean-up
  ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(dyn, true));
}

#endif // OC_DYNAMIC_ALLOCATION

#ifdef OC_STORAGE

static void
setAllETags(uint64_t etag)
{
  oc::IterateAllResources(
    [etag](oc_resource_t *resource) { oc_resource_set_etag(resource, etag); });
}

static bool
isETagStorageEmpty()
{
  for (size_t i = 0; i < oc_core_get_num_devices(); ++i) {
    long ret = oc_storage_data_load(
      OC_ETAG_STORE_NAME, i, [](const oc_rep_t *, size_t, void *) { return 0; },
      nullptr);
    if (ret > 0) {
      OC_ERR("storage for device %zu is not empty", i);
      return false;
    }
  }
  return true;
}

TEST_F(TestETagWithServer, DumpAndLoad)
{
#ifdef OC_COLLECTIONS
  auto col1 = oc::NewCollection("col1", "/col1", kDeviceID1);
  ASSERT_NE(nullptr, col1);
  oc_collection_add(col1.get());

  auto col2 = oc::NewCollection("col2", "/col2", kDeviceID2);
  ASSERT_NE(nullptr, col2);
  oc_collection_add(col2.get());
#endif /* OC_COLLECTIONS */

  // set all etags to 1337
  setAllETags(1337);
  // store etags to the storage
  EXPECT_TRUE(oc_etag_dump());

  std::vector<oc_resource_t *> dynamicResources{};
#ifdef OC_DYNAMIC_ALLOCATION
  // new resource without etag set, will get etag set by oc_etag_get
  auto *dyn = addDynamicResource("Dynamic Resource 3", "/dyn3",
                                 { "oic.d.dynamic", "oic.d.test" },
                                 { OC_IF_BASELINE, OC_IF_R }, kDeviceID1);
  ASSERT_NE(nullptr, dyn);
  dynamicResources.push_back(dyn);
#endif // OC_DYNAMIC_ALLOCATION

  // clear all etags
  setAllETags(0);

  // load etags from the storage and clear the storage
  EXPECT_TRUE(oc_etag_load_and_clear());

  // check if all etags are set to 1337
  oc::IterateAllResources([&dynamicResources](const oc_resource_t *resource) {
    if (std::find(std::begin(dynamicResources), std::end(dynamicResources),
                  resource) != std::end(dynamicResources)) {
      EXPECT_NE(0, oc_resource_get_etag(resource));
      return;
    }
    EXPECT_EQ(1337, oc_resource_get_etag(resource));
  });

  // storage should be empty
  EXPECT_TRUE(isETagStorageEmpty());

  // clean-up
#ifdef OC_DYNAMIC_ALLOCATION
  for (auto *dr : dynamicResources) {
    ASSERT_TRUE(oc::TestDevice::ClearDynamicResource(dr, true));
  }
#endif // OC_DYNAMIC_ALLOCATION
}

TEST_F(TestETagWithServer, SkipDumpOfEmptyETags)
{
  // set all etags to 0
  setAllETags(OC_ETAG_UNINITALIZED);
  // no etags should be stored
  ASSERT_TRUE(oc_etag_dump());

  // all etags should be reinitialized by oc_etag_load_from_storage
  uint64_t max_etag = oc_etag_global();
  EXPECT_TRUE(oc_etag_load_from_storage(false));
  iterateAllResources([&max_etag](const oc_resource_t *resource) {
    EXPECT_LT(max_etag, oc_resource_get_etag(resource));
  });
}

static int
encodeResourceETag(CborEncoder *encoder, const std::string &uri, int64_t etag)
{
  int err = oc_rep_encode_text_string(encoder, uri.c_str(), uri.length());
  CborEncoder etag_map;
  memset(&etag_map, 0, sizeof(etag_map));
  err |= oc_rep_encoder_create_map(encoder, &etag_map, CborIndefiniteLength);
  std::string key = "etag";
  err |= oc_rep_encode_text_string(&etag_map, key.c_str(), key.length());
  err |= oc_rep_encode_int(&etag_map, etag);
  err |= oc_rep_encoder_close_container(encoder, &etag_map);
  return err;
}

TEST_F(TestETagWithServer, IgnoreInvalidStorageData)
{
  constexpr uint64_t kETag = 1337;
  // set all etags to 1337
  setAllETags(kETag);

#ifdef OC_DYNAMIC_ALLOCATION
  auto empty_storage = [](size_t, void *) {
    oc_rep_start_root_object();
    oc_rep_end_root_object();
    return 0;
  };
  // put {} to the storage of the second device so we can ignore it
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID2,
                                    empty_storage, nullptr));
#endif // OC_DYNAMIC_ALLOCATION

  // expected storage data:
  // {
  //   "<uri>": {
  //     "etag": <etag in uint64_t format>,
  //   },
  //   ...
  // }

  auto store_encode_single_string = [](size_t, void *) {
    oc_rep_start_root_object();
    oc_rep_set_text_string(root, uri, "/oic/d");
    oc_rep_end_root_object();
    return 0;
  };
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID1,
                                    store_encode_single_string, nullptr));
  EXPECT_TRUE(oc_etag_load_from_storage(true));
  // no etag should be changed
  iterateAllResources([kETag](const oc_resource_t *resource) {
    EXPECT_EQ(kETag, oc_resource_get_etag(resource));
  });

  auto store_encode_invalid_type = [](size_t, void *) {
    oc_rep_start_root_object();
    std::string uri = "/oic/d";
    int err =
      oc_rep_encode_text_string(oc_rep_object(root), uri.c_str(), uri.length());
    CborEncoder etag_map;
    memset(&etag_map, 0, sizeof(etag_map));
    err |= oc_rep_encoder_create_map(oc_rep_object(root), &etag_map,
                                     CborIndefiniteLength);
    std::string key = "etag";
    err |= oc_rep_encode_text_string(&etag_map, key.c_str(), key.length());
    std::string value = "invalid";
    err |= oc_rep_encode_text_string(&etag_map, value.c_str(), value.length());
    err |= oc_rep_encoder_close_container(oc_rep_object(root), &etag_map);
    oc_rep_end_root_object();
    return err;
  };
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID1,
                                    store_encode_invalid_type, nullptr));
  EXPECT_TRUE(oc_etag_load_from_storage(true));
  // no etag should be changed
  iterateAllResources([kETag](const oc_resource_t *resource) {
    EXPECT_EQ(kETag, oc_resource_get_etag(resource));
  });

  auto store_encode_invalid_value = [](size_t, void *) {
    oc_rep_start_root_object();
    int err = encodeResourceETag(oc_rep_object(root), "/oic/p", 0);
    err |= encodeResourceETag(oc_rep_object(root), "/oic/d", -1);
    oc_rep_end_root_object();
    return err;
  };
  ASSERT_LT(0, oc_storage_data_save(OC_ETAG_STORE_NAME, kDeviceID1,
                                    store_encode_invalid_value, nullptr));
  EXPECT_TRUE(oc_etag_load_from_storage(true));
  // no etag should be changed
  iterateAllResources([kETag](const oc_resource_t *resource) {
    EXPECT_EQ(kETag, oc_resource_get_etag(resource));
  });
}

TEST_F(TestETagWithServer, LoadGlobalETagFromStorage)
{
  uint64_t max_etag = oc_etag_global();
  if (max_etag == 0) {
    max_etag = oc_etag_get();
  }
  constexpr oc_clock_time_t kOneDay = 24 * 60 * 60 * OC_CLOCK_SECOND;
  max_etag += kOneDay;

  oc_resource_t *platform = oc_core_get_resource_by_index(OCF_P, 0);
  ASSERT_NE(nullptr, platform);
  oc_resource_set_etag(platform, max_etag);

  ASSERT_TRUE(oc_etag_dump());
  EXPECT_TRUE(oc_etag_load_from_storage(true));

  // the global etag should be > than the maximal etag of all resources
  EXPECT_GT(oc_etag_global(), max_etag);
}

// if storage is not properly initialized then oc_etag_dump should fail
TEST_F(TestETagWithServer, Dump_FailNoStorage)
{
  ASSERT_EQ(0, oc::TestStorage.Clear());
  EXPECT_FALSE(oc_etag_dump());
  ASSERT_EQ(0, oc::TestStorage.Config());
}

// if the storage is empty then oc_etag_load_from_storage should use oc_etag_get
// to set etags on all resources
TEST_F(TestETagWithServer, ClearStorage)
{
  // set all etags to 1337
  setAllETags(1337);
  // store etags to the storage
  ASSERT_TRUE(oc_etag_dump());

  // clear the storage
  ASSERT_TRUE(oc_etag_clear_storage());
  EXPECT_FALSE(oc_etag_load_from_storage(false));

  oc::IterateAllResources([](const oc_resource_t *resource) {
    // nor 0 nor 1337
    EXPECT_NE(0, oc_resource_get_etag(resource));
    EXPECT_NE(1337, oc_resource_get_etag(resource));
  });
}

// if storage is not properly initialized then oc_etag_clear_storage should fail
TEST_F(TestETagWithServer, ClearStorage_Fail)
{
  ASSERT_EQ(0, oc::TestStorage.Clear());
  EXPECT_FALSE(oc_etag_clear_storage());
  ASSERT_EQ(0, oc::TestStorage.Config());
}

// if storage is not properly initialized then oc_etag_load_and_clear should
// fail
TEST_F(TestETagWithServer, LoadAndClear_Fail)
{
  ASSERT_EQ(0, oc::TestStorage.Clear());
  EXPECT_FALSE(oc_etag_load_and_clear());
  ASSERT_EQ(0, oc::TestStorage.Config());
}

#endif // OC_STORAGE

template<oc_status_t CODE>
static void
getHandlerCheckCode(oc_client_response_t *data)
{
  EXPECT_EQ(CODE, data->code);
  *static_cast<bool *>(data->user_data) = true;
  oc::TestDevice::Terminate();
  OC_DBG("GET payload: %s", oc::RepPool::GetJson(data->payload).data());
}

TEST_F(TestETagWithServer, GetResourceWithETag)
{
  // get insecure connection to the testing device
  const oc_endpoint_t *ep = oc::TestDevice::GetEndpoint(kDeviceID1, 0, SECURED);
  ASSERT_NE(nullptr, ep);

  oc_resource_t *res = oc_core_get_resource_by_index(OCF_D, kDeviceID1);
  ASSERT_NE(nullptr, res);
  oc_resource_set_etag(res, 1337);

  // send get request to the /oic/d resource
  bool invoked = false;
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(res->uri), ep, nullptr,
                            /*timeout_seconds*/ 5,
                            getHandlerCheckCode<OC_STATUS_OK>, LOW_QOS,
                            &invoked, nullptr, nullptr));
  oc::TestDevice::PoolEvents(5);

  invoked = false;
  using etag_t = std::array<uint8_t, COAP_ETAG_LEN>;
  auto configure_req = [](coap_packet_t *req, void *data) {
    auto etag = static_cast<etag_t *>(data);
    coap_options_set_etag(req, etag->data(),
                          static_cast<uint8_t>(etag->size()));
  };
  etag_t etag{};
  memcpy(etag.data(), &res->etag, sizeof(res->etag));
  ASSERT_TRUE(oc_do_request(OC_GET, oc_string(res->uri), ep, nullptr,
                            /*timeout_seconds*/ 5,
                            getHandlerCheckCode<OC_STATUS_NOT_MODIFIED>,
                            LOW_QOS, &invoked, configure_req, &etag));
  oc::TestDevice::PoolEvents(5);
}

#endif // OC_HAS_FEATURE_ETAG

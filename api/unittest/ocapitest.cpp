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

#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_obt.h"
#include "oc_uuid.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
#include "oc_acl.h"
#include "security/oc_acl_internal.h"
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#include <algorithm>
#include <cstdlib>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <pthread.h>
#include <unistd.h>
#include <vector>

#ifdef OC_DYNAMIC_ALLOCATION
// discovery requests are so large that they only work with dynamic allocation

static constexpr uint16_t kMaxWaitTime{ 10 };
static const std::string kDeviceURI{ "/oic/d" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };

struct ApiCallback
{
  oc_request_callback_t cb;
  int response; // -1 if no response should be send, oc_status_t otherwise
};

struct ApiResource
{
  bool enabled;
  oc_endpoint_t endpoint;
  size_t device_id;
  std::string device_type;
  std::string device_name;
  std::string resource_uri;
  std::string resource_type;
  oc_resource_t *resource;
  std::string uuid;
  ApiCallback onGet;
  ApiCallback onPost;
  ApiCallback onPut;
  ApiCallback onDelete;
};

class ApiHelper {
private:
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
  static oc_handler_t s_handler;
  static OC_ATOMIC_UINT8_T s_terminate;
  static bool s_isServerStarted;

public:
  static ApiResource s_ObtResource;
  static ApiResource s_LightResource;
  static ApiResource s_SwitchResource;
  static ApiResource s_TestResource;

  static int appInit(void)
  {
    int result = oc_init_platform(kManufacturerName.c_str(), nullptr, nullptr);
    size_t deviceId = 0;
    if (s_ObtResource.enabled) {
      result |= oc_add_device(
        kDeviceURI.c_str(), s_ObtResource.device_type.c_str(),
        s_ObtResource.device_name.c_str(), kOCFSpecVersion.c_str(),
        kOCFDataModelVersion.c_str(), nullptr, nullptr);
      s_ObtResource.device_id = deviceId++;
    }
    if (s_LightResource.enabled) {
      result |= oc_add_device(
        kDeviceURI.c_str(), s_LightResource.device_type.c_str(),
        s_LightResource.device_name.c_str(), kOCFSpecVersion.c_str(),
        kOCFDataModelVersion.c_str(), nullptr, nullptr);
      s_LightResource.device_id = deviceId++;
    }
    if (s_SwitchResource.enabled) {
      result |= oc_add_device(
        kDeviceURI.c_str(), s_SwitchResource.device_type.c_str(),
        s_SwitchResource.device_name.c_str(), kOCFSpecVersion.c_str(),
        kOCFDataModelVersion.c_str(), nullptr, nullptr);
      s_SwitchResource.device_id = deviceId++;
    }
    if (s_TestResource.enabled) {
      result |= oc_add_device(
        kDeviceURI.c_str(), s_TestResource.device_type.c_str(),
        s_TestResource.device_name.c_str(), kOCFSpecVersion.c_str(),
        kOCFDataModelVersion.c_str(), nullptr, nullptr);
      s_TestResource.device_id = deviceId++;
    }
    return result;
  }

  static void registerResource(ApiResource &resource)
  {
    if (resource.enabled) {
      std::string buffer(OC_UUID_LEN, '\0');

      oc_resource_t *r = oc_new_resource(nullptr, resource.resource_uri.c_str(),
                                         1, resource.device_id);
      oc_resource_bind_resource_type(r, resource.device_type.c_str());
      oc_resource_bind_resource_interface(r, OC_IF_RW);
      oc_resource_set_default_interface(r, OC_IF_RW);
      oc_resource_set_discoverable(r, true);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
      oc_resource_make_public(r);
      oc_resource_set_access_in_RFOTM(
        r, true,
        static_cast<oc_ace_permissions_t>(OC_PERM_RETRIEVE | OC_PERM_UPDATE |
                                          OC_PERM_DELETE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
      if (resource.onGet.cb != nullptr) {
        oc_resource_set_request_handler(r, OC_GET, resource.onGet.cb,
                                        &resource);
      }
      if (resource.onPost.cb != nullptr) {
        oc_resource_set_request_handler(r, OC_POST, resource.onPost.cb,
                                        &resource);
      }
      if (resource.onPut.cb != nullptr) {
        oc_resource_set_request_handler(r, OC_PUT, resource.onPut.cb,
                                        &resource);
      }
      if (resource.onDelete.cb != nullptr) {
        oc_resource_set_request_handler(r, OC_DELETE, resource.onDelete.cb,
                                        &resource);
      }
      oc_add_resource(r);
      resource.resource = r;

      const oc_uuid_t *uuid = oc_core_get_device_id(resource.device_id);
      oc_uuid_to_str(uuid, &buffer[0], buffer.size());
      resource.uuid = buffer;

      OC_DBG("Resource uri=%s id=%zu uuid=%s\n", resource.resource_uri.c_str(),
             resource.device_id, resource.uuid.c_str());
    }
  }

  static void registerResources()
  {
    registerResource(s_ObtResource);
    registerResource(s_LightResource);
    registerResource(s_SwitchResource);
    registerResource(s_TestResource);
  }

  static void signalEventLoop(void)
  {
    pthread_cond_signal(&s_cv);
  }

  static oc_event_callback_retval_t quitEvent(void *)
  {
    terminate();
    return OC_EVENT_DONE;
  }

  static void terminate()
  {
    OC_ATOMIC_STORE8(s_terminate, 1);
  }

  static void poolEvents(uint16_t seconds)
  {
    OC_ATOMIC_STORE8(s_terminate, 0);
    oc_set_delayed_callback(nullptr, quitEvent, seconds);

    while (OC_ATOMIC_LOAD8(s_terminate) == 0) {
      pthread_mutex_lock(&s_mutex);
      oc_clock_time_t next_event = oc_main_poll();
      if (OC_ATOMIC_LOAD8(s_terminate) != 0) {
        pthread_mutex_unlock(&s_mutex);
        break;
      }
      if (next_event == 0) {
        pthread_cond_wait(&s_cv, &s_mutex);
      } else {
        struct timespec ts;
        ts.tv_sec = (next_event / OC_CLOCK_SECOND);
        ts.tv_nsec = static_cast<long>((next_event % OC_CLOCK_SECOND) * 1.e09 /
                                       OC_CLOCK_SECOND);
        pthread_cond_timedwait(&s_cv, &s_mutex, &ts);
      }
      pthread_mutex_unlock(&s_mutex);
    }

    oc_remove_delayed_callback(nullptr, quitEvent);
  }

  static void requestsEntry()
  {
    // no-op
  }

  static void writeResponse(const ApiResource *res)
  {
    oc_rep_start_root_object();
    oc_rep_set_int(root, getResponse, res->onGet.response);
    oc_rep_set_int(root, postResponse, res->onPost.response);
    oc_rep_set_int(root, putResponse, res->onPut.response);
    oc_rep_end_root_object();
  }

  static void onGet(oc_request_t *req, oc_interface_mask_t, void *data)
  {
    const auto *res = static_cast<ApiResource *>(data);
    OC_DBG("GET uri=%s\n", res->resource_uri.c_str());
    if (res->onGet.response == -1) {
      return;
    }

    writeResponse(res);
    oc_send_response(req, static_cast<oc_status_t>(res->onGet.response));
  }

  static void onPost(oc_request_t *req, oc_interface_mask_t, void *data)
  {
    const auto *res = static_cast<ApiResource *>(data);
    OC_DBG("POST uri=%s\n", res->resource_uri.c_str());
    if (res->onPost.response == -1) {
      return;
    }

    writeResponse(res);
    oc_send_response(req, static_cast<oc_status_t>(res->onPost.response));
  }

  static void onPut(oc_request_t *req, oc_interface_mask_t, void *data)
  {
    const auto *res = static_cast<ApiResource *>(data);
    OC_DBG("PUT uri=%s\n", res->resource_uri.c_str());
    if (res->onPut.response == -1) {
      return;
    }

    writeResponse(res);
    oc_send_response(req, static_cast<oc_status_t>(res->onPut.response));
  }

  static void onDelete(oc_request_t *req, oc_interface_mask_t, void *data)
  {
    const auto *res = static_cast<ApiResource *>(data);
    OC_DBG("DELETE uri=%s\n", res->resource_uri.c_str());
    if (res->onDelete.response == -1) {
      return;
    }

    writeResponse(res);
    oc_send_response(req, static_cast<oc_status_t>(res->onDelete.response));
  }

  static bool startServer(std::string &errorMessage)
  {
    OC_ATOMIC_STORE8(s_terminate, 0);
    s_handler.init = appInit;
    s_handler.signal_event_loop = signalEventLoop;
    s_handler.register_resources = registerResources;
    s_handler.requests_entry = requestsEntry;

    oc_set_con_res_announced(false);

    int initResult = oc_main_init(&s_handler);
    if (initResult < 0) {
      errorMessage += "Initialization of main server failed";
      s_isServerStarted = false;
      return false;
    }
    s_isServerStarted = true;
    return true;
  }

  static void stopServer()
  {
    terminate();
    if (s_isServerStarted) {
      oc_main_shutdown();
    }
  }

  static void unregisterResources()
  {
    if (s_ObtResource.enabled) {
      oc_delete_resource(s_ObtResource.resource);
    }
    if (s_LightResource.enabled) {
      oc_delete_resource(s_LightResource.resource);
    }
    if (s_SwitchResource.enabled) {
      oc_delete_resource(s_SwitchResource.resource);
    }
    if (s_TestResource.enabled) {
      oc_delete_resource(s_TestResource.resource);
    }
  }

  static void setApiResources()
  {
    s_ObtResource = {
      /*.enabled =*/false,
      /*.endpoint =*/{},
      /*.device_id =*/static_cast<size_t>(-1),
      /*.device_type =*/"oic.d.obt",
      /*.device_name =*/"Obt",
      /*.resource_uri =*/"/ObtURI",
      /*.resource_type =*/"oic.r.obt",
      /*.resource =*/nullptr,
      /*.uuid =*/"",
      /*.onGet =*/{ /*.cb =*/ApiHelper::onGet, /*.response =*/-1 },
      /*.onPost =*/{ /*.cb =*/ApiHelper::onPost, /*.response =*/-1 },
      /*.onPut =*/{ /*.cb =*/ApiHelper::onPut, /*.response =*/-1 },
      /*.onDelete =*/{ /*.cb =*/ApiHelper::onDelete, /*.response =*/-1 },
    };
    s_LightResource = {
      /*.enabled =*/false,
      /*.endpoint =*/{},
      /*.device_id =*/static_cast<size_t>(-1),
      /*.device_type =*/"oic.d.light",
      /*.device_name =*/"Table Lamp",
      /*.resource_uri =*/"/LightResourceURI",
      /*.resource_type =*/"oic.r.light",
      /*.resource =*/nullptr,
      /*.uuid =*/"",
      /*.onGet =*/{ /*.cb =*/ApiHelper::onGet, /*.response =*/-1 },
      /*.onPost =*/{ /*.cb =*/ApiHelper::onPost, /*.response =*/-1 },
      /*.onPut =*/{ /*.cb =*/ApiHelper::onPut, /*.response =*/-1 },
      /*.onDelete =*/{ /*.cb =*/ApiHelper::onDelete, /*.response =*/-1 },
    };
    s_SwitchResource = {
      /*.enabled =*/false,
      /*.endpoint =*/{},
      /*.device_id =*/static_cast<size_t>(-1),
      /*.device_type =*/"oic.d.switch",
      /*.device_name =*/"Switch",
      /*.resource_uri =*/"/SwitchURI",
      /*.resource_type =*/"oic.r.switch",
      /*.resource =*/nullptr,
      /*.uuid =*/"",
      /*.onGet =*/{ /*.cb =*/ApiHelper::onGet, /*.response =*/-1 },
      /*.onPost =*/{ /*.cb =*/ApiHelper::onPost, /*.response =*/-1 },
      /*.onPut =*/{ /*.cb =*/ApiHelper::onPut, /*.response =*/-1 },
      /*.onDelete =*/{ /*.cb =*/ApiHelper::onDelete, /*.response =*/-1 },
    };
    s_TestResource = {
      /*.enabled =*/false,
      /*.endpoint =*/{},
      /*.device_id =*/static_cast<size_t>(-1),
      /*.device_type =*/"oic.d.test",
      /*.device_name =*/"Test",
      /*.resource_uri =*/"/test",
      /*.resource_type =*/"oic.r.test",
      /*.resource =*/nullptr,
      /*.uuid =*/"",
      /*.onGet =*/{ /*.cb =*/ApiHelper::onGet, /*.response =*/OC_STATUS_OK },
      /*.onPost =*/
      { /*.cb =*/ApiHelper::onPost, /*.response =*/OC_STATUS_CREATED },
      /*.onPut =*/
      { /*.cb =*/ApiHelper::onPut, /*.response =*/OC_STATUS_CHANGED },
      /*.onDelete =*/
      { /*.cb =*/ApiHelper::onDelete, /*.response =*/OC_STATUS_DELETED },
    };
  }
};

pthread_mutex_t ApiHelper::s_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ApiHelper::s_cv = PTHREAD_COND_INITIALIZER;
oc_handler_t ApiHelper::s_handler{};
OC_ATOMIC_UINT8_T ApiHelper::s_terminate{ 0 };
bool ApiHelper::s_isServerStarted{ false };
ApiResource ApiHelper::s_ObtResource{};
ApiResource ApiHelper::s_LightResource{};
ApiResource ApiHelper::s_SwitchResource{};
ApiResource ApiHelper::s_TestResource{};

class ResourceDiscovered {
private:
  std::set<std::string> requiredURI_;
  std::set<std::string> deviceURI_;

  void addRequired(const std::string &uri) { requiredURI_.insert(uri); }

public:
  bool isDone() const
  {
    return std::all_of(
      requiredURI_.cbegin(), requiredURI_.cend(),
      [this](const std::string &uri) { return deviceURI_.count(uri) == 1; });
  }

  static void addRequiredResources(ResourceDiscovered &rd)
  {
    if (ApiHelper::s_LightResource.enabled) {
      rd.addRequired(ApiHelper::s_LightResource.resource_uri);
    }
    if (ApiHelper::s_SwitchResource.enabled) {
      rd.addRequired(ApiHelper::s_SwitchResource.resource_uri);
    }
    if (ApiHelper::s_TestResource.enabled) {
      rd.addRequired(ApiHelper::s_TestResource.resource_uri);
    }
  }

  bool discoverTestResource(ApiResource &resource, const std::string &uri,
                            const oc_endpoint_t *ep)
  {
    if (uri.compare(resource.resource_uri.c_str()) == 0) {
      deviceURI_.insert(uri);
      memcpy(&resource.endpoint, ep, sizeof(oc_endpoint_t));
      OC_DBG("Resource(%s) discovered...\n", uri.c_str());
      return true;
    }
    return false;
  }
};

class TestServerClient : public testing::Test {
protected:
  void SetUp() override
  {
    ApiHelper::setApiResources();
    ApiHelper::s_LightResource.enabled = true;
    ApiHelper::s_SwitchResource.enabled = true;
    ApiHelper::s_TestResource.enabled = true;
    std::string msg = "";
    EXPECT_TRUE(ApiHelper::startServer(msg)) << msg;
    ApiHelper::poolEvents(1); // give some time for everything to start-up
  }

  void TearDown() override
  {
    ApiHelper::unregisterResources();
    ApiHelper::stopServer();
  }

public:
  static oc_discovery_flags_t onResourceDiscovered(
    const char *, const char *uri, oc_string_array_t, oc_interface_mask_t,
    oc_endpoint_t *ep, oc_resource_properties_t, void *user_data)
  {
    auto *rd = static_cast<ResourceDiscovered *>(user_data);
    if (uri == nullptr) {
      OC_ERR("invalid uri parameter");
      return OC_CONTINUE_DISCOVERY;
    }
    auto discoveredUri = std::string(uri);

    bool discovered =
      rd->discoverTestResource(ApiHelper::s_LightResource, discoveredUri, ep) ||
      rd->discoverTestResource(ApiHelper::s_SwitchResource, discoveredUri,
                               ep) ||
      rd->discoverTestResource(ApiHelper::s_TestResource, discoveredUri, ep);

    if (discovered && rd->isDone()) {
      OC_DBG("Discovery done\n");
      ApiHelper::terminate();
      return OC_STOP_DISCOVERY;
    }
    return OC_CONTINUE_DISCOVERY;
  }

  static void DiscoverTestResources()
  {
    ResourceDiscovered rd{};
    ResourceDiscovered::addRequiredResources(rd);
    EXPECT_TRUE(oc_do_ip_discovery(nullptr, &onResourceDiscovered, &rd))
      << "Cannot send discovery request";
    ApiHelper::poolEvents(kMaxWaitTime);
    EXPECT_TRUE(rd.isDone());
  }

  static void HandleClientResponse(oc_client_response_t *data)
  {
    auto *code = static_cast<oc_status_t *>(data->user_data);
    memcpy(code, &data->code, sizeof(oc_status_t));

#ifdef OC_DEBUG
    if (data->payload != nullptr) {
      std::vector<char> json{};
      json.reserve(256);
      oc_rep_to_json(data->payload, &json[0], json.capacity(), true);
      OC_DBG("%s\n", json.data());
    }
#endif /* OC_DEBUG */

    ApiHelper::terminate();
  }
};

TEST_F(TestServerClient, DiscoverResources)
{
  DiscoverTestResources();
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)
TEST_F(TestServerClient, GetWithTimeout)
{
  DiscoverTestResources();

  auto GetDevice = [](oc_client_response_t *data) {
    OC_DBG("GetDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  int expected = ApiHelper::s_TestResource.onGet.response;
  oc_status_t code = OC_STATUS_OK;
  EXPECT_TRUE(
    oc_do_get_with_timeout(ApiHelper::s_TestResource.resource_uri.c_str(),
                           &ApiHelper::s_TestResource.endpoint, nullptr,
                           /*timeout*/ 3, GetDevice, HIGH_QOS, &code));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onGet.response = -1; // disable sending of response
  expected = OC_STATUS_SERVICE_UNAVAILABLE;
  EXPECT_TRUE(
    oc_do_get_with_timeout(ApiHelper::s_TestResource.resource_uri.c_str(),
                           &ApiHelper::s_TestResource.endpoint, nullptr,
                           /*timeout*/ 3, GetDevice, HIGH_QOS, &code));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);
}

TEST_F(TestServerClient, DeleteWithTimeout)
{
  DiscoverTestResources();

  auto DeleteDevice = [](oc_client_response_t *data) {
    OC_DBG("DeleteDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  int expected = ApiHelper::s_TestResource.onDelete.response;
  oc_status_t code = OC_STATUS_OK;
  EXPECT_TRUE(
    oc_do_delete_with_timeout(ApiHelper::s_TestResource.resource_uri.c_str(),
                              &ApiHelper::s_TestResource.endpoint, nullptr,
                              /*timeout*/ 3, DeleteDevice, HIGH_QOS, &code));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onDelete.response =
    -1; // disable sending of response
  expected = OC_STATUS_SERVICE_UNAVAILABLE;
  EXPECT_TRUE(
    oc_do_delete_with_timeout(ApiHelper::s_TestResource.resource_uri.c_str(),
                              &ApiHelper::s_TestResource.endpoint, nullptr,
                              /*timeout*/ 3, DeleteDevice, HIGH_QOS, &code));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);
}

TEST_F(TestServerClient, PostWithTimeout)
{
  DiscoverTestResources();

  auto PostDevice = [](oc_client_response_t *data) {
    OC_DBG("PostDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  int expected = ApiHelper::s_TestResource.onPost.response;
  oc_status_t code = OC_STATUS_OK;
  EXPECT_TRUE(oc_init_post(ApiHelper::s_TestResource.resource_uri.c_str(),
                           &ApiHelper::s_TestResource.endpoint, nullptr,
                           PostDevice, HIGH_QOS, &code));
  EXPECT_TRUE(oc_do_post_with_timeout(3));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onPost.response = -1; // disable sending of
  expected = OC_STATUS_SERVICE_UNAVAILABLE;
  EXPECT_TRUE(oc_init_post(ApiHelper::s_TestResource.resource_uri.c_str(),
                           &ApiHelper::s_TestResource.endpoint, nullptr,
                           PostDevice, HIGH_QOS, &code));
  EXPECT_TRUE(oc_do_post_with_timeout(/*timeout*/ 3));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);
}

TEST_F(TestServerClient, PutWithTimeout)
{
  DiscoverTestResources();

  auto PutDevice = [](oc_client_response_t *data) {
    OC_DBG("PutDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  int expected = ApiHelper::s_TestResource.onPut.response;
  oc_status_t code = OC_STATUS_OK;
  EXPECT_TRUE(oc_init_put(ApiHelper::s_TestResource.resource_uri.c_str(),
                          &ApiHelper::s_TestResource.endpoint, nullptr,
                          PutDevice, HIGH_QOS, &code));
  EXPECT_TRUE(oc_do_put_with_timeout(3));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onPut.response = -1; // disable sending of
  expected = OC_STATUS_SERVICE_UNAVAILABLE;
  EXPECT_TRUE(oc_init_put(ApiHelper::s_TestResource.resource_uri.c_str(),
                          &ApiHelper::s_TestResource.endpoint, nullptr,
                          PutDevice, HIGH_QOS, &code));
  EXPECT_TRUE(oc_do_put_with_timeout(/*timeout*/ 3));
  ApiHelper::poolEvents(5);
  EXPECT_EQ(expected, code);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_SECURITY
class TestObt : public testing::Test {
protected:
  void SetUp() override
  {
    ApiHelper::setApiResources();
    ApiHelper::s_ObtResource.enabled = true;
    ApiHelper::s_LightResource.enabled = true;
    ApiHelper::s_SwitchResource.enabled = true;
    ApiHelper::s_TestResource.enabled = true;
    std::string msg = "";
    EXPECT_TRUE(ApiHelper::startServer(msg)) << msg;
    oc_obt_init();
  }

  void TearDown() override
  {
    oc_obt_shutdown();
    ApiHelper::unregisterResources();
    ApiHelper::stopServer();
  }

public:
  static void onDeviceDiscovered(oc_uuid_t *uuid, oc_endpoint_t *, void *data)
  {
    auto *devices = static_cast<std::vector<std::string> *>(data);
    std::string buffer(OC_UUID_LEN, '\0');
    oc_uuid_to_str(uuid, &buffer[0], buffer.size());
    devices->push_back(buffer);
  }
};

TEST_F(TestObt, DiscoverUnownedResources)
{
  std::vector<std::string> devices;
  EXPECT_EQ(0, oc_obt_discover_unowned_devices(onDeviceDiscovered, &devices));
  ApiHelper::poolEvents(5);
  for (const auto &device : devices) {
    PRINT("Discovered unowned device: %s\n", device.c_str());
  }
  std::set<std::string> deviceUUIDs(devices.begin(), devices.end());
  if (ApiHelper::s_LightResource.enabled) {
    EXPECT_EQ(1, deviceUUIDs.count(ApiHelper::s_LightResource.uuid));
    deviceUUIDs.erase(ApiHelper::s_LightResource.uuid);
  }
  if (ApiHelper::s_SwitchResource.enabled) {
    EXPECT_EQ(1, deviceUUIDs.count(ApiHelper::s_SwitchResource.uuid));
    deviceUUIDs.erase(ApiHelper::s_SwitchResource.uuid);
  }
  if (ApiHelper::s_TestResource.enabled) {
    EXPECT_EQ(1, deviceUUIDs.count(ApiHelper::s_TestResource.uuid));
    deviceUUIDs.erase(ApiHelper::s_TestResource.uuid);
  }
  EXPECT_EQ(0, deviceUUIDs.size());
}

#endif /* OC_SECURITY */
#endif /* OC_DYNAMIC_ALLOCATION */

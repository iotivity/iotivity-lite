/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#include "api/client/oc_client_cb_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_api.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "oc_obt.h"
#include "oc_uuid.h"
#include "port/oc_clock.h"
#include "port/oc_log_internal.h"
#include "util/oc_atomic.h"

#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
#include "oc_acl.h"
#include "security/oc_acl_internal.h"
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <unistd.h>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#else /* !_WIN32 */
#include <pthread.h>
#include <stdexcept>
#endif /* _WIN32 */

#if defined(OC_DYNAMIC_ALLOCATION) && !defined(OC_INOUT_BUFFER_POOL) &&        \
  !defined(OC_APP_DATA_BUFFER_POOL)
// discovery requests are so large that they only work with dynamic allocation

static constexpr uint16_t kMaxWaitTime{ 10 };
static const std::string kDeviceURI{ "/oic/d" };
static const std::string kManufacturerName{ "Samsung" };
static const std::string kOCFSpecVersion{ "ocf.1.0.0" };
static const std::string kOCFDataModelVersion{ "ocf.res.1.0.0" };
static const std::string kDeviceIdKey{ "di" };

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
#ifdef _WIN32
  static CRITICAL_SECTION s_mutex;
  static CONDITION_VARIABLE s_cv;
#else  /* !_WIN32 */
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
#endif /* _WIN32 */
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

  static void init()
  {
#ifdef _WIN32
    InitializeCriticalSection(&s_mutex);
    InitializeConditionVariable(&s_cv);
#else
    if (pthread_mutex_init(&s_mutex, nullptr) != 0) {
      throw std::string("cannot initialize mutex");
    }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr) != 0) {
      throw std::string("cannot initialize condition variable attribute");
    }
    if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
      throw std::string("cannot set condition variable clockid");
    }
    if (pthread_cond_init(&s_cv, &attr) != 0) {
      throw std::string("cannot initialize condition variable");
    }
    pthread_condattr_destroy(&attr);
#endif /* _WIN32 */
  }

  static void deinit()
  {
#ifndef _WIN32
    pthread_cond_destroy(&s_cv);
    pthread_mutex_destroy(&s_mutex);
#endif /* _WIN32 */
  }

  static void lock()
  {
#ifdef _WIN32
    EnterCriticalSection(&s_mutex);
#else
    pthread_mutex_lock(&s_mutex);
#endif /* _WIN32 */
  }

  static void unlock()
  {
#ifdef _WIN32
    LeaveCriticalSection(&s_mutex);
#else
    pthread_mutex_unlock(&s_mutex);
#endif /* _WIN32 */
  }

  static void signalEventLoop(void)
  {
    lock();
#ifdef _WIN32
    WakeConditionVariable(&s_cv);
#else
    pthread_cond_signal(&s_cv);
#endif /* _WIN32 */
    unlock();
  }

  static oc_event_callback_retval_t quitEvent(void *)
  {
    terminate();
    return OC_EVENT_DONE;
  }

  static void terminate()
  {
    OC_ATOMIC_STORE8(s_terminate, 1);
    signalEventLoop();
  }

  static void poolEvents(uint64_t secs)
  {
    poolEventsMs(secs * 1000U);
  }

  static void waitForEvent(oc_clock_time_t next_event_mt)
  {
#ifdef _WIN32
    if (next_event_mt == 0) {
      SleepConditionVariableCS(&s_cv, &s_mutex, INFINITE);
      return;
    }
    oc_clock_time_t now_mt = oc_clock_time();
    if (now_mt < next_event_mt) {
      SleepConditionVariableCS(
        &s_cv, &s_mutex,
        (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
    }
#else
    if (next_event_mt == 0) {
      pthread_cond_wait(&s_cv, &s_mutex);
      return;
    }
    struct timespec next_event = { 1, 0 };
    if (oc_clock_time_t next_event_cv; oc_clock_monotonic_time_to_posix(
          next_event_mt, CLOCK_MONOTONIC, &next_event_cv)) {
      next_event = oc_clock_time_to_timespec(next_event_cv);
    }
    pthread_cond_timedwait(&s_cv, &s_mutex, &next_event);
#endif
  }

  static void poolEventsMs(uint64_t msecs)
  {
    OC_ATOMIC_STORE8(s_terminate, 0);
    oc_set_delayed_callback_ms_v1(nullptr, quitEvent, msecs);

    while (OC_ATOMIC_LOAD8(s_terminate) == 0) {
      oc_clock_time_t next_event = oc_main_poll_v1();
      lock();
      if (oc_main_needs_poll()) {
        unlock();
        continue;
      }
      if (OC_ATOMIC_LOAD8(s_terminate) != 0) {
        unlock();
        break;
      }
      waitForEvent(next_event);
      unlock();
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

    if (oc_main_init(&s_handler) < 0) {
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

  static void getAndRemoveClientCb(const ApiResource &resource,
                                   oc_method_t method)
  {
    oc_client_cb_t *cb = oc_ri_get_client_cb(resource.resource_uri.c_str(),
                                             &resource.endpoint, method);
    ASSERT_NE(nullptr, cb);
    oc_client_cb_free(cb);
  }
};

#ifdef _WIN32
CRITICAL_SECTION ApiHelper::s_mutex;
CONDITION_VARIABLE ApiHelper::s_cv;
#else  /* !_WIN32 */
pthread_mutex_t ApiHelper::s_mutex;
pthread_cond_t ApiHelper::s_cv;
#endif /* _WIN32 */
oc_handler_t ApiHelper::s_handler{};
OC_ATOMIC_UINT8_T ApiHelper::s_terminate{ 0 };
bool ApiHelper::s_isServerStarted{ false };
ApiResource ApiHelper::s_ObtResource{};
ApiResource ApiHelper::s_LightResource{};
ApiResource ApiHelper::s_SwitchResource{};
ApiResource ApiHelper::s_TestResource{};

class ResourceDiscovered {
private:
  std::set<std::string, std::less<>> requiredURI_;
  std::set<std::string, std::less<>> deviceURI_;

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

class DevicesDiscovered {
private:
  std::set<std::string, std::less<>> requiredDevices_;
  std::set<std::string, std::less<>> devices_;

public:
  bool isDone() const
  {
    return std::all_of(requiredDevices_.cbegin(), requiredDevices_.cend(),
                       [this](const std::string &device_id) {
                         return devices_.find(device_id.c_str()) !=
                                devices_.end();
                       });
  }
  size_t size() const { return devices_.size(); }

  void addRequired(const std::string &device_id)
  {
    requiredDevices_.insert(device_id);
  }
  void addDevice(const std::string &device_id) { devices_.insert(device_id); }
};

class TestServerClient : public testing::Test {
protected:
  static void SetUpTestCase() { ApiHelper::init(); }
  static void TearDownTestCase() { ApiHelper::deinit(); }

  void SetUp() override
  {
    ApiHelper::setApiResources();
    ApiHelper::s_LightResource.enabled = true;
    ApiHelper::s_SwitchResource.enabled = true;
    ApiHelper::s_TestResource.enabled = true;
    std::string msg = "";
    EXPECT_TRUE(ApiHelper::startServer(msg)) << msg;
    ApiHelper::poolEventsMs(200); // give some time for everything to start-up
  }

  void TearDown() override { ApiHelper::stopServer(); }

public:
  static oc_discovery_flags_t onResourceDiscovered(
    const char *, const char *uri, oc_string_array_t, oc_interface_mask_t,
    const oc_endpoint_t *ep, oc_resource_properties_t, void *user_data)
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

  static void onDeviceResourceResponse(oc_client_response_t *data)
  {
    oc_rep_t *rep = data->payload;
    auto *rd = static_cast<DevicesDiscovered *>(data->user_data);
    while (rep != nullptr) {
      if (rep->type == OC_REP_STRING &&
          oc_string_len(rep->name) == kDeviceIdKey.size() &&
          memcmp(oc_string(rep->name), kDeviceIdKey.c_str(),
                 kDeviceIdKey.size()) == 0) {
        rd->addDevice(oc_string(rep->value.string));
      }
      rep = rep->next;
    }
    if (rd->isDone()) {
      OC_DBG("Discovery done\n");
      ApiHelper::terminate();
    }
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

  static void DiscoverDeviceIDTestResources()
  {
    DevicesDiscovered lightDevice{};
    std::string lightDeviceID(OC_UUID_LEN, '\0');
    oc_uuid_to_str(oc_core_get_device_id(ApiHelper::s_LightResource.device_id),
                   &lightDeviceID[0], lightDeviceID.size());
    lightDevice.addRequired(lightDeviceID);
    std::string query = kDeviceIdKey + "=" + lightDeviceID.c_str();
    EXPECT_TRUE(oc_do_ip_multicast("/oic/d", query.c_str(),
                                   &onDeviceResourceResponse, &lightDevice))
      << "Cannot send multicast request";
    ApiHelper::poolEvents(kMaxWaitTime);
    EXPECT_TRUE(lightDevice.isDone());
    EXPECT_EQ(lightDevice.size(), 1);

    DevicesDiscovered lightSwitchDevice{};
    std::string switchDeviceID(OC_UUID_LEN, '\0');
    oc_uuid_to_str(oc_core_get_device_id(ApiHelper::s_SwitchResource.device_id),
                   &switchDeviceID[0], switchDeviceID.size());
    lightSwitchDevice.addRequired(switchDeviceID);
    lightSwitchDevice.addRequired(lightDeviceID);
    query += "&" + kDeviceIdKey + "=" + switchDeviceID.c_str();

    EXPECT_TRUE(oc_do_ip_multicast(
      "/oic/d", query.c_str(), &onDeviceResourceResponse, &lightSwitchDevice))
      << "Cannot send multicast request";
    ApiHelper::poolEvents(kMaxWaitTime);
    EXPECT_TRUE(lightSwitchDevice.isDone());
    EXPECT_EQ(lightSwitchDevice.size(), 2);
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
      OC_PRINTF("%s\n", json.data());
    }
#endif /* OC_DEBUG */

    ApiHelper::terminate();
  }
};

TEST_F(TestServerClient, DiscoverResources)
{
  DiscoverTestResources();
}

TEST_F(TestServerClient, DiscoverDeviceIDWithResources)
{
  DiscoverDeviceIDTestResources();
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

using namespace std::chrono_literals;

#ifdef _WIN32
// windows implementation or github testing machine seems to be slower,
// resulting in failures, so we use longer timeouts
static constexpr auto kTimeout = 4s;
static constexpr auto kShortTimeout = 2s;
#else  /* !_WIN32 */
static constexpr auto kTimeout = 2s;
static constexpr auto kShortTimeout = 1s;
#endif /* _WIN32 */

static void
failResponse(oc_client_response_t *)
{
  ADD_FAILURE();
}

TEST_F(TestServerClient, GetWithTimeout)
{
  DiscoverTestResources();

  auto onGetDevice = [](oc_client_response_t *data) {
    OC_DBG("onGetDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  oc_status_t code = OC_STATUS_OK;
  auto doGet = [&code](const ApiResource &resource,
                       oc_response_handler_t handler, uint16_t timeout) {
    EXPECT_TRUE(oc_do_get_with_timeout(resource.resource_uri.c_str(),
                                       &resource.endpoint, nullptr, timeout,
                                       handler, HIGH_QOS, &code));
  };

  int expected = ApiHelper::s_TestResource.onGet.response;
  doGet(ApiHelper::s_TestResource, onGetDevice, kTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kTimeout).count() + 200);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onGet.response = -1; // disable sending of response
  expected = OC_REQUEST_TIMEOUT;
  doGet(ApiHelper::s_TestResource, onGetDevice, kShortTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(expected, code);

  // test clean-up
  code = OC_STATUS_OK;
  doGet(ApiHelper::s_TestResource, failResponse, kShortTimeout.count());
  ApiHelper::getAndRemoveClientCb(ApiHelper::s_TestResource, OC_GET);
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_STATUS_OK, code);
}

TEST_F(TestServerClient, DeleteWithTimeout)
{
  DiscoverTestResources();

  auto onDeleteDevice = [](oc_client_response_t *data) {
    OC_DBG("onDeleteDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  oc_status_t code = OC_STATUS_OK;
  auto doDelete = [&code](const ApiResource &resource,
                          oc_response_handler_t handler, uint16_t timeout) {
    EXPECT_TRUE(oc_do_delete_with_timeout(resource.resource_uri.c_str(),
                                          &resource.endpoint, nullptr, timeout,
                                          handler, HIGH_QOS, &code));
  };

  int expected = ApiHelper::s_TestResource.onDelete.response;
  doDelete(ApiHelper::s_TestResource, onDeleteDevice, kTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kTimeout).count() + 200);
  EXPECT_EQ(expected, code);

  ApiHelper::s_SwitchResource.onDelete.response = -1; // disable response
  doDelete(ApiHelper::s_SwitchResource, onDeleteDevice, kShortTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_REQUEST_TIMEOUT, code);

  // test clean-up
  code = OC_STATUS_OK;
  doDelete(ApiHelper::s_TestResource, failResponse, kShortTimeout.count());
  ApiHelper::getAndRemoveClientCb(ApiHelper::s_TestResource, OC_DELETE);
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_STATUS_OK, code);
}

TEST_F(TestServerClient, PostWithTimeout)
{
  DiscoverTestResources();

  auto onPostDevice = [](oc_client_response_t *data) {
    OC_DBG("onPostDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  oc_status_t code = OC_STATUS_OK;
  auto doPost = [&code](const ApiResource &resource,
                        oc_response_handler_t handler, uint16_t timeout) {
    EXPECT_TRUE(oc_init_post(resource.resource_uri.c_str(), &resource.endpoint,
                             nullptr, handler, HIGH_QOS, &code));
    EXPECT_TRUE(oc_do_post_with_timeout(timeout));
  };

  int expected = ApiHelper::s_TestResource.onPost.response;
  doPost(ApiHelper::s_TestResource, onPostDevice, kTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kTimeout).count() + 200);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onPost.response = -1; // disable response
  doPost(ApiHelper::s_TestResource, onPostDevice, kShortTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_REQUEST_TIMEOUT, code);

  // test clean-up
  code = OC_STATUS_OK;
  doPost(ApiHelper::s_TestResource, failResponse, kShortTimeout.count());
  ApiHelper::getAndRemoveClientCb(ApiHelper::s_TestResource, OC_POST);
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_STATUS_OK, code);
}

TEST_F(TestServerClient, PutWithTimeout)
{
  DiscoverTestResources();

  auto onPutDevice = [](oc_client_response_t *data) {
    OC_DBG("onPutDevice code=%d\n", (int)data->code);
    HandleClientResponse(data);
  };

  oc_status_t code = OC_STATUS_OK;
  auto doPut = [&code](const ApiResource &resource,
                       oc_response_handler_t handler, uint16_t timeout) {
    EXPECT_TRUE(oc_init_put(resource.resource_uri.c_str(), &resource.endpoint,
                            nullptr, handler, HIGH_QOS, &code));
    EXPECT_TRUE(oc_do_put_with_timeout(timeout));
  };

  int expected = ApiHelper::s_TestResource.onPut.response;
  doPut(ApiHelper::s_TestResource, onPutDevice, kTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kTimeout).count() + 200);
  EXPECT_EQ(expected, code);

  ApiHelper::s_TestResource.onPut.response = -1; // disable response
  doPut(ApiHelper::s_TestResource, onPutDevice, kShortTimeout.count());
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_REQUEST_TIMEOUT, code);

  // test clean-up
  code = OC_STATUS_OK;
  doPut(ApiHelper::s_TestResource, failResponse, kShortTimeout.count());
  ApiHelper::getAndRemoveClientCb(ApiHelper::s_TestResource, OC_PUT);
  ApiHelper::poolEventsMs(std::chrono::milliseconds(kShortTimeout).count() +
                          200);
  EXPECT_EQ(OC_STATUS_OK, code);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#ifdef OC_SECURITY
class TestObt : public testing::Test {
protected:
  static void SetUpTestCase() { ApiHelper::init(); }
  static void TearDownTestCase() { ApiHelper::deinit(); }

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
    ApiHelper::stopServer();
  }

public:
  static void onDeviceDiscovered(const oc_uuid_t *uuid, const oc_endpoint_t *,
                                 void *data)
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
  ApiHelper::poolEvents(3);
  for (const auto &device : devices) {
    OC_PRINTF("Discovered unowned device: %s\n", device.c_str());
  }
  std::set<std::string, std::less<>> deviceUUIDs(devices.begin(),
                                                 devices.end());
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
#endif /* OC_DYNAMIC_ALLOCATION && !OC_INOUT_BUFFER_POOL &&                    \
          !OC_APP_DATA_BUFFER_POOL */

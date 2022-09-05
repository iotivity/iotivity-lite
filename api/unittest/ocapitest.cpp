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

#include "port/oc_clock.h"
#include "util/oc_atomic.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_obt.h"
#include "oc_uuid.h"
#include <cstdlib>
#include <gtest/gtest.h>
#include <set>
#include <string>
#include <pthread.h>
#include <unistd.h>
#include <vector>

#define MAX_WAIT_TIME 10
#define DEVICE_URI "/oic/d"
#define MANUFACTURER_NAME "Samsung"
#define OCF_SPEC_VERSION "ocf.1.0.0"
#define OCF_DATA_MODEL_VERSION "ocf.res.1.0.0"

struct ApiDevice
{
  bool enabled;
  size_t device_id;
  std::string device_type;
  std::string device_name;
  std::string resource_uri;
  std::string resource_type;
  oc_resource_t *resource;
  std::string uuid;
};

class ApiHelper {
private:
  static pthread_mutex_t s_mutex;
  static pthread_cond_t s_cv;
  static oc_handler_t s_handler;
  static OC_ATOMIC_UINT8_T s_terminate;
  static bool s_isServerStarted;

public:
  static ApiDevice s_ObtResource;
  static ApiDevice s_LightResource;
  static ApiDevice s_SwitchResource;

  static int appInit(void)
  {
    int result = oc_init_platform(MANUFACTURER_NAME, nullptr, nullptr);
    size_t deviceId = 0;
    if (s_ObtResource.enabled) {
      result |=
        oc_add_device(DEVICE_URI, s_ObtResource.device_type.c_str(),
                      s_ObtResource.device_name.c_str(), OCF_SPEC_VERSION,
                      OCF_DATA_MODEL_VERSION, nullptr, nullptr);
      s_ObtResource.device_id = deviceId++;
    }
    if (s_LightResource.enabled) {
      result |=
        oc_add_device(DEVICE_URI, s_LightResource.device_type.c_str(),
                      s_LightResource.device_name.c_str(), OCF_SPEC_VERSION,
                      OCF_DATA_MODEL_VERSION, nullptr, nullptr);
      s_LightResource.device_id = deviceId++;
    }
    if (s_SwitchResource.enabled) {
      result |=
        oc_add_device(DEVICE_URI, s_SwitchResource.device_type.c_str(),
                      s_SwitchResource.device_name.c_str(), OCF_SPEC_VERSION,
                      OCF_DATA_MODEL_VERSION, nullptr, nullptr);
      s_SwitchResource.device_id = deviceId++;
    }
    return result;
  }

  static void registerResources(void)
  {
    std::string buffer(OC_UUID_LEN, '\0');

    if (s_ObtResource.enabled) {
      oc_resource_t *o =
        oc_new_resource(nullptr, s_ObtResource.resource_uri.c_str(), 1,
                        s_ObtResource.device_id);
      oc_resource_bind_resource_type(o, s_ObtResource.device_type.c_str());
      oc_resource_bind_resource_interface(o, OC_IF_BASELINE);
      oc_resource_set_default_interface(o, OC_IF_BASELINE);
      oc_resource_set_discoverable(o, true);
      oc_resource_set_periodic_observable(o, 1);
      oc_resource_set_request_handler(o, OC_GET, onGet, nullptr);
      oc_add_resource(o);
      s_ObtResource.resource = o;

      const oc_uuid_t *uuid =
        oc_core_get_device_id(ApiHelper::s_ObtResource.device_id);
      oc_uuid_to_str(uuid, &buffer[0], buffer.size());
      s_ObtResource.uuid = buffer;
    }

    if (s_LightResource.enabled) {
      oc_resource_t *l =
        oc_new_resource(nullptr, s_LightResource.resource_uri.c_str(), 1,
                        s_LightResource.device_id);
      oc_resource_bind_resource_type(l, s_LightResource.device_type.c_str());
      oc_resource_bind_resource_interface(l, OC_IF_BASELINE);
      oc_resource_set_default_interface(l, OC_IF_BASELINE);
      oc_resource_set_discoverable(l, true);
      oc_resource_set_periodic_observable(l, 1);
      oc_resource_set_request_handler(l, OC_GET, onGet, nullptr);
      oc_add_resource(l);
      s_LightResource.resource = l;

      const oc_uuid_t *uuid =
        oc_core_get_device_id(ApiHelper::s_LightResource.device_id);
      oc_uuid_to_str(uuid, &buffer[0], buffer.size());
      s_LightResource.uuid = buffer;
    }

    if (s_SwitchResource.enabled) {
      oc_resource_t *s =
        oc_new_resource(nullptr, s_SwitchResource.resource_uri.c_str(), 1,
                        s_SwitchResource.device_id);
      oc_resource_bind_resource_type(s, s_SwitchResource.device_type.c_str());
      oc_resource_bind_resource_interface(s, OC_IF_BASELINE);
      oc_resource_set_default_interface(s, OC_IF_BASELINE);
      oc_resource_set_discoverable(s, true);
      oc_resource_set_periodic_observable(s, 1);
      oc_resource_set_request_handler(s, OC_GET, onGet, nullptr);
      oc_add_resource(s);
      s_SwitchResource.resource = s;

      const oc_uuid_t *uuid =
        oc_core_get_device_id(ApiHelper::s_SwitchResource.device_id);
      oc_uuid_to_str(uuid, &buffer[0], buffer.size());
      s_SwitchResource.uuid = buffer;
    }
  }

  static void signalEventLoop(void) { pthread_cond_signal(&s_cv); }

  static oc_event_callback_retval_t quitEvent(void *)
  {
    terminate();
    return OC_EVENT_DONE;
  }

  static void terminate() { OC_ATOMIC_STORE8(s_terminate, 1); }

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

  static void onGet(oc_request_t *, oc_interface_mask_t, void *)
  {
    // no-op
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
  }
};

pthread_mutex_t ApiHelper::s_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t ApiHelper::s_cv = PTHREAD_COND_INITIALIZER;
oc_handler_t ApiHelper::s_handler{};
OC_ATOMIC_UINT8_T ApiHelper::s_terminate{ 0 };
bool ApiHelper::s_isServerStarted{ false };
ApiDevice ApiHelper::s_ObtResource{
  .enabled = false,
  .device_id = static_cast<size_t>(-1),
  .device_type = "oic.d.obt",
  .device_name = "Obt",
  .resource_uri = "/ObtURI",
  .resource_type = "oic.r.obt",
  .resource = nullptr,
  .uuid = "",
};
ApiDevice ApiHelper::s_LightResource{
  .enabled = false,
  .device_id = static_cast<size_t>(-1),
  .device_type = "oic.d.light",
  .device_name = "Table Lamp",
  .resource_uri = "/LightResourceURI",
  .resource_type = "oic.r.light",
  .resource = nullptr,
  .uuid = "",
};
ApiDevice ApiHelper::s_SwitchResource{
  .enabled = false,
  .device_id = static_cast<size_t>(-1),
  .device_type = "oic.d.switch",
  .device_name = "Switch",
  .resource_uri = "/SwitchURI",
  .resource_type = "oic.r.switch",
  .resource = nullptr,
  .uuid = "",
};

class ResourceDiscovered {
public:
  std::set<std::string> deviceURI;

  bool isDone() const
  {
    return deviceURI.count(ApiHelper::s_LightResource.resource_uri) == 1 &&
           deviceURI.count(ApiHelper::s_SwitchResource.resource_uri) == 1;
  }
};

class TestServerClient : public testing::Test {
protected:
  void SetUp() override
  {
    ApiHelper::s_ObtResource.enabled = false;
    ApiHelper::s_LightResource.enabled = true;
    ApiHelper::s_SwitchResource.enabled = true;
    std::string msg = "";
    EXPECT_TRUE(ApiHelper::startServer(msg)) << msg;
  }

  void TearDown() override
  {
    ApiHelper::unregisterResources();
    ApiHelper::stopServer();
  }

public:
  static oc_discovery_flags_t onResourceDiscovered(
    const char *, const char *uri, oc_string_array_t, oc_interface_mask_t,
    oc_endpoint_t *, oc_resource_properties_t, void *user_data)
  {
    auto *rd = static_cast<ResourceDiscovered *>(user_data);
    std::string discoveredResourceUri = std::string(uri);
    if (discoveredResourceUri.compare(
          ApiHelper::s_LightResource.resource_uri.c_str()) == 0) {
      rd->deviceURI.insert(discoveredResourceUri);
      PRINT("Light Resource Discovered....\n");
    }
    if (discoveredResourceUri.compare(
          ApiHelper::s_SwitchResource.resource_uri.c_str()) == 0) {
      rd->deviceURI.insert(discoveredResourceUri);
      PRINT("Switch Resource Discovered....\n");
    }
    if (rd->isDone()) {
      ApiHelper::terminate();
      return OC_STOP_DISCOVERY;
    }
    return OC_CONTINUE_DISCOVERY;
  }
};

#ifdef OC_DYNAMIC_ALLOCATION
TEST_F(TestServerClient, DiscoverResources)
{
  ResourceDiscovered rd{};
  EXPECT_TRUE(oc_do_ip_discovery(nullptr, &onResourceDiscovered, &rd))
    << "Cannot send discovery request";
  ApiHelper::poolEvents(MAX_WAIT_TIME);
  EXPECT_TRUE(rd.isDone());
}

#ifdef OC_SECURITY
class TestObt : public testing::Test {
protected:
  void SetUp() override
  {
    ApiHelper::s_ObtResource.enabled = true;
    ApiHelper::s_LightResource.enabled = true;
    ApiHelper::s_SwitchResource.enabled = true;
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
  EXPECT_EQ(2, devices.size());
  std::set<std::string> deviceUUIDs(devices.begin(), devices.end());
  EXPECT_EQ(1, deviceUUIDs.count(ApiHelper::s_LightResource.uuid));
  EXPECT_EQ(1, deviceUUIDs.count(ApiHelper::s_SwitchResource.uuid));
}

#endif /* OC_SECURITY */
#endif /* OC_DYNAMIC_ALLOCATION */

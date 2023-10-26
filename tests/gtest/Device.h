/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#pragma once

#include "oc_api.h"
#include "oc_config.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "port/oc_clock.h"
#include "util/oc_atomic.h"
#include "util/oc_features.h"

#ifdef _WIN32
#include <WinSock2.h>
#include <windows.h>
#else /* !_WIN32 */
#include <pthread.h>
#endif /* _WIN32 */

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace oc {

using encodePayloadFn = void (*)();

void testNotSupportedMethod(
  oc_method_t method, const oc_endpoint_t *ep, const std::string &uri,
  encodePayloadFn payloadFn = nullptr,
  oc_status_t error_code = OC_STATUS_METHOD_NOT_ALLOWED);

struct DeviceToAdd
{
  std::string rt;
  std::string name;
  std::string spec_version;
  std::string data_model_version;
  std::string uri;
};

inline const DeviceToAdd DefaultDevice = {
  /*rt=*/"oic.d.test",
  /*name=*/"Test Device",
  /*spec_version=*/"ocf.1.0.0",
  /*data_model_version=*/"ocf.res.1.0.0",
  /*uri=*/"/oic/d",
};

class Device {
public:
  Device();
  ~Device();

  void SignalEventLoop();
  void PoolEvents(uint64_t seconds, bool addDelay = false);
  void PoolEventsMs(uint64_t mseconds, bool addDelay = false);
  void Terminate();

private:
  void Lock();
  void Unlock();
  void WaitForEvent(oc_clock_time_t next_event);

  static oc_event_callback_retval_t QuitEvent(void *data)
  {
    auto *instance = static_cast<Device *>(data);
    instance->Terminate();
    return OC_EVENT_DONE;
  }

#ifdef _WIN32
  CRITICAL_SECTION mutex_;
  CONDITION_VARIABLE cv_;
#else  /* !_WIN32 */
  pthread_mutex_t mutex_;
  pthread_cond_t cv_;
#endif /* _WIN32 */
  OC_ATOMIC_UINT8_T terminate_;
};

#ifdef OC_SERVER
struct DynamicResourceHandler
{
  oc_request_callback_t onGet;
  void *onGetData;
  oc_request_callback_t onPost;
  void *onPostData;
  oc_request_callback_t onPut;
  void *onPutData;
  oc_request_callback_t onDelete;
  void *onDeleteData;
};

struct DynamicResourceToAdd
{
  std::string name;
  std::string uri;
  const std::vector<std::string> rts;
  const std::vector<oc_interface_mask_t> ifaces;
  DynamicResourceHandler handlers;
  unsigned properties;
};

inline DynamicResourceToAdd
makeDynamicResourceToAdd(const std::string &name, const std::string &uri,
                         const std::vector<std::string> &rts,
                         const std::vector<oc_interface_mask_t> &ifaces,
                         const DynamicResourceHandler &handlers,
                         unsigned properties = OC_DISCOVERABLE)
{
  return { name, uri, rts, ifaces, handlers, properties };
}

#endif /* OC_SERVER */

class TestDevice {
public:
  TestDevice() = delete;

  static size_t CountDevices();
  static size_t IsStarted() { return is_started; }

  // IoTivity-lite application callbacks
  static int AppInit();
  static void RegisterResources()
  {
    // no-op
  }
  static void SignalEventLoop() { device.SignalEventLoop(); }
  static void PoolEvents(uint64_t seconds, bool addDelay = false)
  {
    device.PoolEvents(seconds, addDelay);
  }
  static void PoolEventsMs(uint64_t mseconds, bool addDelay = false)
  {
    device.PoolEventsMs(mseconds, addDelay);
  }
  static void PoolEventsMsV1(std::chrono::milliseconds interval,
                             bool addDelay = false)
  {
    device.PoolEventsMs(interval.count(), addDelay);
  }

  static void SetServerDevices(std::vector<DeviceToAdd> devices);
  static void ResetServerDevices();
  static bool StartServer();
  static void StopServer();
  static void Terminate() { device.Terminate(); }
  static void DropOutgoingMessages();
#ifdef OC_CLIENT
  static void CloseSessions(size_t device);
#endif /* OC_CLIENT */

#ifdef OC_HAS_FEATURE_PLGD_TIME
  static void ConfigurePlgdTime(bool useInMbedTLS);
#endif /* OC_HAS_FEATURE_PLGD_TIME */

  static oc_clock_time_t GetSystemTime()
  {
    return system_time;
  };
  static void ClearSystemTime()
  {
    system_time = 0;
  }

  static void DummyHandler(oc_request_t *, oc_interface_mask_t, void *)
  {
    // no-op
  }
#ifdef OC_SERVER
  static oc_resource_t *AddDynamicResource(const DynamicResourceToAdd &dr,
                                           size_t device);

  static oc_resource_t *GetDynamicResource(size_t device, size_t index);

  static void ClearDynamicResource(size_t device, size_t index, bool doDelete);
  static bool ClearDynamicResource(oc_resource_t *resource, bool doDelete);
  static void ClearDynamicResources();
#endif /* OC_SERVER */

  static constexpr unsigned kDefaultEndpointExcludeFlags = SECURED;

  constexpr static unsigned defaultEndpointIncludeFlags()
  {
    unsigned flags = 0;
#ifdef OC_IPV4
    // force IPv4 if it is enabled
    flags |= IPV4;
#endif /* OC_IPV4 */

#ifdef OC_TCP
    // force TCP if it is enabled
    flags |= TCP;
#endif /* OC_TCP */
    return flags;
  }

  /**
   * @brief Get the Endpoint object
   *
   * @param device index of device associated with the endpoint
   * @param flags flags that the endpoint flags must contain
   * @param exclude_flags flags that the endpoint flags cannot contain
   * @return oc_endpoint_t matching endpoint or std::nullopt if not found
   */
  static std::optional<oc_endpoint_t> GetEndpoint(
    size_t device, unsigned flags = defaultEndpointIncludeFlags(),
    unsigned exclude_flags = kDefaultEndpointExcludeFlags);

  /** @brief Get pointer to a matching endpoint of a device
   *
   * @warning list of endpoints might get refreshed by each call of the method,
   * so you should not store the pointer for later use
   */
  static oc_endpoint_t *GetEndpointPtr(
    size_t device, unsigned flags = defaultEndpointIncludeFlags(),
    unsigned exclude_flags = kDefaultEndpointExcludeFlags);

private:
  static int SetSystemTime(oc_clock_time_t time, void *user_data);

  static Device device;
  static size_t index;
  static bool is_started;
  static std::vector<DeviceToAdd> server_devices;
#ifdef OC_SERVER
  static std::unordered_map<size_t, std::vector<oc_resource_t *>>
    dynamic_resources;
#endif /* OC_SERVER */

  static oc_clock_time_t system_time;
};

} // namespace oc

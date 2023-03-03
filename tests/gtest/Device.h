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
#include "util/oc_atomic.h"

#if defined(_WIN32)
#include <windows.h>
#else /* !_WIN32 */
#include <pthread.h>
#endif /* _WIN32 */

#include <stdint.h>
#include <string>
#include <vector>

namespace oc {

struct DeviceToAdd
{
  std::string rt;
  std::string name;
  std::string spec_version;
  std::string data_model_version;
};

class Device {
public:
  Device();
  ~Device() = default;

  void SignalEventLoop();
  void PoolEvents(uint16_t seconds);
  void PoolEventsMs(uint16_t mseconds);
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

#if defined(_WIN32)
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
};
#endif /* OC_SERVER */

class TestDevice {
public:
  TestDevice() = delete;

  static size_t Index() { return index; }
  static size_t IsStarted() { return is_started; }

  // IoTivity-lite application callbacks
  static int AppInit();
  static void RegisterResources()
  {
    // no-op
  }
  static void SignalEventLoop() { device.SignalEventLoop(); }
  static void PoolEvents(uint16_t seconds) { device.PoolEvents(seconds); }
  static void PoolEventsMs(uint16_t mseconds) { device.PoolEventsMs(mseconds); }

  static void SetServerDevices(std::vector<DeviceToAdd> devices);
  static void ResetServerDevices();
  static bool StartServer();
  static void StopServer();
  static void Terminate() { device.Terminate(); }

  static void DummyHandler(oc_request_t *, oc_interface_mask_t, void *)
  {
    // no-op
  }
#ifdef OC_SERVER
  static oc_resource_t *AddDynamicResource(const DynamicResourceToAdd &dr,
                                           size_t device);
#endif /* OC_SERVER */
  static const oc_endpoint_t *GetEndpoint(int flags = 0);

private:
  static Device device;
  static size_t index;
  static bool is_started;
  static std::vector<DeviceToAdd> server_devices;
#ifdef OC_SERVER
  std::vector<oc_resource_t *> dynamic_resources;
#endif /* OC_SERVER */
};

} // namespace oc

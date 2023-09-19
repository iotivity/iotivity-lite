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

#include "Device.h"

#include "api/oc_core_res_internal.h"
#include "api/oc_ri_internal.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_clock_util.h"
#include "oc_core_res.h"
#include "messaging/coap/engine.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "plgd/plgd_time.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <algorithm>
#include <array>
#include <gtest/gtest.h>
#include <optional>
#include <vector>

namespace oc {

using namespace std::chrono_literals;

void
testNotSupportedMethod(oc_method_t method, const oc_endpoint_t *ep,
                       const std::string &uri, encodePayloadFn payloadFn,
                       oc_status_t error_code)
{
  struct handlerData
  {
    bool invoked;
    oc_status_t error_code;
  };

  auto handler = [](oc_client_response_t *data) {
    auto *hd = static_cast<handlerData *>(data->user_data);
    EXPECT_EQ(hd->error_code, data->code);
    oc::TestDevice::Terminate();
    hd->invoked = true;
  };

  handlerData hd = { false, error_code };
  switch (method) {
  case OC_GET:
  case OC_DELETE:
    break;
  case OC_POST:
    ASSERT_TRUE(oc_init_post(uri.c_str(), ep, nullptr, handler, HIGH_QOS, &hd));
    break;
  case OC_PUT:
    ASSERT_TRUE(oc_init_put(uri.c_str(), ep, nullptr, handler, HIGH_QOS, &hd));
    break;
  default:
    GTEST_FAIL();
  }
  if (payloadFn != nullptr) {
    payloadFn();
  }

  auto timeout = 1s;
  switch (method) {
  case OC_GET:
    EXPECT_TRUE(oc_do_get_with_timeout(
      uri.c_str(), ep, nullptr, timeout.count(), handler, HIGH_QOS, &hd));
    break;
  case OC_DELETE:
    EXPECT_TRUE(oc_do_delete_with_timeout(
      uri.c_str(), ep, nullptr, timeout.count(), handler, HIGH_QOS, &hd));
    break;
  case OC_POST:
    ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));
    break;
  case OC_PUT:
    ASSERT_TRUE(oc_do_put_with_timeout(timeout.count()));
    break;
  default:
    GTEST_FAIL();
  }
  oc::TestDevice::PoolEventsMsV1(timeout, true);
  EXPECT_TRUE(hd.invoked);
}

Device::Device()
{
#ifdef _WIN32
  InitializeCriticalSection(&mutex_);
  InitializeConditionVariable(&cv_);
#else
  if (pthread_mutex_init(&mutex_, nullptr) != 0) {
    throw std::string("cannot initialize mutex");
  }
  pthread_condattr_t attr;
  if (pthread_condattr_init(&attr) != 0) {
    throw std::string("cannot attributes of conditional variable");
  }
  if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) != 0) {
    throw std::string("cannot configure clockid");
  }
  if (pthread_cond_init(&cv_, &attr) != 0) {
    throw std::string("cannot initialize conditional variable");
  }
  pthread_condattr_destroy(&attr);
#endif /* _WIN32 */
}

Device::~Device()
{
#ifndef _WIN32
  pthread_cond_destroy(&cv_);
  pthread_mutex_destroy(&mutex_);
#endif /* _WIN32 */
}

void
Device::SignalEventLoop()
{
  Lock();
#ifdef _WIN32
  WakeConditionVariable(&cv_);
#else
  pthread_cond_signal(&cv_);
#endif /* _WIN32 */
  Unlock();
}

void
Device::Lock()
{
#ifdef _WIN32
  EnterCriticalSection(&mutex_);
#else
  pthread_mutex_lock(&mutex_);
#endif /* _WIN32 */
}

void
Device::Unlock()
{
#ifdef _WIN32
  LeaveCriticalSection(&mutex_);
#else
  pthread_mutex_unlock(&mutex_);
#endif /* _WIN32 */
}

void
Device::WaitForEvent(oc_clock_time_t next_event_mt)
{
#ifdef _WIN32
  if (next_event_mt == 0) {
    SleepConditionVariableCS(&cv_, &mutex_, INFINITE);
    return;
  }
  oc_clock_time_t now_mt = oc_clock_time_monotonic();
  if (now_mt < next_event_mt) {
    SleepConditionVariableCS(
      &cv_, &mutex_,
      (DWORD)((next_event_mt - now_mt) * 1000 / OC_CLOCK_SECOND));
  }
#else
  if (next_event_mt == 0) {
    pthread_cond_wait(&cv_, &mutex_);
    return;
  }
  struct timespec next_event = { 1, 0 };
  if (oc_clock_time_t next_event_cv; oc_clock_monotonic_time_to_posix(
        next_event_mt, CLOCK_MONOTONIC, &next_event_cv)) {
    next_event = oc_clock_time_to_timespec(next_event_cv);
  }
  pthread_cond_timedwait(&cv_, &mutex_, &next_event);
#endif /* _WIN32 */
}

void
Device::Terminate()
{
  OC_ATOMIC_STORE8(terminate_, 1);
  SignalEventLoop();
#ifdef OC_REQUEST_HISTORY
  oc_request_history_init();
#endif /* OC_REQUEST_HISTORY */
}

void
Device::PoolEvents(uint64_t seconds, bool addDelay)
{
  PoolEventsMs(seconds * 1000, addDelay);
}

void
Device::PoolEventsMs(uint64_t mseconds, bool addDelay)
{
  OC_ATOMIC_STORE8(terminate_, 0);

  uint64_t interval = mseconds;
  if (addDelay) {
    // Add a delay to allow the server to process the request
    interval += 200;
  }
  oc_set_delayed_callback_ms_v1(this, Device::QuitEvent, interval);

  while (OC_ATOMIC_LOAD8(terminate_) == 0) {
    oc_clock_time_t next_event = oc_main_poll_v1();
    Lock();
    if (oc_main_needs_poll()) {
      Unlock();
      continue;
    }
    if (OC_ATOMIC_LOAD8(terminate_) != 0) {
      Unlock();
      break;
    }
    WaitForEvent(next_event);
    Unlock();
  }

  oc_remove_delayed_callback(this, Device::QuitEvent);
}

Device TestDevice::device{};
size_t TestDevice::index{ 0 };
bool TestDevice::is_started{ false };
std::vector<DeviceToAdd> TestDevice::server_devices{
  oc::DefaultDevice,
};
#ifdef OC_SERVER
std::unordered_map<size_t, std::vector<oc_resource_t *>>
  TestDevice::dynamic_resources{};
#endif /* OC_SERVER */
oc_clock_time_t TestDevice::system_time{ 0 };

int
TestDevice::AppInit()
{
  if (oc_init_platform("OCFTest", nullptr, nullptr) != 0) {
    return -1;
  }
  for (const auto &sd : server_devices) {
    if (oc_add_device(sd.uri.c_str(), sd.rt.c_str(), sd.name.c_str(),
                      sd.spec_version.c_str(), sd.data_model_version.c_str(),
                      nullptr, nullptr) != 0) {
      return -1;
    }
  }
  return 0;
}

size_t
TestDevice::CountDevices()
{
  return oc_core_get_num_devices();
}

void
TestDevice::SetServerDevices(std::vector<DeviceToAdd> devices)
{
  server_devices = devices;
}

void
TestDevice::ResetServerDevices()
{
  server_devices = { oc::DefaultDevice };
}

bool
TestDevice::StartServer()
{
  static oc_handler_t s_handler{};
  s_handler.init = AppInit;
  s_handler.signal_event_loop = SignalEventLoop;
#ifdef OC_SERVER
  s_handler.register_resources = RegisterResources;
#endif /* OC_SERVER */

  oc_set_con_res_announced(true);

  int ret = oc_main_init(&s_handler);
  if (ret < 0) {
    is_started = false;
    return false;
  }
  is_started = true;
  device.PoolEventsMs(200); // give some time for everything to start-up
  return true;
}

void
TestDevice::StopServer()
{
  device.Terminate();
  if (is_started) {
#ifdef OC_SERVER
    ClearDynamicResources();
#endif /* OC_SERVER */
    oc_main_shutdown();
  }
  ResetServerDevices();
}

#ifdef OC_SERVER

oc_resource_t *
TestDevice::AddDynamicResource(const DynamicResourceToAdd &dr, size_t device)
{
  oc_resource_t *res =
    oc_new_resource(dr.name.c_str(), dr.uri.c_str(), dr.rts.size(), device);
  for (const auto &rt : dr.rts) {
    oc_resource_bind_resource_type(res, rt.c_str());
  }
  for (const auto &iface : dr.ifaces) {
    oc_resource_bind_resource_interface(res, iface);
  }

  unsigned permission = 0;
  if (dr.handlers.onGet != nullptr) {
    oc_resource_set_request_handler(res, OC_GET, dr.handlers.onGet,
                                    dr.handlers.onGetData);
    permission |= OC_PERM_RETRIEVE;
  }
  if (dr.handlers.onPost != nullptr) {
    oc_resource_set_request_handler(res, OC_POST, dr.handlers.onPost,
                                    dr.handlers.onPostData);
    permission |= OC_PERM_UPDATE;
  }
  if (dr.handlers.onPut != nullptr) {
    oc_resource_set_request_handler(res, OC_PUT, dr.handlers.onPut,
                                    dr.handlers.onPutData);
    permission |= OC_PERM_UPDATE;
  }
  if (dr.handlers.onDelete != nullptr) {
    oc_resource_set_request_handler(res, OC_DELETE, dr.handlers.onDelete,
                                    dr.handlers.onDeleteData);
    permission |= OC_PERM_DELETE;
  }

  (void)permission;
#ifdef OC_SECURITY
  if ((dr.properties & OC_SECURE) == 0) {
    oc_resource_make_public(res);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_set_access_in_RFOTM(
      res, true, static_cast<oc_ace_permissions_t>(permission));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }
#endif /* OC_SECURITY */

  oc_resource_set_discoverable(res, (dr.properties & OC_DISCOVERABLE) != 0);
  oc_resource_set_observable(res, (dr.properties & OC_OBSERVABLE) != 0);

  if (!oc_add_resource(res)) {
    oc_delete_resource(res);
    return nullptr;
  }

  dynamic_resources[device].push_back(res);
  return res;
}

oc_resource_t *
TestDevice::GetDynamicResource(size_t device, size_t index)
{
  return dynamic_resources[device].at(index);
}

void
TestDevice::ClearDynamicResource(size_t device, size_t index, bool doDelete)
{
  auto it = dynamic_resources[device].begin() + index;
  oc_resource_t *res = *it;
  dynamic_resources[device].erase(it);
  if (doDelete) {
    oc_delete_resource(res);
  }
}

bool
TestDevice::ClearDynamicResource(oc_resource_t *resource, bool doDelete)
{
  for (auto &dev : dynamic_resources) {
    auto it = std::find(dev.second.begin(), dev.second.end(), resource);
    if (it != dev.second.end()) {
      dev.second.erase(it);
      if (doDelete) {
        oc_delete_resource(resource);
      }
      return true;
    }
  }
  return false;
}

void
TestDevice::ClearDynamicResources()
{
  for (auto it : dynamic_resources) {
    for (auto *res : it.second) {
      oc_delete_resource(res);
    }
  }
  dynamic_resources.clear();
}

#endif /* OC_SERVER */

oc_endpoint_t *
TestDevice::GetEndpointPtr(size_t device, unsigned flags,
                           unsigned exclude_flags)
{
  oc_endpoint_t *ep = oc_connectivity_get_endpoints(device);
  auto has_matching_flags = [](const oc_endpoint_t *ep, unsigned flags,
                               unsigned exclude_flags) {
    if (flags == 0 && exclude_flags == 0) {
      return true;
    }
    if (exclude_flags != 0) {
      if ((ep->flags & exclude_flags) != 0) {
        return false;
      }
    }
    return (ep->flags & flags) == flags;
  };

  auto has_matching_device = [](const oc_endpoint_t *ep, size_t device) {
    return device == SIZE_MAX || ep->device == device;
  };

  while (ep != nullptr) {
    if (has_matching_flags(ep, flags, exclude_flags) &&
        has_matching_device(ep, device)) {
      return ep;
    }
    ep = ep->next;
  }
  return nullptr;
}

std::optional<oc_endpoint_t>
TestDevice::GetEndpoint(size_t device, unsigned flags, unsigned exclude_flags)
{
  oc_endpoint_t *ep = GetEndpointPtr(device, flags, exclude_flags);
  if (ep != nullptr) {
    return *ep;
  }
  return std::nullopt;
}

int
TestDevice::SetSystemTime(oc_clock_time_t time, void *user_data)
{
  auto *v = static_cast<oc_clock_time_t *>(user_data);
  *v = time;

  std::array<char, 64> ts{};
  oc_clock_encode_time_rfc3339(time, ts.data(), ts.size());
  OC_DBG("set system_time: %s", ts.data());
  return 0;
}

#ifdef OC_HAS_FEATURE_PLGD_TIME
void
TestDevice::ConfigurePlgdTime(bool useInMbedTLS)
{
  plgd_time_configure(useInMbedTLS, TestDevice::SetSystemTime,
                      &TestDevice::system_time);
}
#endif /*OC_HAS_FEATURE_PLGD_TIME*/

} // namespace oc

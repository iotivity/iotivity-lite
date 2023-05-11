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
#include "oc_core_res.h"

#ifdef OC_HAS_FEATURE_PLGD_TIME
#include "plgd/plgd_time.h"
#endif /* OC_HAS_FEATURE_PLGD_TIME */

#include <array>
#include <gtest/gtest.h>
#include <vector>

namespace oc {

void
testNotSupportedMethod(oc_method_t method, const oc_endpoint_t *ep,
                       const std::string &uri, encodePayloadFn payloadFn)
{
  auto handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_METHOD_NOT_ALLOWED, data->code);
    oc::TestDevice::Terminate();
    bool *invoked = static_cast<bool *>(data->user_data);
    *invoked = true;
  };

  bool invoked = false;
  switch (method) {
  case OC_GET:
  case OC_DELETE:
    break;
  case OC_POST:
    ASSERT_TRUE(
      oc_init_post(uri.c_str(), ep, nullptr, handler, HIGH_QOS, &invoked));
    break;
  case OC_PUT:
    ASSERT_TRUE(
      oc_init_put(uri.c_str(), ep, nullptr, handler, HIGH_QOS, &invoked));
    break;
  default:
    GTEST_FAIL();
  }
  if (payloadFn != nullptr) {
    payloadFn();
  }
  switch (method) {
  case OC_GET:
    EXPECT_TRUE(
      oc_do_get(uri.c_str(), ep, nullptr, handler, HIGH_QOS, &invoked));
    break;
  case OC_DELETE:
    EXPECT_TRUE(
      oc_do_delete(uri.c_str(), ep, nullptr, handler, HIGH_QOS, &invoked));
    break;
  case OC_POST:
    ASSERT_TRUE(oc_do_post());
    break;
  case OC_PUT:
    ASSERT_TRUE(oc_do_put());
    break;
  default:
    GTEST_FAIL();
  }
  oc::TestDevice::PoolEvents(5);

  EXPECT_TRUE(invoked);
}

Device::Device()
{
#ifdef _WIN32
  InitializeCriticalSection(&mutex_);
  InitializeConditionVariable(&cv_);
#else
  if (pthread_mutex_init(&mutex_, nullptr) != 0) {
    throw "cannot initialize mutex";
  }
  if (pthread_cond_init(&cv_, nullptr) != 0) {
    throw "cannot initialize conditional variable";
  }
#endif /* _WIN32 */
}

void
Device::SignalEventLoop()
{
#ifdef _WIN32
  WakeConditionVariable(&cv_);
#else
  pthread_cond_signal(&cv_);
#endif
}

void
Device::Lock()
{
#ifdef _WIN32
  EnterCriticalSection(&mutex_);
#else
  pthread_mutex_lock(&mutex_);
#endif
}

void
Device::Unlock()
{
#ifdef _WIN32
  LeaveCriticalSection(&mutex_);
#else
  pthread_mutex_unlock(&mutex_);
#endif
}

void
Device::WaitForEvent(oc_clock_time_t next_event)
{
#ifdef _WIN32
  if (next_event == 0) {
    SleepConditionVariableCS(&cv_, &mutex_, INFINITE);
    return;
  }
  oc_clock_time_t now = oc_clock_time();
  if (now < next_event) {
    SleepConditionVariableCS(
      &cv_, &mutex_, (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
  }
#else
  if (next_event == 0) {
    pthread_cond_wait(&cv_, &mutex_);
    return;
  }
  struct timespec ts;
  ts.tv_sec = (next_event / OC_CLOCK_SECOND);
  ts.tv_nsec =
    static_cast<long>((next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND);
  pthread_cond_timedwait(&cv_, &mutex_, &ts);
#endif
}

void
Device::Terminate()
{
  OC_ATOMIC_STORE8(terminate_, 1);
}

void
Device::PoolEvents(uint64_t seconds)
{
  PoolEventsMs(seconds * 1000);
}

void
Device::PoolEventsMs(uint64_t mseconds)
{
  OC_ATOMIC_STORE8(terminate_, 0);
  oc_set_delayed_callback_ms_v1(this, Device::QuitEvent, mseconds);

  while (OC_ATOMIC_LOAD8(terminate_) == 0) {
    Lock();
    oc_clock_time_t next_event = oc_main_poll();
    if (OC_ATOMIC_LOAD8(terminate_) != 0) {
      Unlock();
      break;
    }
    WaitForEvent(next_event);
    Unlock();
  }

  oc_remove_delayed_callback(this, Device::QuitEvent);
}

const DeviceToAdd defaultDevice = {
  /*rt=*/"oic.d.test",
  /*name=*/"Test Device",
  /*spec_version=*/"ocf.1.0.0",
  /*data_model_version=*/"ocf.res.1.0.0",
  /*uri=*/"/oic/d",
};

Device TestDevice::device{};
size_t TestDevice::index{ 0 };
bool TestDevice::is_started{ false };
std::vector<DeviceToAdd> TestDevice::server_devices{
  defaultDevice,
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
  server_devices = { defaultDevice };
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

#ifdef OC_SECURITY
  if (dr.isPublic) {
    oc_resource_make_public(res);
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    oc_resource_set_access_in_RFOTM(
      res, true, static_cast<oc_ace_permissions_t>(permission));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }
#else  /* !OC_SECURITY */
  (void)permission;
#endif /* OC_SECURITY */

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
TestDevice::GetEndpoint(size_t device, unsigned flags, unsigned exclude_flags)
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

int
TestDevice::SetSystemTime(oc_clock_time_t time, void *user_data)
{
  auto *v = static_cast<oc_clock_time_t *>(user_data);
  *v = time;

  std::array<char, 64> ts = { 0 };
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

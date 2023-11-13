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

#pragma once

#include "oc_endpoint.h"
#include "port/oc_connectivity.h"

#include <chrono>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace oc::coap::message {

using oc_message_unique_ptr =
  std::unique_ptr<oc_message_t, void (*)(oc_message_t *)>;

using token_t = std::vector<uint8_t>;

class SyncQueue {
public:
  SyncQueue() = default;
  ~SyncQueue() = default;

  SyncQueue(const SyncQueue &) = delete;
  SyncQueue &operator=(const SyncQueue &) = delete;
  SyncQueue(SyncQueue &&) = delete;
  SyncQueue &operator=(SyncQueue &&) = delete;

  void Push(oc_message_unique_ptr &&message);
  oc_message_unique_ptr Pop();
  bool IsEmpty() const;

private:
  mutable std::mutex mutex_;
  std::deque<oc_message_unique_ptr> queue_;
};

/** Wait for the synchronized queue to receive a message until a timeout */
oc_message_unique_ptr WaitForMessage(
  SyncQueue &queue, std::function<void(std::chrono::milliseconds)> runFor,
  std::chrono::milliseconds timeout);

/** Use oc::TestDevice to poll and wait the synchronized queue to receive a
 * message. */
oc_message_unique_ptr WaitForMessage(SyncQueue &queue,
                                     std::chrono::milliseconds timeout);

/** Allocate message from test pool */
oc_message_unique_ptr AllocateMessage();

#ifdef OC_TCP

namespace tcp {

/** Create observation registration message */
oc_message_unique_ptr RegisterObserve(token_t token, const std::string &uri,
                                      const std::string &query,
                                      const oc_endpoint_t *endpoint);

} // namespace tcp

#endif // OC_TCP

} // namespace oc::coap::message

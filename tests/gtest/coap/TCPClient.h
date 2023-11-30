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

#include "util/oc_features.h"

#ifdef OC_TCP

#include "messaging/coap/coap_internal.h"
#include "Message.h"
#include "oc_endpoint.h"
#include "port/oc_tcp_socket_internal.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace oc::coap {

using OnRead = std::function<void(message::oc_message_unique_ptr &&)>;

class TCPClient {
public:
  TCPClient(OnRead onRead);
  ~TCPClient();

  TCPClient(TCPClient &) = delete;
  TCPClient &operator=(const TCPClient &) = delete;
  TCPClient(TCPClient &&) noexcept = delete;
  TCPClient &operator=(TCPClient &&) = delete;

  bool Connect(const oc_endpoint_t *endpoint);
  void Close();

  long Send(const uint8_t *data, size_t size);

  void Run();
  void Terminate();

private:
  OnRead onRead_;
  oc_endpoint_t endpoint_;
  OC_SOCKET_T socket_;
  std::atomic_bool terminated_;

  OC_SOCKET_T ConnectAndWait(const oc_endpoint_t *endpoint);

  message::oc_message_unique_ptr ReceiveMessage();
  long Receive(uint8_t *buffer, size_t size);

  bool Poll(
    std::chrono::milliseconds timeout = std::chrono::milliseconds::zero());
};

} // namespace oc::coap

#endif // OC_TCP

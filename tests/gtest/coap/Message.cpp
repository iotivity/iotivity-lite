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

#include "api/oc_helpers_internal.h"
#include "api/oc_message_internal.h"
#include "Message.h"
#include "messaging/coap/coap_internal.h"
#include "messaging/coap/constants.h"
#include "messaging/coap/options_internal.h"
#include "tests/gtest/Device.h"
#include "util/oc_memb.h"

#ifdef OC_TCP
#include "messaging/coap/signal_internal.h"
#endif // OC_TCP

#include <array>

namespace oc::coap::message {

constexpr size_t kPoolSize = 8;
OC_MEMB(test_messages, oc_message_t, kPoolSize);

bool
SyncQueue::IsEmpty() const
{
  std::lock_guard<std::mutex> lock(mutex_);
  return queue_.empty();
}

void
SyncQueue::Push(oc_message_unique_ptr &&message)
{
  std::lock_guard<std::mutex> lock(mutex_);
  queue_.emplace_back(std::move(message));
}

oc_message_unique_ptr
SyncQueue::Pop()
{
  std::lock_guard<std::mutex> lock(mutex_);
  if (queue_.empty()) {
    return oc_message_unique_ptr(nullptr, nullptr);
  }
  auto message = std::move(queue_.front());
  queue_.pop_front();
  return message;
}

oc_message_unique_ptr
WaitForMessage(SyncQueue &queue,
               std::function<void(std::chrono::milliseconds)> runFor,
               std::chrono::milliseconds timeout)
{
  while (true) {
    auto msg = queue.Pop();
    if (!msg) {
      runFor(timeout);
      msg = queue.Pop();
    }

    if (!msg) {
      return message::oc_message_unique_ptr(nullptr, nullptr);
    }

#ifdef OC_TCP
    coap_packet_t packet;
    if (coap_tcp_parse_message(&packet, msg->data, msg->length, false) !=
        COAP_NO_ERROR) {
      return message::oc_message_unique_ptr(nullptr, nullptr);
    }
    if (coap_check_signal_message(packet.code)) {
      continue;
    }
#endif // OC_TCP
    return msg;
  }
}

oc_message_unique_ptr
WaitForMessage(SyncQueue &queue, std::chrono::milliseconds timeout)
{
  return WaitForMessage(
    queue,
    [](std::chrono::milliseconds t) { oc::TestDevice::PoolEventsMsV1(t); },
    timeout);
}

oc_message_unique_ptr
AllocateMessage()
{
  oc_message_t *message = oc_allocate_message_from_pool(&test_messages);
  if (message == nullptr) {
    return oc_message_unique_ptr(nullptr, oc_message_unref);
  }
  return oc_message_unique_ptr(message, oc_message_unref);
}

#ifdef OC_TCP

namespace tcp {

oc_message_unique_ptr
RegisterObserve(token_t token, const std::string &uri, const std::string &query,
                const oc_endpoint_t *endpoint)
{
  coap_packet_t pkt;
  coap_tcp_init_message(&pkt, COAP_GET);

  if (!token.empty()) {
    coap_set_token(&pkt, &token[0], token.size());
  }
  coap_options_set_accept(&pkt, APPLICATION_VND_OCF_CBOR);
  coap_options_set_uri_path(&pkt, uri.c_str(), uri.length());
  if (!query.empty()) {
    coap_options_set_uri_query(&pkt, query.c_str(), query.length());
  }
  coap_options_set_observe(&pkt, OC_COAP_OPTION_OBSERVE_REGISTER);

  auto message = AllocateMessage();
  if (message.get() == nullptr) {
    return message;
  }
  memcpy(&message->endpoint, endpoint, sizeof(oc_endpoint_t));
  message->length =
    coap_serialize_message(&pkt, message->data, oc_message_buffer_size());

  return message;
}

} // namespace tcp

#endif // OC_TCP

} // namespace oc::coap::message

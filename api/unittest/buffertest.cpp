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

#include "api/oc_message_internal.h"
#include "api/oc_message_buffer_internal.h"
#include "api/oc_ri_internal.h"
#include "api/oc_runtime_internal.h"
#include "oc_buffer.h"
#include "oc_config.h"
#include "port/oc_allocator_internal.h"
#include "port/oc_network_event_handler_internal.h"
#include "util/oc_features.h"
#include "util/oc_memb.h"
#include "util/oc_process_internal.h"

#include <gtest/gtest.h>
#include <memory>

constexpr size_t kTestMessagesPoolSize = 1;
OC_MEMB(oc_test_messages, oc_message_t, kTestMessagesPoolSize);

using oc_message_unique_ptr =
  std::unique_ptr<oc_message_t, void (*)(oc_message_t *)>;

class TestMessage : public testing::Test {
public:
  static void SetUpTestCase()
  {
    (void)kTestMessagesPoolSize;
#ifndef OC_DYNAMIC_ALLOCATION
    oc_allocator_mutex_init();
#endif /* OC_DYNAMIC_ALLOCATION */
    oc_memb_init(&oc_test_messages);
    oc_set_buffers_avail_cb(onIncomingBufferAvailable);
    oc_memb_set_buffers_avail_cb(&oc_test_messages, onTestBufferAvailable);
  }

  static void TearDownTestCase()
  {
    oc_set_buffers_avail_cb(nullptr);
#ifndef OC_DYNAMIC_ALLOCATION
    oc_allocator_mutex_destroy();
#endif /* OC_DYNAMIC_ALLOCATION */
  }

  void SetUp() override
  {
    incomingBufferAvailableCount_ = -1;
    testBufferAvailableCount_ = -1;
  }

  static void onIncomingBufferAvailable(int count)
  {
    incomingBufferAvailableCount_ = count;
  }
  static void onTestBufferAvailable(int count)
  {
    testBufferAvailableCount_ = count;
  }

  static int incomingBufferAvailableCount_;
  static int testBufferAvailableCount_;
};

int TestMessage::incomingBufferAvailableCount_ = -1;
int TestMessage::testBufferAvailableCount_ = -1;

TEST_F(TestMessage, AllocateFromPool_Fail)
{
  EXPECT_EQ(nullptr, oc_allocate_message_from_pool(nullptr));
}

TEST_F(TestMessage, AllocateAndDeallocateFromPool)
{
  oc_message_t *message = oc_allocate_message_from_pool(&oc_test_messages);
  EXPECT_NE(nullptr, message);
  oc_message_unref(message);

#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(kTestMessagesPoolSize, TestMessage::testBufferAvailableCount_);
  EXPECT_EQ(-1, TestMessage::incomingBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestMessage, AllocateAndDeallocateFromPoolStatic)
{
  EXPECT_EQ(kTestMessagesPoolSize, oc_memb_numfree(&oc_test_messages));
  oc_message_t *message = oc_allocate_message_from_pool(&oc_test_messages);
  EXPECT_NE(nullptr, message);
  EXPECT_EQ(kTestMessagesPoolSize - 1, oc_memb_numfree(&oc_test_messages));

  oc_message_unref(message);
  EXPECT_EQ(kTestMessagesPoolSize, oc_memb_numfree(&oc_test_messages));

  EXPECT_EQ(kTestMessagesPoolSize, TestMessage::testBufferAvailableCount_);
  EXPECT_EQ(-1, TestMessage::incomingBufferAvailableCount_);
}

#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestMessage, ReferenceCountIgnore)
{
  // no segfauls, these calls should be ignored
  oc_message_add_ref(nullptr);
  oc_message_unref(nullptr);
}

TEST_F(TestMessage, ReferenceCount)
{
  // refcount = 1
  oc_message_t *msg = oc_allocate_message_from_pool(&oc_test_messages);
  EXPECT_NE(nullptr, msg);

  // refcount = 2
  oc_message_add_ref(msg);

  // refcount = 1
  oc_message_unref(msg);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(-1, TestMessage::testBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */

  // refcount = 0 -> deallocate
  oc_message_unref(msg);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(kTestMessagesPoolSize, TestMessage::testBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestMessage, AllocateAndDeallocateIncomming)
{
  oc_message_t *in = oc_allocate_message();
  EXPECT_NE(nullptr, in);

  oc_message_t *in_with_size = oc_message_allocate_with_size(1337);
  EXPECT_NE(nullptr, in_with_size);

  oc_message_unref(in_with_size);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(-1, TestMessage::testBufferAvailableCount_);
  EXPECT_EQ(OC_MAX_NUM_CONCURRENT_REQUESTS - 1,
            TestMessage::incomingBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_message_unref(in);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(-1, TestMessage::testBufferAvailableCount_);
  EXPECT_EQ(OC_MAX_NUM_CONCURRENT_REQUESTS,
            TestMessage::incomingBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestMessage, AllocateAndDeallocateIncomming_Fail)
{
  std::vector<oc_message_unique_ptr> messages{};
  for (size_t i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    oc_message_t *in = oc_allocate_message();
    ASSERT_NE(nullptr, in);
    messages.push_back(oc_message_unique_ptr(in, &oc_message_unref));
  }

  oc_message_t *in = oc_allocate_message();
  EXPECT_EQ(nullptr, in);

  // incoming and outgoing buffers do not share the allocation pool, so
  // after exhausting of incoming messages we should still get an outgoing
  // message
  oc_message_t *out = oc_message_allocate_outgoing();
  EXPECT_NE(nullptr, out);
  oc_message_unref(out);
}

#endif /* OC_DYNAMIC_ALLOCATION */

TEST_F(TestMessage, AllocateAndDeallocateOutgoing)
{
  oc_message_t *out = oc_message_allocate_outgoing();
  EXPECT_NE(nullptr, out);

  oc_message_t *out_with_size = oc_message_allocate_outgoing_with_size(1337);
  EXPECT_NE(nullptr, out_with_size);

  oc_message_unref(out_with_size);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(-1, TestMessage::testBufferAvailableCount_);
  EXPECT_EQ(-1, TestMessage::incomingBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_message_unref(out);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(-1, TestMessage::testBufferAvailableCount_);
  EXPECT_EQ(-1, TestMessage::incomingBufferAvailableCount_);
#endif /* OC_DYNAMIC_ALLOCATION */
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestMessage, AllocateAndDeallocateOutgoing_Fail)
{
  std::vector<oc_message_unique_ptr> messages{};
  for (size_t i = 0; i < OC_MAX_NUM_CONCURRENT_REQUESTS; ++i) {
    oc_message_t *out = oc_message_allocate_outgoing();
    ASSERT_NE(nullptr, out);
    messages.push_back(oc_message_unique_ptr(out, &oc_message_unref));
  }

  oc_message_t *out = oc_message_allocate_outgoing();
  EXPECT_EQ(nullptr, out);

  // incoming and outgoing buffers do not share the allocation pool, so
  // after exhausting of outgoing messages we should still get an incoming
  // message
  oc_message_t *in = oc_allocate_message();
  EXPECT_NE(nullptr, in);
  oc_message_unref(in);
}

#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_TEST

template<class Event, void Op(Event *)>
void
testProcessMessagesByProcess()
{
  oc_network_event_handler_mutex_init();
  oc_runtime_init();
  oc_ri_init();

  using oc_event_uptr = std::unique_ptr<Event, void (*)(Event *)>;
  oc_process_num_events_t size = oc_process_num_events();
  std::vector<oc_event_uptr> events{};
  for (size_t i = 0; i < size; ++i) {
    auto *event = new Event;
    events.push_back(oc_event_uptr(event, [](Event *evt) { delete evt; }));
    Op(event);
  }
  ASSERT_EQ(size, oc_process_nevents());

  auto *event = new Event;
  Op(event);
#ifdef OC_DYNAMIC_ALLOCATION
  // with dynamic allocation the maximal number of events should simply double
  // and everything should success
  events.push_back(oc_event_uptr(event, [](Event *evt) { delete evt; }));

  EXPECT_EQ(size + 1, oc_process_nevents());
  EXPECT_LT(size, oc_process_num_events());
#else  /* !OC_DYNAMIC_ALLOCATION */
  // with static allocation the message should be thrown away and deallocated
  EXPECT_EQ(size, oc_process_nevents());
  EXPECT_EQ(size, oc_process_num_events());
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_message_buffer_handler_stop();
  oc_ri_shutdown();
  oc_runtime_shutdown();
  oc_network_event_handler_mutex_destroy();
}

TEST_F(TestMessage, RecvMessageByProcess)
{
  testProcessMessagesByProcess<oc_message_t, oc_recv_message>();
}

TEST_F(TestMessage, SendMessageByProcess)
{
  testProcessMessagesByProcess<oc_message_t, oc_send_message>();
}

#ifdef OC_HAS_FEATURE_TCP_ASYNC_CONNECT

TEST_F(TestMessage, TCPConnectByProcess)
{
  testProcessMessagesByProcess<oc_tcp_on_connect_event_t,
                               oc_tcp_connect_session>();
}

#endif /* OC_HAS_FEATURE_TCP_ASYNC_CONNECT */

#endif /* OC_TEST */

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

#include "api/oc_events_internal.h"
#include "port/oc_log_internal.h"

#include <gtest/gtest.h>

class TestEvents : public testing::Test {
public:
  static void SetUpTestCase() { oc_event_assign_oc_process_events(); }
};

#if OC_DBG_IS_ENABLED

TEST_F(TestEvents, ProcessEventName)
{
  for (int ev = 0; ev < __NUM_OC_EVENT_TYPES__; ++ev) {
    auto name = oc_process_event_name(static_cast<oc_process_event_t>(ev));
    EXPECT_NE(name.data, nullptr);
  }
}

#endif /* OC_DBG_IS_ENABLED */

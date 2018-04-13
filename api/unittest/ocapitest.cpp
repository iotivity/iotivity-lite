/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 *
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

#include <cstdlib>
#include "gtest/gtest.h"

extern "C" {
    #include "oc_api.h"
}

#define UUID "12345678123412341234123456789012"


static int app_init(void)
{
  return 0;
}

static void register_resources(void)
{
}

static void signal_event_loop(void)
{
}

TEST(TestServerClient, ServerStartTest_P) {

    static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources };

    int result = oc_main_init(&handler);
    EXPECT_GE(result,  0);
 
    oc_main_shutdown();
}

TEST(TestServerClient, ServerStopTest_P) {

    static const oc_handler_t handler = {.init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources };

    int result = oc_main_init(&handler);
    ASSERT_GE(result,  0);
 
    EXPECT_NO_THROW(oc_main_shutdown());
}

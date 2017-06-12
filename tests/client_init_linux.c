/*
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "test.h"

#include "oc_api.h"
#include "port/oc_clock.h"

#include <stdio.h>

static int
app_init(void)
{
  int ret;

  ret = oc_init_platform("Intel", NULL, NULL);
  ASSERT(ret == 0);

  ret = oc_add_device("/oic/d", "oic.d.test-client-init", "Client init test", "1.0", "1.0",
                       NULL, NULL);
  return ret;
}

static void
issue_requests(void)
{
}

static void
signal_event_loop(void)
{
}

int
main(void)
{
  int init;

  oc_handler_t handler = {
    .init = app_init,
    .signal_event_loop = signal_event_loop,
    .requests_entry = issue_requests
  };

  init = oc_main_init(&handler);
  ASSERT(init == 0);
  oc_main_shutdown();

  return 0;
}

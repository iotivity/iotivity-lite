/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
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

#include "gtest/gtest.h"
#include <cstdlib>

extern "C"
{
#include "oc_api.h"
#include "oc_core_res.h"
#include <sys/stat.h>
#include <sys/types.h>
}

static int
app_init(void)
{
  int ret = oc_init_platform("UnitTest", NULL, NULL);
  ret |= oc_add_device("/oic/d", "oic.d.light", "Lamp", "ocf.1.0.0",
                       "ocf.res.1.0.0", NULL, NULL);
  return ret;
}

static void
post_light(oc_request_t *request, oc_interface_mask_t interface,
           void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  PRINT("%s\n", __func__);
}

static void
put_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  PRINT("%s\n", __func__);
}

static void
get_light(oc_request_t *request, oc_interface_mask_t interface, void *user_data)
{
  (void)interface;
  (void)user_data;
  (void)request;
  PRINT("%s\n", __func__);
}

static void
register_resources(void)
{
  oc_resource_t *res = oc_new_resource(NULL, "/a/light", 2, 0);
  oc_resource_bind_resource_type(res, "core.light");
  oc_resource_bind_resource_type(res, "core.brightlight");
  oc_resource_bind_resource_interface(res, OC_IF_RW);
  oc_resource_set_default_interface(res, OC_IF_RW);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, 1);
  oc_resource_set_request_handler(res, OC_GET, get_light, NULL);
  oc_resource_set_request_handler(res, OC_PUT, put_light, NULL);
  oc_resource_set_request_handler(res, OC_POST, post_light, NULL);
  oc_add_resource(res);
}

static void
signal_event_loop(void)
{
  PRINT("%s\n", __func__);
}

void
requests_entry(void)
{
  PRINT("%s\n", __func__);
}

TEST(Security, Init)
{
  static const oc_handler_t handler = { .init = app_init,
                                        .signal_event_loop = signal_event_loop,
                                        .register_resources =
                                          register_resources,
                                        .requests_entry = NULL };

  mkdir("unittest_creds", 0770);
  oc_storage_config("unittest_creds");
  oc_main_init(&handler);
  oc_core_regen_unique_ids(0);
}

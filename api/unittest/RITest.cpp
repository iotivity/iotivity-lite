/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *           2021 CASCODA LTD        All Rights Reserved.
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
#include <gtest/gtest.h>
#include <stdio.h>
#include <string>

#include "oc_api.h"
#include "oc_helpers.h"
#include "oc_ri.h"
#include "oc_collection.h"
#include "port/linux/oc_config.h"

#define RESOURCE_URI "/LightResourceURI"
#define RESOURCE_NAME "roomlights"
#define OBSERVERPERIODSECONDS_P 1

class TestOcRi : public testing::Test {
protected:
  virtual void SetUp() { oc_ri_init(); }
  virtual void TearDown() { oc_ri_shutdown(); }
};

static void
onGet(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)request;
  (void)iface_mask;
  (void)user_data;
}

TEST_F(TestOcRi, GetAppResourceByUri_P)
{
  oc_resource_t *res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
  oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
  bool add_check = oc_ri_add_resource(res);
  EXPECT_TRUE(add_check);

  res = oc_ri_get_app_resource_by_uri(RESOURCE_URI, strlen(RESOURCE_URI), 0);
  EXPECT_NE(nullptr, res);
  bool del_check = oc_ri_delete_resource(res);
  EXPECT_TRUE(del_check);
}

TEST_F(TestOcRi, GetAppResourceByUri_N)
{
  oc_resource_t *res =
    oc_ri_get_app_resource_by_uri(RESOURCE_URI, strlen(RESOURCE_URI), 0);
  EXPECT_EQ(nullptr, res);
}

TEST_F(TestOcRi, RiGetAppResource_P)
{
  oc_resource_t *res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
  oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
  bool add_check = oc_ri_add_resource(res);
  EXPECT_TRUE(add_check);
  res = oc_ri_get_app_resources();
  EXPECT_NE(nullptr, res);
  bool del_check = oc_ri_delete_resource(res);
  EXPECT_TRUE(del_check);
}

TEST_F(TestOcRi, RiGetAppResource_N)
{
  oc_resource_t *res = oc_ri_get_app_resources();
  EXPECT_EQ(nullptr, res);
}

TEST_F(TestOcRi, RiAllocResource_P)
{
  oc_resource_t *res = oc_ri_alloc_resource();
  EXPECT_NE(nullptr, res);
  oc_ri_dealloc_resource(res);
}

TEST_F(TestOcRi, RiFreeResourceProperties_P)
{
  oc_resource_t *res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
  oc_ri_free_resource_properties(res);
  EXPECT_EQ(0, oc_string_len(res->name));
  bool del_check = oc_ri_delete_resource(res);
  EXPECT_EQ(true, del_check);
}

TEST_F(TestOcRi, RiAddResource_P)
{
  oc_resource_t *res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
  oc_resource_set_request_handler(res, OC_GET, onGet, NULL);
  bool add_check = oc_ri_add_resource(res);
  EXPECT_EQ(true, add_check);
  bool del_check = oc_ri_delete_resource(res);
  EXPECT_EQ(true, del_check);
}

TEST_F(TestOcRi, RIGetQueryValue_P)
{
  const char *input[] = { "key=1",          "data=1&key=2",     "key=2&data=3",
                          "x&key=2&data=3", "y&x&key=2&data=3", "y&x&key=2",
                          "y&x&key=2&y" };
  int ret;
  char *value;

  for (int i = 0; i < 7; i++) {
    ret = oc_ri_get_query_value(input[i], strlen(input[i]), "key", &value);
    EXPECT_EQ(1, ret) << "P input[" << i << "] " << input[i] << " "
                      << "key";
  }
  for (int i = 0; i < 7; i++) {
    ret = oc_ri_get_query_value(input[i], strlen(input[i]), "key2", &value);
    EXPECT_EQ(-1, ret) << "N input[" << i << "] " << input[i] << " "
                       << "key2";
  }
}

TEST_F(TestOcRi, RIQueryExists_P)
{
  const char *input[] = { "key=1",
                          "key",
                          "data=1&key=2",
                          "data=2&key",
                          "key&data=3",
                          "key=2&data=3",
                          "x=1&key=2&data=3",
                          "y=&key=2&data=3",
                          "y=1&x&key=2&data=3",
                          "y=1&x&key" };
  int ret;
  for (int i = 0; i < 10; i++) {
    ret = oc_ri_query_exists(input[i], strlen(input[i]), "key");
    EXPECT_EQ(1, ret) << "P input[" << i << "] " << input[i] << " "
                      << "key";
  }
  for (int i = 0; i < 10; i++) {
    ret = oc_ri_query_exists(input[i], strlen(input[i]), "key2");
    EXPECT_EQ(-1, ret) << "N input[" << i << "] " << input[i] << " "
                       << "key2";
  }
}

bool
find_resource_in_collections(oc_resource_t *resource)
{
  oc_collection_t *collection = oc_collection_get_all();
  while (collection) {
    oc_link_t *link = (oc_link_t *)oc_list_head(collection->links);
    while (link) {
      if (link->resource == resource) {
        return true;
      }
      link = link->next;
    }
    collection = (oc_collection_t *)collection->res.next;
  }
  return false;
}

TEST_F(TestOcRi, RiCleanupCollection_P)
{
  oc_resource_t *col = oc_new_collection(NULL, "/switches", 1, 0);
  oc_resource_bind_resource_type(col, "oic.wk.col");
  oc_resource_set_discoverable(col, true);
  oc_resource_set_observable(col, true);
  oc_collection_add_supported_rt(col, "oic.r.switch.binary");
  oc_collection_add_mandatory_rt(col, "oic.r.switch.binary");
  oc_add_collection(col);

  oc_resource_t *res = oc_new_resource(RESOURCE_NAME, RESOURCE_URI, 1, 0);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_periodic_observable(res, OBSERVERPERIODSECONDS_P);
  oc_resource_set_request_handler(res, OC_GET, onGet, NULL);

  oc_link_t *l = oc_new_link(res);
  oc_collection_add_link(col, l);
  bool add_check = oc_ri_add_resource(res);
  EXPECT_TRUE(add_check);
  bool find_check = find_resource_in_collections(res);
  EXPECT_TRUE(find_check);

  res = oc_ri_get_app_resources();
  EXPECT_NE(nullptr, res);
  bool del_check = oc_ri_delete_resource(res);
  EXPECT_TRUE(del_check);

  find_check = find_resource_in_collections(res);
  EXPECT_FALSE(find_check);
  oc_delete_collection(col);
  res = oc_ri_get_app_resources();
  EXPECT_EQ(nullptr, res);
}
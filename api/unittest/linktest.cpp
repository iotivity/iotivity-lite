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

#include "api/oc_link_internal.h"
#include "oc_ri.h"
#include "port/oc_random.h"

#include "gtest/gtest.h"
#include <string>
#include <vector>

class TestLinkParam : public testing::Test {};

TEST_F(TestLinkParam, AllocateAndDeallocate)
{
  std::string key{ "key" };
  std::string value{ "value" };
  oc_link_params_t *params =
    oc_link_param_allocate(oc_string_view(key.c_str(), key.length()),
                           oc_string_view(value.c_str(), value.length()));
  ASSERT_NE(params, nullptr);
  oc_link_param_free(params);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestLinkParam, Allocate_Fail)
{
  std::string key{ "key" };
  std::string value{ "value" };
  std::vector<oc_link_params_t *> params_list{};
  for (int i = 0; i < OC_LINK_PARAM_COUNT_MAX; ++i) {
    oc_link_params_t *params =
      oc_link_param_allocate(oc_string_view(key.c_str(), key.length()),
                             oc_string_view(value.c_str(), value.length()));
    ASSERT_NE(params, nullptr);
    params_list.push_back(params);
  }

  oc_link_params_t *params =
    oc_link_param_allocate(oc_string_view(key.c_str(), key.length()),
                           oc_string_view(value.c_str(), value.length()));
  EXPECT_EQ(params, nullptr);

  for (auto &params : params_list) {
    oc_link_param_free(params);
  }
}

#endif // !OC_DYNAMIC_ALLOCATION

class TestLink : public testing::Test {
public:
  static void SetUpTestCase() { oc_random_init(); }
  static void TearDownTestCase() { oc_random_destroy(); }
};

TEST_F(TestLink, AllocateAndDeallocate)
{
  oc_resource_t resource{};
  resource.interfaces =
    static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R);

  oc_link_t *link = oc_new_link(&resource);
  ASSERT_NE(link, nullptr);
  EXPECT_EQ(link->resource, &resource);
  EXPECT_EQ(link->interfaces, OC_IF_BASELINE | OC_IF_R);
#ifdef OC_COLLECTIONS
  EXPECT_EQ(resource.num_links, 1);
#endif /* OC_COLLECTIONS */

  oc_delete_link(link);
}

TEST_F(TestLink, DeallocateNull)
{
  oc_delete_link(nullptr);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestLink, Allocate_Fail)
{
  oc_resource_t resource{};

  std::vector<oc_link_t *> links{};
  for (int i = 0; i < OC_MAX_APP_RESOURCES; ++i) {
    oc_link_t *link = oc_new_link(&resource);
    ASSERT_NE(link, nullptr);
    links.push_back(link);
  }
#ifdef OC_COLLECTIONS
  EXPECT_EQ(resource.num_links, OC_MAX_APP_RESOURCES);
#endif /* OC_COLLECTIONS */

  oc_link_t *link = oc_new_link(&resource);
  EXPECT_EQ(link, nullptr);

  for (auto &link : links) {
    oc_delete_link(link);
  }
}

#endif // !OC_DYNAMIC_ALLOCATION

static size_t
countNonEmptyRels(const oc_link_t *link)
{
  size_t count = 0;
  for (size_t i = 0; i < oc_string_array_get_allocated_size(link->rel); ++i) {
    if (oc_string_array_get_item_size(link->rel, i) > 0) {
      ++count;
    }
  }
  return count;
}

struct LinkParam
{
  std::string key;
  std::string value;
};

static std::vector<LinkParam>
getLinkParams(const oc_link_t *link)
{
  std::vector<LinkParam> params{};
  for (const oc_link_params_t *lp =
         static_cast<oc_link_params_t *>(oc_list_head(link->params));
       lp != nullptr; lp = lp->next) {
    LinkParam param{};
    param.key = std::string(oc_string(lp->key));
    param.value = std::string(oc_string(lp->value));
    params.push_back(param);
  }
  return params;
}

TEST_F(TestLink, AddRels)
{
  oc_resource_t resource{};
  oc_link_t *link = oc_new_link(&resource);
  ASSERT_NE(nullptr, link);
  ASSERT_EQ(1, countNonEmptyRels(link));

  for (size_t i = 1; i < OC_LINK_RELATIONS_ARRAY_SIZE; ++i) {
    EXPECT_TRUE(oc_link_add_rel(link, ("rel" + std::to_string(i + 1)).c_str()));
    EXPECT_EQ(i + 1, countNonEmptyRels(link));
  }
  EXPECT_FALSE(oc_link_add_rel(link, "relFail"));
  EXPECT_EQ(OC_LINK_RELATIONS_ARRAY_SIZE, countNonEmptyRels(link));

  oc_link_clear_rels(link);
  EXPECT_EQ(0, countNonEmptyRels(link));

  oc_delete_link(link);
}

TEST_F(TestLink, AddLinkParams)
{
  oc_resource_t resource{};
  oc_link_t *link = oc_new_link(&resource);
  ASSERT_NE(nullptr, link);
  ASSERT_EQ(0, oc_list_length(link->params));

  LinkParam lp{ "key", "value" };
  EXPECT_TRUE(oc_link_add_link_param(link, lp.key.c_str(), lp.value.c_str()));
  auto params = getLinkParams(link);
  ASSERT_EQ(1, params.size());
  EXPECT_STREQ(lp.key.c_str(), params[0].key.c_str());
  EXPECT_STREQ(lp.value.c_str(), params[0].value.c_str());

  oc_link_clear_link_params(link);
  EXPECT_EQ(0, oc_list_length(link->params));

  EXPECT_TRUE(oc_link_add_link_param(link, lp.key.c_str(), lp.value.c_str()));
#ifdef OC_DYNAMIC_ALLOCATION
  for (size_t i = 0; i < 3; ++i) {
    lp.key = "key" + std::to_string(i + 1);
    lp.value = "value" + std::to_string(i + 1);
    EXPECT_TRUE(oc_link_add_link_param(link, lp.key.c_str(), lp.value.c_str()));
  }
  EXPECT_EQ(4, oc_list_length(link->params));
#endif // OC_DYNAMIC_ALLOCATION

  // delete link should deallocate all link params
  oc_delete_link(link);
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestLink, AddLinkParamsFail)
{
  oc_resource_t resource{};
  oc_link_t *link = oc_new_link(&resource);
  ASSERT_NE(nullptr, link);
  ASSERT_EQ(0, oc_list_length(link->params));

  LinkParam exp{};
  for (int i = 0; i < OC_LINK_PARAM_COUNT_MAX; ++i) {
    exp.key = "key" + std::to_string(i);
    exp.value = "value" + std::to_string(i);
    EXPECT_TRUE(
      oc_link_add_link_param(link, exp.key.c_str(), exp.value.c_str()));
  }

  EXPECT_FALSE(
    oc_link_add_link_param(link, exp.key.c_str(), exp.value.c_str()));
  oc_delete_link(link);
}

#endif // !OC_DYNAMIC_ALLOCATION

TEST_F(TestLink, SetInterfaces)
{
  oc_resource_t resource{};
  resource.interfaces =
    static_cast<oc_interface_mask_t>(OC_IF_BASELINE | OC_IF_R);

  oc_link_t *link = oc_new_link(&resource);
  ASSERT_NE(link, nullptr);
  EXPECT_EQ(link->interfaces, resource.interfaces);

  oc_link_set_interfaces(link, OC_IF_RW);
  EXPECT_EQ(link->interfaces, OC_IF_RW);

  oc_delete_link(link);
}

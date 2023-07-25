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

#include "util/oc_list.h"

#include <gtest/gtest.h>
#include <string>
#include <vector>

struct TestListItem
{
  struct TestListItem *next;
  std::string name;
};

class TestList : public testing::Test {
public:
  static TestListItem *makeListItem(std::string_view name)
  {
    auto *item = new TestListItem();
    item->name = name;
    return item;
  }

  template<typename... Ts>
  static void addToList(oc_list_t list, Ts... args)
  {
    (oc_list_add(list, makeListItem(args)), ...);
  }

  template<typename... Ts>
  static void pushToList(oc_list_t list, Ts... args)
  {
    (oc_list_push(list, makeListItem(args)), ...);
  }

  static void clearList(oc_list_t list)
  {
    TestListItem *item = nullptr;
    while ((item = static_cast<TestListItem *>(oc_list_pop(list)))) {
      delete item;
    }
  }
};

TEST_F(TestList, Head)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  EXPECT_EQ(nullptr, oc_list_head(list));

  addToList(list, "a", "b", "c");
  const auto *item = static_cast<TestListItem *>(oc_list_head(list));
  EXPECT_STREQ("a", item->name.c_str());

  clearList(list);
}

TEST_F(TestList, Tail)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  EXPECT_EQ(nullptr, oc_list_tail(list));

  addToList(list, "a", "b", "c");
  const auto *item = static_cast<TestListItem *>(oc_list_tail(list));
  EXPECT_STREQ("c", item->name.c_str());

  clearList(list);
}

TEST_F(TestList, Length)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  EXPECT_EQ(0, oc_list_length(list));

  addToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));

  clearList(list);
}

TEST_F(TestList, Add)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  addToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));
  auto *item1 = static_cast<TestListItem *>(oc_list_head(list));
  EXPECT_STREQ("a", item1->name.c_str());
  auto *item2 = static_cast<TestListItem *>(oc_list_item_next(item1));
  EXPECT_STREQ("b", item2->name.c_str());
  auto *item3 = static_cast<TestListItem *>(oc_list_item_next(item2));
  EXPECT_STREQ("c", item3->name.c_str());
  auto *item4 = oc_list_item_next(item3);
  EXPECT_EQ(nullptr, item4);

  clearList(list);
}

TEST_F(TestList, Push)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  pushToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));
  auto *item1 = static_cast<TestListItem *>(oc_list_head(list));
  EXPECT_STREQ("c", item1->name.c_str());
  auto *item2 = static_cast<TestListItem *>(oc_list_item_next(item1));
  EXPECT_STREQ("b", item2->name.c_str());
  auto *item3 = static_cast<TestListItem *>(oc_list_item_next(item2));
  EXPECT_STREQ("a", item3->name.c_str());
  auto *item4 = oc_list_item_next(item3);
  EXPECT_EQ(nullptr, item4);

  clearList(list);
}

TEST_F(TestList, Insert)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  auto *item1 = TestList::makeListItem("a");
  oc_list_insert(list, nullptr, item1);
  EXPECT_EQ(1, oc_list_length(list));

  auto *item2 = TestList::makeListItem("b");
  oc_list_insert(list, item1, item2);
  EXPECT_EQ(2, oc_list_length(list));
  EXPECT_EQ(item1, oc_list_head(list));
  EXPECT_EQ(item2, oc_list_tail(list));

  auto *item3 = TestList::makeListItem("c");
  oc_list_insert(list, item1, item3);
  EXPECT_EQ(3, oc_list_length(list));
  EXPECT_EQ(item1, oc_list_head(list));
  EXPECT_EQ(item3, oc_list_item_next(item1));
  EXPECT_EQ(item2, oc_list_item_next(item3));

  clearList(list);
}

TEST_F(TestList, Chop)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  addToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));
  auto *item1 = static_cast<TestListItem *>(oc_list_chop(list));
  EXPECT_STREQ("c", item1->name.c_str());
  delete item1;
  EXPECT_EQ(2, oc_list_length(list));
  auto *item2 = static_cast<TestListItem *>(oc_list_chop(list));
  EXPECT_STREQ("b", item2->name.c_str());
  EXPECT_EQ(1, oc_list_length(list));
  delete item2;
  auto *item3 = static_cast<TestListItem *>(oc_list_chop(list));
  EXPECT_STREQ("a", item3->name.c_str());
  delete item3;
  EXPECT_EQ(0, oc_list_length(list));
  auto *item4 = static_cast<TestListItem *>(oc_list_chop(list));
  EXPECT_EQ(nullptr, item4);

  clearList(list);
}

TEST_F(TestList, Pop)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  addToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));
  auto *item1 = static_cast<TestListItem *>(oc_list_pop(list));
  EXPECT_STREQ("a", item1->name.c_str());
  delete item1;
  EXPECT_EQ(2, oc_list_length(list));
  auto *item2 = static_cast<TestListItem *>(oc_list_pop(list));
  EXPECT_STREQ("b", item2->name.c_str());
  EXPECT_EQ(1, oc_list_length(list));
  delete item2;
  auto *item3 = static_cast<TestListItem *>(oc_list_pop(list));
  EXPECT_STREQ("c", item3->name.c_str());
  delete item3;
  EXPECT_EQ(0, oc_list_length(list));
  auto *item4 = static_cast<TestListItem *>(oc_list_pop(list));
  EXPECT_EQ(nullptr, item4);

  clearList(list);
}

TEST_F(TestList, Remove)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  addToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));
  auto *item1 = static_cast<TestListItem *>(oc_list_head(list));
  auto *item2 = static_cast<TestListItem *>(oc_list_item_next(item1));
  auto *item3 = static_cast<TestListItem *>(oc_list_item_next(item2));

  TestListItem item4{};
  oc_list_remove(list, &item4);
  EXPECT_EQ(3, oc_list_length(list));

  oc_list_remove(list, item2);
  delete item2;
  EXPECT_EQ(2, oc_list_length(list));
  EXPECT_EQ(item1, oc_list_head(list));
  EXPECT_EQ(item3, oc_list_item_next(item1));
  EXPECT_EQ(item3, oc_list_tail(list));
  EXPECT_EQ(nullptr, oc_list_item_next(item3));

  oc_list_remove(list, item1);
  delete item1;
  EXPECT_EQ(1, oc_list_length(list));
  EXPECT_EQ(item3, oc_list_head(list));
  EXPECT_EQ(item3, oc_list_tail(list));

  clearList(list);
}

TEST_F(TestList, Remove2)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  addToList(list, "a", "b", "c");
  EXPECT_EQ(3, oc_list_length(list));
  auto *item1 = static_cast<TestListItem *>(oc_list_head(list));
  auto *item2 = static_cast<TestListItem *>(oc_list_item_next(item1));
  auto *item3 = static_cast<TestListItem *>(oc_list_item_next(item2));

  delete static_cast<TestListItem *>(oc_list_remove2(list, item2));
  EXPECT_EQ(2, oc_list_length(list));
  EXPECT_EQ(item1, oc_list_head(list));
  EXPECT_EQ(item3, oc_list_item_next(item1));
  EXPECT_EQ(item3, oc_list_tail(list));
  EXPECT_EQ(nullptr, oc_list_item_next(item3));

  delete static_cast<TestListItem *>(oc_list_remove2(list, item1));
  EXPECT_EQ(1, oc_list_length(list));
  EXPECT_EQ(item3, oc_list_head(list));
  EXPECT_EQ(item3, oc_list_tail(list));

  clearList(list);
}

TEST_F(TestList, HasItem)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  auto *item1 = TestList::makeListItem("a");
  EXPECT_FALSE(oc_list_has_item(list, item1));

  oc_list_add(list, item1);
  EXPECT_TRUE(oc_list_has_item(list, item1));

  clearList(list);
}

TEST_F(TestList, Copy)
{
  OC_LIST_LOCAL(list);
  oc_list_init(list);

  addToList(list, "a", "b", "c", "d");
  EXPECT_EQ(4, oc_list_length(list));

  OC_LIST_LOCAL(list2);
  oc_list_copy(list2, list);
  EXPECT_EQ(4, oc_list_length(list2));

  auto *item4 = static_cast<TestListItem *>(oc_list_chop(list));
  EXPECT_FALSE(oc_list_has_item(list, item4));
  EXPECT_FALSE(oc_list_has_item(list2, item4));
  delete item4;

  // since "copy" merely copies the head, poping the head should affect both
  // lists and after the operation the second list should contain only the
  // popped item
  const auto *item1 = static_cast<TestListItem *>(oc_list_pop(list));
  EXPECT_FALSE(oc_list_has_item(list, item1));
  EXPECT_EQ(2, oc_list_length(list));
  EXPECT_TRUE(oc_list_has_item(list2, item1));
  EXPECT_EQ(1, oc_list_length(list2));

  clearList(list2);
  clearList(list);
}

TEST_F(TestList, Next)
{
  EXPECT_EQ(nullptr, oc_list_item_next(nullptr));
}

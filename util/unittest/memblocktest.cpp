/****************************************************************************
 *
 * Copyright (c) 2024 plgd.dev s.r.o.
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

#include "util/oc_memb.h"

#include "gtest/gtest.h"

#include <array>

struct test_data_t
{
  int a;
  int b;
};

class TestMemoryBlock : public testing::Test {};

TEST_F(TestMemoryBlock, Init)
{
  OC_MEMB_LOCAL(oc_test_data, test_data_t, 13);
  EXPECT_EQ(oc_test_data.size, sizeof(test_data_t));
  oc_memb_init(&oc_test_data);
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(oc_test_data.num, 0);
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_EQ(oc_test_data.num, 13);
#endif /* OC_DYNAMIC_ALLOCATION */
}

TEST_F(TestMemoryBlock, Alloc_Fail)
{
  EXPECT_EQ(nullptr, oc_memb_alloc(nullptr));
}

TEST_F(TestMemoryBlock, Alloc)
{
  OC_MEMB_LOCAL(oc_test_data, test_data_t, 13);
  oc_memb_init(&oc_test_data);
  auto *block1 = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data));
  EXPECT_NE(nullptr, block1);
  auto *block2 = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data));
  EXPECT_NE(nullptr, block2);
  EXPECT_NE(block1, block2);
  // Add more assertions as necessary to test initialization of allocated blocks
  EXPECT_FALSE(oc_memb_free(&oc_test_data, block2));
  EXPECT_FALSE(oc_memb_free(&oc_test_data, block1));
}

TEST_F(TestMemoryBlock, Dealloc_Fail)
{
  EXPECT_EQ(-1, oc_memb_free(nullptr, nullptr));
}

TEST_F(TestMemoryBlock, AllocExceedsLimit)
{
  OC_MEMB_LOCAL(oc_test_data, test_data_t, 13);
  oc_memb_init(&oc_test_data);
  std::array<test_data_t *, 14> blocks;
  for (int i = 0; i < 13; ++i) {
    blocks[i] = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data));
    EXPECT_NE(nullptr, blocks[i]);
  }
  blocks[13] = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data));
#ifdef OC_DYNAMIC_ALLOCATION
  EXPECT_NE(nullptr, blocks[13]); // Expecting the allocation to succeed
  oc_memb_free(&oc_test_data, blocks[13]);
#else  /* !OC_DYNAMIC_ALLOCATION */
  EXPECT_EQ(nullptr,
            blocks[13]); // Expecting the allocation to fail beyond the limit
#endif /* OC_DYNAMIC_ALLOCATION */
  for (int i = 0; i < 13; ++i) {
    oc_memb_free(&oc_test_data, blocks[i]);
  }
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestMemoryBlock, Realloc)
{
  OC_MEMB_LOCAL(oc_test_data, test_data_t, 13);
  oc_memb_init(&oc_test_data);
  auto *block = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data));
  EXPECT_NE(block, nullptr);
  oc_memb_free(&oc_test_data, block);
  auto *block_realloc =
    static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data));
  EXPECT_EQ(block, block_realloc);
  oc_memb_free(&oc_test_data, block_realloc);
}

TEST_F(TestMemoryBlock, InBlock)
{
  OC_MEMB_LOCAL(oc_test_data1, test_data_t, 13);
  oc_memb_init(&oc_test_data1);
  OC_MEMB_LOCAL(oc_test_data2, test_data_t, 37);
  oc_memb_init(&oc_test_data2);
  auto td1 = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data1));
  EXPECT_TRUE(oc_memb_inmemb(&oc_test_data1, td1));
  EXPECT_FALSE(oc_memb_inmemb(&oc_test_data2, td1));
  auto td2 = static_cast<test_data_t *>(oc_memb_alloc(&oc_test_data2));
  EXPECT_TRUE(oc_memb_inmemb(&oc_test_data2, td2));
  EXPECT_FALSE(oc_memb_inmemb(&oc_test_data1, td2));

  oc_memb_free(&oc_test_data2, td2);
  oc_memb_free(&oc_test_data1, td1);
}

#endif /* !OC_DYNAMIC_ALLOCATION */

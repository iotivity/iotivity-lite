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

#include <util/oc_mmem_internal.h>

#include <cstdint>
#include <gtest/gtest.h>

class TestMemoryPool : public testing::Test {
public:
  static void SetUpTestCase() { oc_mmem_init(); }
};

TEST_F(TestMemoryPool, AllocAndDeallocByte)
{
  oc_mmem byte{};
  size_t size = oc_mmem_alloc(&byte, 1, BYTE_POOL);
  EXPECT_EQ(size, 1);
  EXPECT_NE(byte.ptr, nullptr);
  EXPECT_EQ(byte.size, 1);

  oc_mmem_free(&byte, BYTE_POOL);
}

TEST_F(TestMemoryPool, AllocByte_F)
{
  oc_mmem_alloc(nullptr, 1, BYTE_POOL);
}

TEST_F(TestMemoryPool, DeallocByte_F)
{
  oc_mmem_free(nullptr, BYTE_POOL);
}

TEST_F(TestMemoryPool, AllocAndDeallocInt)
{
  oc_mmem integer{};
  size_t size = oc_mmem_alloc(&integer, 2, INT_POOL);
  ASSERT_EQ(size, 2 * sizeof(int64_t));
  EXPECT_NE(integer.ptr, nullptr);
  EXPECT_EQ(integer.size, 2);

  oc_mmem_free(&integer, INT_POOL);
}

TEST_F(TestMemoryPool, AllocInt_F)
{
  oc_mmem_alloc(nullptr, 1, INT_POOL);
}

TEST_F(TestMemoryPool, DeallocInt_F)
{
  oc_mmem_free(nullptr, INT_POOL);
}

TEST_F(TestMemoryPool, AllocAndDeallocDouble)
{
  oc_mmem dbl{};
  size_t size = oc_mmem_alloc(&dbl, 3, DOUBLE_POOL);
  ASSERT_EQ(size, 3 * sizeof(double));
  EXPECT_NE(dbl.ptr, nullptr);
  EXPECT_EQ(dbl.size, 3);

  oc_mmem_free(&dbl, DOUBLE_POOL);
}

TEST_F(TestMemoryPool, AllocDouble_F)
{
  oc_mmem_alloc(nullptr, 1, DOUBLE_POOL);
}

TEST_F(TestMemoryPool, DeallocDouble_F)
{
  oc_mmem_free(nullptr, DOUBLE_POOL);
}

TEST_F(TestMemoryPool, AllocateMultipleBytes)
{
#ifndef OC_DYNAMIC_ALLOCATION
  size_t bytePoolSize = oc_mmem_available_size(BYTE_POOL);
#endif // OC_DYNAMIC_ALLOCATION

  oc_mmem byte1{};
  size_t size = oc_mmem_alloc(&byte1, 1, BYTE_POOL);
  ASSERT_EQ(size, 1);
  ASSERT_NE(byte1.ptr, nullptr);
  ASSERT_EQ(byte1.size, 1);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(bytePoolSize - 1, oc_mmem_available_size(BYTE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  uint8_t byte1Value = 0x42;
  memcpy(byte1.ptr, &byte1Value, 1);

  oc_mmem byte2{};
  size = oc_mmem_alloc(&byte2, 1, BYTE_POOL);
  ASSERT_EQ(size, 1);
  ASSERT_NE(byte2.ptr, nullptr);
  ASSERT_EQ(byte2.size, 1);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(bytePoolSize - 2, oc_mmem_available_size(BYTE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  uint8_t byte2Value = 0x43;
  memcpy(byte2.ptr, &byte2Value, 1);

  uint8_t exp = 0;
  memcpy(&exp, byte1.ptr, 1);
  EXPECT_EQ(exp, byte1Value);
  memcpy(&exp, byte2.ptr, 1);
  EXPECT_EQ(exp, byte2Value);

  oc_mmem_free(&byte1, BYTE_POOL);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(bytePoolSize - 1, oc_mmem_available_size(BYTE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  memcpy(&exp, byte2.ptr, 1);
  EXPECT_EQ(exp, byte2Value);

  oc_mmem_free(&byte2, BYTE_POOL);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(bytePoolSize, oc_mmem_available_size(BYTE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
}

TEST_F(TestMemoryPool, AllocateMultipleInts)
{
#ifndef OC_DYNAMIC_ALLOCATION
  size_t intPoolSize = oc_mmem_available_size(INT_POOL);
#endif // OC_DYNAMIC_ALLOCATION

  oc_mmem int1{};
  size_t size = oc_mmem_alloc(&int1, 1, INT_POOL);
  ASSERT_EQ(size, sizeof(int64_t));
  ASSERT_NE(int1.ptr, nullptr);
  ASSERT_EQ(int1.size, 1);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(intPoolSize - 1, oc_mmem_available_size(INT_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  int64_t int1Value = 1337;
  memcpy(int1.ptr, &int1Value, sizeof(int64_t));

  oc_mmem int2{};
  size = oc_mmem_alloc(&int2, 1, INT_POOL);
  ASSERT_EQ(size, sizeof(int64_t));
  ASSERT_NE(int2.ptr, nullptr);
  ASSERT_EQ(int2.size, 1);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(intPoolSize - 2, oc_mmem_available_size(INT_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  int64_t int2Value = 1338;
  memcpy(int2.ptr, &int2Value, sizeof(int64_t));

  int64_t exp = 0;
  memcpy(&exp, int1.ptr, sizeof(int64_t));
  EXPECT_EQ(exp, int1Value);
  memcpy(&exp, int2.ptr, sizeof(int64_t));
  EXPECT_EQ(exp, int2Value);

  oc_mmem_free(&int1, INT_POOL);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(intPoolSize - 1, oc_mmem_available_size(INT_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  memcpy(&exp, int2.ptr, sizeof(int64_t));
  EXPECT_EQ(exp, int2Value);

  oc_mmem_free(&int2, INT_POOL);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(intPoolSize, oc_mmem_available_size(INT_POOL));
#endif // OC_DYNAMIC_ALLOCATION
}

TEST_F(TestMemoryPool, AllocateMultipleDoubles)
{
#ifndef OC_DYNAMIC_ALLOCATION
  size_t doublePoolSize = oc_mmem_available_size(DOUBLE_POOL);
#endif // OC_DYNAMIC_ALLOCATION

  oc_mmem dbl1{};
  size_t size = oc_mmem_alloc(&dbl1, 1, DOUBLE_POOL);
  ASSERT_EQ(size, sizeof(double));
  ASSERT_NE(dbl1.ptr, nullptr);
  ASSERT_EQ(dbl1.size, 1);

#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(doublePoolSize - 1, oc_mmem_available_size(DOUBLE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  double dbl1Value = 3.1415;
  memcpy(dbl1.ptr, &dbl1Value, sizeof(double));

  oc_mmem dbl2{};
  size = oc_mmem_alloc(&dbl2, 1, DOUBLE_POOL);
  ASSERT_EQ(size, sizeof(double));
  ASSERT_NE(dbl2.ptr, nullptr);
  ASSERT_EQ(dbl2.size, 1);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(doublePoolSize - 2, oc_mmem_available_size(DOUBLE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  double dbl2Value = 2.71828;
  memcpy(dbl2.ptr, &dbl2Value, sizeof(double));

  double exp = 0;
  memcpy(&exp, dbl1.ptr, sizeof(double));
  EXPECT_EQ(exp, dbl1Value);
  memcpy(&exp, dbl2.ptr, sizeof(double));
  EXPECT_EQ(exp, dbl2Value);

  oc_mmem_free(&dbl1, DOUBLE_POOL);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(doublePoolSize - 1, oc_mmem_available_size(DOUBLE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
  memcpy(&exp, dbl2.ptr, sizeof(double));
  EXPECT_EQ(exp, dbl2Value);

  oc_mmem_free(&dbl2, DOUBLE_POOL);
#ifndef OC_DYNAMIC_ALLOCATION
  EXPECT_EQ(doublePoolSize, oc_mmem_available_size(DOUBLE_POOL));
#endif // OC_DYNAMIC_ALLOCATION
}

#ifndef OC_DYNAMIC_ALLOCATION

TEST_F(TestMemoryPool, ExhaustBytePool)
{
  size_t bytePoolSize = oc_mmem_available_size(BYTE_POOL);
  oc_mmem bytes{};
  size_t size = oc_mmem_alloc(&bytes, bytePoolSize, BYTE_POOL);
  ASSERT_EQ(size, bytePoolSize * sizeof(uint8_t));
  ASSERT_NE(bytes.ptr, nullptr);
  ASSERT_EQ(bytes.size, bytePoolSize);
  ASSERT_EQ(0, oc_mmem_available_size(BYTE_POOL));

  oc_mmem fail{};
  EXPECT_EQ(0, oc_mmem_alloc(&fail, 1, BYTE_POOL));

  oc_mmem_free(&bytes, BYTE_POOL);
  ASSERT_EQ(bytePoolSize, oc_mmem_available_size(BYTE_POOL));
}

TEST_F(TestMemoryPool, ExhaustIntPool)
{
  size_t intPoolSize = oc_mmem_available_size(INT_POOL);
  oc_mmem ints{};
  size_t size = oc_mmem_alloc(&ints, intPoolSize, INT_POOL);
  ASSERT_EQ(size, intPoolSize * sizeof(int64_t));
  ASSERT_NE(ints.ptr, nullptr);
  ASSERT_EQ(ints.size, intPoolSize);
  ASSERT_EQ(0, oc_mmem_available_size(INT_POOL));

  oc_mmem fail{};
  EXPECT_EQ(0, oc_mmem_alloc(&fail, 1, INT_POOL));

  oc_mmem_free(&ints, INT_POOL);
  ASSERT_EQ(intPoolSize, oc_mmem_available_size(INT_POOL));
}

TEST_F(TestMemoryPool, ExhaustDoublePool)
{
  size_t doublePoolSize = oc_mmem_available_size(DOUBLE_POOL);
  oc_mmem doubles{};
  size_t size = oc_mmem_alloc(&doubles, doublePoolSize, DOUBLE_POOL);
  ASSERT_EQ(size, doublePoolSize * sizeof(double));
  ASSERT_NE(doubles.ptr, nullptr);
  ASSERT_EQ(doubles.size, doublePoolSize);
  ASSERT_EQ(0, oc_mmem_available_size(DOUBLE_POOL));

  oc_mmem fail{};
  EXPECT_EQ(0, oc_mmem_alloc(&fail, 1, DOUBLE_POOL));

  oc_mmem_free(&doubles, DOUBLE_POOL);
  ASSERT_EQ(doublePoolSize, oc_mmem_available_size(DOUBLE_POOL));
}

#endif // OC_DYNAMIC_ALLOCATION

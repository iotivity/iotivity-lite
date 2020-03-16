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
#include <string>
#include <gtest/gtest.h>

extern "C" {
#include "port/oc_storage.h"
}

#ifdef OC_SECURITY
static const char *path = "./storage_test";
static const char *file_name = "storage_store";
static uint8_t buf[100];
#endif /* OC_SECURITY */

class TestStorage : public testing::Test {
protected:
  virtual void SetUp() {}

  virtual void TearDown() {}
};

#ifdef OC_SECURITY
TEST_F(TestStorage, oc_storage_config_fail_with_length_over)
{
  int ret = oc_storage_config("./"
                              "storage_test_long_size_fail_storage_test_long_"
                              "size_fail_storage_test_long_size_fail");
  EXPECT_NE(0, ret);
}

TEST_F(TestStorage, oc_storage_read_fail)
{
  int ret = oc_storage_read(file_name, buf, 100);
  EXPECT_NE(0, ret);
}

TEST_F(TestStorage, oc_storage_write_fail)
{
  int ret = oc_storage_write(file_name, buf, 100);
  EXPECT_NE(0, ret);
}

TEST_F(TestStorage, oc_storage_config)
{
  int ret = oc_storage_config(path);
  EXPECT_EQ(0, ret);
}

TEST_F(TestStorage, oc_storage_write)
{
  uint8_t str[100] = "storage";
  int ret = oc_storage_write(file_name, str, strlen((char *)str));
  EXPECT_LE(0, ret);
  ret = oc_storage_read(file_name, buf, 100);
  EXPECT_LE(0, ret);
  EXPECT_STREQ((const char *)str, (const char *)buf);
}
#endif /* OC_SECURITY */

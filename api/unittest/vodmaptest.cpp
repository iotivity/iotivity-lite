/******************************************************************
 *
 * Copyright 2020 Intel Corporation
 * Copyright 2023 ETRI Joo-Chul Kevin Lee
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_BRIDGE

#include <gtest/gtest.h>
#include <sys/stat.h>
#define OC_STORAGE

#include "oc_api.h"
#include "oc_bridge.h"
#include <oc_vod_map.h>
#include "port/oc_storage.h"

#include <string>
#include <vector>

using test_vod = struct test_vod
{
  std::string vod_id;
  std::string eco_system;
};

class VodMapTest : public testing::Test {
public:
  int dirExists(const char *const path);
  std::vector<test_vod> tv = {
    { "1b32e152-3756-4fb6-b3f2-d8db7aafe39f", "ABC" },
    { "f959f6fd-8d08-4766-849b-74c3eec5e041", "ABC" },
    { "02feb15a-bf94-4f33-9794-adfb25c7bc60", "XYZ" },
    { "686ef93d-36e0-47fc-8316-fbd7045e850a", "ABC" },
    { "686ef93d-36e0-47fc-8316-fbd7045e850a", "XYZ" }
  };

protected:
  void SetUp() override
  {
#ifdef OC_STORAGE
#if defined(_WIN32_)
    mkdir("vod_map_test_dir");
#elif defined(__linux__)
    mkdir("vod_map_test_dir",
          S_IRWXU | S_IRWXG | S_IRWXG /* 0777 permissions*/);
#endif /* if defined(_WIN32_) */
    oc_storage_config("./vod_map_test_dir/");
#endif /* OC_STORAGE */
  }
  void TearDown() override
  {
    remove("./vod_map_test_dir/vod_map");
    remove("./vod_map_test_dir/");
  }
};

TEST_F(VodMapTest, vod_map_add_id)
{
  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  const char *dummy = "dummy";
  EXPECT_EQ(
    oc_vod_map_add_mapping_entry((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[0].vod_id.c_str(),
                                         strlen(tv[0].vod_id.c_str()),
                                         tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            2);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);

  oc_vod_map_free();
}

TEST_F(VodMapTest, vod_map_remove_id)
{
  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  const char *dummy = "dummy";
  EXPECT_EQ(
    oc_vod_map_add_mapping_entry((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[0].vod_id.c_str(),
                                         strlen(tv[0].vod_id.c_str()),
                                         tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            2);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);

  oc_vod_map_remove_mapping_entry(1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);

  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[0].vod_id.c_str(),
                                         strlen(tv[0].vod_id.c_str()),
                                         tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[2].vod_id.c_str(),
                                         strlen(tv[2].vod_id.c_str()),
                                         tv[2].eco_system.c_str()),
            3);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            3);

  oc_vod_map_reset();

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);

  oc_vod_map_free();

  // test intermittent removal of vod_id.c_strs

  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  EXPECT_EQ(
    oc_vod_map_add_mapping_entry((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[0].vod_id.c_str(),
                                         strlen(tv[0].vod_id.c_str()),
                                         tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[2].vod_id.c_str(),
                                         strlen(tv[2].vod_id.c_str()),
                                         tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[3].vod_id.c_str(),
                                         strlen(tv[3].vod_id.c_str()),
                                         tv[3].eco_system.c_str()),
            4);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[4].vod_id.c_str(),
                                         strlen(tv[4].vod_id.c_str()),
                                         tv[4].eco_system.c_str()),
            5);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            4);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            5);

  oc_vod_map_remove_mapping_entry(2);
  oc_vod_map_remove_mapping_entry(4);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            5);

  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[3].vod_id.c_str(),
                                         strlen(tv[3].vod_id.c_str()),
                                         tv[3].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            4);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            4);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            5);

  oc_vod_map_reset();
  oc_vod_map_free();

  // test consecutive removal of vod_id.c_strs

  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  EXPECT_EQ(
    oc_vod_map_add_mapping_entry((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[0].vod_id.c_str(),
                                         strlen(tv[0].vod_id.c_str()),
                                         tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[2].vod_id.c_str(),
                                         strlen(tv[2].vod_id.c_str()),
                                         tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[3].vod_id.c_str(),
                                         strlen(tv[3].vod_id.c_str()),
                                         tv[3].eco_system.c_str()),
            4);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[4].vod_id.c_str(),
                                         strlen(tv[4].vod_id.c_str()),
                                         tv[4].eco_system.c_str()),
            5);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            4);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            5);

  oc_vod_map_remove_mapping_entry(2);
  oc_vod_map_remove_mapping_entry(4);
  oc_vod_map_remove_mapping_entry(3);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            5);

  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[3].vod_id.c_str(),
                                         strlen(tv[3].vod_id.c_str()),
                                         tv[3].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[2].vod_id.c_str(),
                                         strlen(tv[2].vod_id.c_str()),
                                         tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_add_mapping_entry((uint8_t *)tv[1].vod_id.c_str(),
                                         strlen(tv[1].vod_id.c_str()),
                                         tv[1].eco_system.c_str()),
            4);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[0].vod_id.c_str(),
                                     strlen(tv[0].vod_id.c_str()),
                                     tv[0].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[1].vod_id.c_str(),
                                     strlen(tv[1].vod_id.c_str()),
                                     tv[1].eco_system.c_str()),
            4);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[2].vod_id.c_str(),
                                     strlen(tv[2].vod_id.c_str()),
                                     tv[2].eco_system.c_str()),
            3);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            2);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            5);

  oc_vod_map_free();
}

TEST_F(VodMapTest, vod_map_add_same_id_different_econame)
{
  oc_vod_map_init();
  // verify the vod_id.c_str() are not yet added
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            0);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  const char *dummy = "dummy";
  EXPECT_EQ(
    oc_vod_map_add_mapping_entry((uint8_t *)dummy, strlen(dummy), dummy), 0);

  // even though tv[3] and tv[4] have the same vod_id.c_str() they have
  // different econames and should each get a different index
  size_t vod_index3 = oc_vod_map_add_mapping_entry(
    (uint8_t *)tv[3].vod_id.c_str(), strlen(tv[3].vod_id.c_str()),
    tv[3].eco_system.c_str());
  size_t vod_index4 = oc_vod_map_add_mapping_entry(
    (uint8_t *)tv[4].vod_id.c_str(), strlen(tv[4].vod_id.c_str()),
    tv[4].eco_system.c_str());
  EXPECT_NE(vod_index3, vod_index4);

  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[3].vod_id.c_str(),
                                     strlen(tv[3].vod_id.c_str()),
                                     tv[3].eco_system.c_str()),
            1);
  EXPECT_EQ(oc_vod_map_get_vod_index((uint8_t *)tv[4].vod_id.c_str(),
                                     strlen(tv[4].vod_id.c_str()),
                                     tv[4].eco_system.c_str()),
            2);

  oc_vod_map_free();
}

#endif /* OC_HAS_FEATURE_BRIDGE */

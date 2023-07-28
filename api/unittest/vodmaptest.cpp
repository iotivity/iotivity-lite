/******************************************************************
 *
 * Copyright 2020 Intel Corporation
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
#include <gtest/gtest.h>
#include <sys/stat.h>
#define OC_STORAGE

#include "oc_api.h"
#include "oc_bridge.h"
#include "api/oc_vod_map.h"
#include "port/oc_storage.h"

typedef struct test_vod {
  char vod_id[37];
  char eco_system[5];
}test_vod;

class VodMapTest: public testing::Test
{
public:
  int dirExists(const char* const path);
  test_vod tv[5] = {
      {"1b32e152-3756-4fb6-b3f2-d8db7aafe39f", "ABC"},
      {"f959f6fd-8d08-4766-849b-74c3eec5e041", "ABC"},
      {"02feb15a-bf94-4f33-9794-adfb25c7bc60", "XYZ"},
      {"686ef93d-36e0-47fc-8316-fbd7045e850a", "ABC"},
      {"686ef93d-36e0-47fc-8316-fbd7045e850a", "XYZ"}

  };
protected:
  virtual void SetUp()
  {
#ifdef OC_STORAGE
    mkdir("vod_map_test_dir", S_IRWXU | S_IRWXG | S_IRWXG /* 0777 permissions*/ );
    oc_storage_config("./vod_map_test_dir/");
#endif /* OC_STORAGE */

  }
  virtual void TearDown()
  {
    remove("./vod_map_test_dir/vod_map");
    remove("./vod_map_test_dir/");
  }
};

TEST_F(VodMapTest, vod_map_add_id) {
  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  const char * dummy = "dummy";
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  oc_vod_map_free();

  // by freeing the vod map and calling oc_vod_map_init again the code is using
  // the same code path it would take if the process were shut down and had
  // to load the vod map from oc_storage.
  oc_vod_map_init();
  // tv[0] and tv[1] were dumped to file so should be loaded as part of the init
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  // tv[2] should not be found since it was not added above.
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  oc_vod_map_free();
}


TEST_F(VodMapTest, vod_map_remove_id) {
  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  const char * dummy = "dummy";
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  oc_vod_map_remove_id(1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  oc_vod_map_free();

  // by freeing the vod map and calling oc_vod_map_init again the code is using
  // the same code path it would take if the process were shut down and had
  // to load the vod map from oc_storage.
  oc_vod_map_init();
  // tv[0] and tv[1] were dumped to file so should be loaded as part of the init
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  // tv[2] should not be found since it was not added above.
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);

  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  
  oc_vod_map_reset();
  
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);
  
  oc_vod_map_free();

  // test intermittent removal of vod_ids

  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 0);



  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 4);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 4);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  oc_vod_map_remove_id(2);
  oc_vod_map_remove_id(4);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  oc_vod_map_free();

  // by freeing the vod map and calling oc_vod_map_init again the code is using
  // the same code path it would take if the process were shut down and had
  // to load the vod map from oc_storage.
  oc_vod_map_init();

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 2);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 4);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 4);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  oc_vod_map_reset();
  oc_vod_map_free();

  // test consecutive removal of vod_ids

  oc_vod_map_init();
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 0);



  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)dummy, strlen(dummy), dummy), 0);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 4);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 4);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  oc_vod_map_remove_id(2);
  oc_vod_map_remove_id(4);
  oc_vod_map_remove_id(3);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  oc_vod_map_free();
  // by freeing the vod map and calling oc_vod_map_init again the code is using
  // the same code path it would take if the process were shut down and had
  // to load the vod map from oc_storage.
  oc_vod_map_init();

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 2);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 4);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[0].vod_id, strlen(tv[0].vod_id), tv[0].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[1].vod_id, strlen(tv[1].vod_id), tv[1].eco_system), 4);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[2].vod_id, strlen(tv[2].vod_id), tv[2].eco_system), 3);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 2);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 5);

  oc_vod_map_free();
}

TEST_F(VodMapTest, vod_map_add_same_id_different_econame) {
  oc_vod_map_init();
  // verify the vod_id are not yet added
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 0);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 0);

  // The vod map code actually expects the zero device to always be a bridge or
  // other device for that reason we are inserting a dummy device at index zero
  // this will be dumped into the output map file but shouldn't effect the
  // test results.
  const char * dummy = "dummy";
  EXPECT_EQ(oc_vod_map_add_id((uint8_t *)dummy, strlen(dummy), dummy), 0);

  // even though tv[3] and tv[4] have the same vod_id they have different econames and
  // should each get a different index
  size_t vod_index3 = oc_vod_map_add_id((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system);
  size_t vod_index4 = oc_vod_map_add_id((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system);
  EXPECT_NE(vod_index3, vod_index4);

  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[3].vod_id, strlen(tv[3].vod_id), tv[3].eco_system), 1);
  EXPECT_EQ(oc_vod_map_get_id_index((uint8_t *)tv[4].vod_id, strlen(tv[4].vod_id), tv[4].eco_system), 2);

  oc_vod_map_free();
}

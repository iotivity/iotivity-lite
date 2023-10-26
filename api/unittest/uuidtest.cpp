/******************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
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
 *
 ******************************************************************/

#include "oc_uuid.h"
#include "port/oc_random.h"

#include <array>
#include <cstdlib>
#include <gtest/gtest.h>
#include <string>

constexpr const char UUID[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
constexpr const char UUID2[] = "XYZabcdefghijklmnopqrstuvwxyz012";

using uuid_buffer_t = std::array<char, OC_UUID_LEN>;

TEST(UUID, StrToUUIDTest_P)
{
  oc_uuid_t uuid{};
  oc_uuid_t uuidTemp = uuid;
  oc_str_to_uuid(UUID, &uuid);
  EXPECT_NE(0, memcmp(uuid.id, uuidTemp.id, OC_UUID_ID_SIZE));

  oc_uuid_t uuid2{};
  oc_uuid_t uuid2Temp = uuid2;
  oc_str_to_uuid(UUID2, &uuid2);
  EXPECT_NE(0, memcmp(uuid2.id, uuid2Temp.id, OC_UUID_ID_SIZE));
}

TEST(UUID, StrToUUIDTest_F)
{
  oc_uuid_t uuid{};
  memset(&uuid, 0, sizeof(oc_uuid_t));
  oc_uuid_t uuidTemp = uuid;
  oc_str_to_uuid(nullptr, &uuid);
  EXPECT_EQ(0, memcmp(uuid.id, uuidTemp.id, OC_UUID_ID_SIZE));
}

TEST(UUID, UUIDToStr_F)
{
  uuid_buffer_t wc{};
  oc_uuid_to_str(nullptr, wc.data(), wc.size());

  oc_uuid_t uuid{};
  std::array<char, OC_UUID_LEN - 1> too_small{};
  oc_uuid_to_str(&uuid, too_small.data(), too_small.size());
}

TEST(UUIDGeneration, WildcardStrToUUID)
{
  std::string u = "*";
  oc_uuid_t uuid{};
  oc_str_to_uuid(u.c_str(), &uuid);
  oc_uuid_t wc{};
  wc.id[0] = '*';
  EXPECT_EQ(memcmp(wc.id, uuid.id, OC_UUID_ID_SIZE), 0);
}

TEST(UUID, WildcardUUIDToStr)
{
  std::string u = "*";
  uuid_buffer_t wc{};
  oc_uuid_t uuid{};
  uuid.id[0] = '*';
  oc_uuid_to_str(&uuid, wc.data(), wc.size());
  EXPECT_STREQ(u.c_str(), wc.data());
}

TEST(UUID, WildcardUUIDToStrV1)
{
  std::string u = "*";
  std::array<char, 2> wc{};
  oc_uuid_t uuid{};
  uuid.id[0] = '*';
  EXPECT_EQ(1, oc_uuid_to_str_v1(&uuid, wc.data(), wc.size()));
  EXPECT_STREQ(u.c_str(), wc.data());
}

TEST(UUID, WildcardUUIDToStrV1_F)
{
  std::string u = "*";
  std::array<char, 1> too_small{};
  oc_uuid_t uuid{};
  uuid.id[0] = '*';
  EXPECT_EQ(-1, oc_uuid_to_str_v1(&uuid, too_small.data(), too_small.size()));
}

TEST(UUID, NonWildcardUUID)
{
  std::string u = "2af07d57-b2e3-4120-9292-f9fef16b41d7";
  uuid_buffer_t nonwc{};
  oc_uuid_t uuid{};
  oc_str_to_uuid(u.c_str(), &uuid);

  EXPECT_EQ('*', uuid.id[0]);
  EXPECT_EQ(0xf0, uuid.id[1]);
  EXPECT_EQ(0x7d, uuid.id[2]);
  EXPECT_EQ(0x57, uuid.id[3]);
  EXPECT_EQ(0xb2, uuid.id[4]);
  EXPECT_EQ(0xe3, uuid.id[5]);
  EXPECT_EQ(0x41, uuid.id[6]);
  EXPECT_EQ(0x20, uuid.id[7]);
  EXPECT_EQ(0x92, uuid.id[8]);
  EXPECT_EQ(0x92, uuid.id[9]);
  EXPECT_EQ(0xf9, uuid.id[10]);
  EXPECT_EQ(0xfe, uuid.id[11]);
  EXPECT_EQ(0xf1, uuid.id[12]);
  EXPECT_EQ(0x6b, uuid.id[13]);
  EXPECT_EQ(0x41, uuid.id[14]);
  EXPECT_EQ(0xd7, uuid.id[15]);

  oc_uuid_to_str(&uuid, nonwc.data(), nonwc.size());
  EXPECT_EQ(u.length(), strlen(nonwc.data()));
  EXPECT_STREQ(u.c_str(), nonwc.data());
}

TEST(UUID, UUIDToStrV1_F)
{
  oc_uuid_t uuid{};
  oc_str_to_uuid(UUID, &uuid);

  std::vector<char> too_small{};
  for (int i = 1; i < OC_UUID_LEN; i++) {
    too_small.resize(i);
    EXPECT_EQ(-1, oc_uuid_to_str_v1(&uuid, too_small.data(), too_small.size()));
  }
}

/*
 * Text from RFC 4122 4.4 placed here since it helps to understand the bit
 * twiddling done in the test.
 *
 * The version 4 UUID is meant for generating UUIDs from truly-random or
 * pseudo-random numbers.
 *
 * The algorithm is as follows:
 *
 * o  Set the two most significant bits (bits 6 and 7) of the
 *    clock_seq_hi_and_reserved to zero and one, respectively.
 *
 * o  Set the four most significant bits (bits 12 through 15) of the
 *    time_hi_and_version field to the 4-bit version number from
 *    Section 4.1.3.
 *
 * o  Set all the other bits to randomly (or pseudo-randomly) chosen
 *    values.
 */
TEST(UUIDGeneration, GenerateType4UUID)
{
  // Type 4 uuid uses iotivities psudo random number generator.
  oc_random_init();
  oc_uuid_t uuid{};
  oc_gen_uuid(&uuid);
  // `clock_seq_hi_and_reserved` is the 8th byte bit 7 is zero per spec
  EXPECT_EQ(0, (uuid.id[8] & 0x80));
  // `clock_seq_hi_and_reserved` is the 8th byte bit 6 is one per spec
  EXPECT_EQ(0x40, (uuid.id[8] & 0x40));
  // `time_hi_version` is the 6th and 7th bytes bits 15 through 12 should
  // be set to 0 1 0 0 (0x40) per spec
  EXPECT_EQ(0x40, (uuid.id[6] & 0x40));

  uuid_buffer_t uuid_str{};
  oc_uuid_to_str(&uuid, uuid_str.data(), uuid_str.size());
  EXPECT_EQ('-', uuid_str[8]);
  EXPECT_EQ('-', uuid_str[13]);
  EXPECT_EQ('4', uuid_str[14]); // For Version 4 UUIDs this will always be a 4
  EXPECT_EQ('-', uuid_str[18]);
  EXPECT_EQ('-', uuid_str[23]);
  oc_random_destroy();
}

TEST(UUIDComparison, EmptyUUID)
{
  oc_uuid_t first{};
  oc_uuid_t second{};
  EXPECT_TRUE(oc_uuid_is_equal(first, second));
  EXPECT_TRUE(oc_uuid_is_equal(second, first));
}

TEST(UUIDComparison, EmptyAndNonEmptyUUID)
{
  oc_uuid_t uuid{};
  oc_str_to_uuid(UUID, &uuid);
  oc_uuid_t empty{};
  EXPECT_FALSE(oc_uuid_is_equal(uuid, empty));
  EXPECT_FALSE(oc_uuid_is_equal(empty, uuid));
}

TEST(UUIDComparison, CopyUUID)
{
  oc_uuid_t uuid{};
  oc_str_to_uuid(UUID, &uuid);
  oc_uuid_t uuid_copy = uuid;
  EXPECT_TRUE(oc_uuid_is_equal(uuid, uuid_copy));
  EXPECT_TRUE(oc_uuid_is_equal(uuid_copy, uuid));
}

TEST(UUIDComparison, NonEmptyUUID)
{
  std::string uuid_str = "2af07d57-b2e3-4120-9292-f9fef16b41d7";
  oc_uuid_t uuid{};
  oc_str_to_uuid(uuid_str.c_str(), &uuid);

  oc_random_init();
  oc_uuid_t gen_uuid{};
  uuid_buffer_t gen_uuid_str{};
  do {
    oc_gen_uuid(&gen_uuid);
    oc_uuid_to_str(&gen_uuid, gen_uuid_str.data(), gen_uuid_str.size());
  } while (memcmp(gen_uuid_str.data(), uuid_str.c_str(), gen_uuid_str.size()) ==
           0);

  EXPECT_FALSE(oc_uuid_is_equal(uuid, gen_uuid));
  EXPECT_FALSE(oc_uuid_is_equal(gen_uuid, uuid));
}
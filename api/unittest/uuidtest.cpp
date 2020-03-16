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
#include "gtest/gtest.h"

#include "oc_uuid.h"
#include "port/oc_random.h"

#define UUID "12345678123412341234123456789012"

TEST(UUIDGeneration, StrToUUIDTest_P)
{
  oc_uuid_t uuid;
  memset(&uuid, 0, sizeof(oc_uuid_t));
  oc_uuid_t uuidTemp = uuid;
  oc_str_to_uuid(UUID, &uuid);
  EXPECT_NE(uuid.id, uuidTemp.id);
}

TEST(UUIDGeneration, WildcardStrToUUID)
{
  const char *u = "*";
  oc_uuid_t uuid;
  oc_str_to_uuid(u, &uuid);
  oc_uuid_t wc = { { 0 } };
  wc.id[0] = '*';
  EXPECT_EQ(memcmp(wc.id, uuid.id, 16), 0);
}

TEST(UUIDGeneration, WildcardUUIDToStr)
{
  const char *u = "*";
  char wc[37];
  oc_uuid_t uuid = { { 0 } };
  uuid.id[0] = '*';
  oc_uuid_to_str(&uuid, wc, 37);
  EXPECT_EQ(strlen(u), strlen(wc));
  EXPECT_EQ(memcmp(u, wc, strlen(u)), 0);
}

TEST(UUIDGeneration, NonWildcardUUID)
{
  const char *u = "2af07d57-b2e3-4120-9292-f9fef16b41d7";
  char nonwc[37];
  oc_uuid_t uuid;
  oc_str_to_uuid(u, &uuid);

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

  oc_uuid_to_str(&uuid, nonwc, 37);
  EXPECT_EQ(strlen(u), strlen(nonwc));
  EXPECT_EQ(memcmp(u, nonwc, strlen(u)), 0);
  EXPECT_STREQ(u, nonwc);
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
TEST(UUIDGeneration, GenerateType4UUID) {
  // Type 4 uuid uses iotivities psudo random number generator.
  oc_random_init();
  oc_uuid_t uuid;
  oc_gen_uuid(&uuid);
  // `clock_seq_hi_and_reserved` is the 8th byte bit 7 is zero per spec
  EXPECT_EQ(0, (uuid.id[8] & 0x80));
  // `clock_seq_hi_and_reserved` is the 8th byte bit 6 is one per spec
  EXPECT_EQ(0x40, (uuid.id[8] & 0x40));
  // `time_hi_version` is the 6th and 7th bytes bits 15 through 12 should
  // be set to 0 1 0 0 (0x40) per spec
  EXPECT_EQ(0x40, (uuid.id[6] & 0x40));

  char uuid_str[OC_UUID_LEN];
  oc_uuid_to_str(&uuid, uuid_str, OC_UUID_LEN);
  EXPECT_EQ('-', uuid_str[8]);
  EXPECT_EQ('-', uuid_str[13]);
  EXPECT_EQ('4', uuid_str[14]); // For Version 4 UUIDs this will always be a 4
  EXPECT_EQ('-', uuid_str[18]);
  EXPECT_EQ('-', uuid_str[23]);
  oc_random_destroy();
}

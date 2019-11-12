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
  oc_uuid_to_str(&uuid, nonwc, 37);
  EXPECT_EQ(strlen(u), strlen(nonwc));
  EXPECT_EQ(memcmp(u, nonwc, strlen(u)), 0);
}

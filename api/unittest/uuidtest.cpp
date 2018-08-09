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

extern "C" {
#include "oc_uuid.h"
}

#define UUID "12345678123412341234123456789012"

/*
 * @API             : oc_str_to_uuid
 * @Description     : test oc_str_to_uuid in a positive way
 * @PassCondition   : UUID not equal to oc_uuid_t
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(UUIDGeneration, StrToUUIDTest_P)
{
    oc_uuid_t uuid;
    memset(&uuid, 0, sizeof(oc_uuid_t));
    oc_uuid_t uuidTemp = uuid;
    oc_str_to_uuid(UUID, &uuid);
    EXPECT_NE(uuid.id, uuidTemp.id);
}

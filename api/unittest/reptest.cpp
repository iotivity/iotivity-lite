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


#include <stdlib.h>
#include "gtest/gtest.h"
extern "C" {
    #include "oc_rep.h"
}

TEST(TestRep, OCRepFinalizeTest_P)
{
    int repSize = oc_rep_finalize();
    EXPECT_NE(repSize, -1);
}

TEST(TestRep, OCRepGetDoubleTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    double *value = NULL;

    bool isFailure = oc_rep_get_double(&rep, key, value);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetIntArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int **value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_int_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetStringArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int *size = NULL;
    oc_string_array_t  *value = NULL;

    bool isFailure = oc_rep_get_string_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetDoubleTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";
    double value = 10;
    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    rep.name = name;
    rep.type = OC_REP_DOUBLE;
    rep.value.double_p = value;
    double retrievedValue = 0;

    bool isSuccess = oc_rep_get_double(&rep, key, &retrievedValue);
    ASSERT_TRUE(isSuccess);
    ASSERT_EQ(value, retrievedValue);
}

TEST(TestRep, OCRepGetIntArrayTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";
    int value[] = {1, 2};
    oc_array_t intArray;
    int size = 2;    
    intArray.size = size;
    intArray.ptr = value;
    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    rep.name = name;
    rep.type = OC_REP_INT_ARRAY;
    rep.value.array = intArray;
    int **retrievedValue = NULL;

    bool isFailure = oc_rep_get_int_array(&rep, key, retrievedValue, &size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetObjectTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";
    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    oc_rep_t  *value;
    rep.name = name;
    rep.type = OC_REP_OBJECT;
    rep.value.object = value;

    bool isSuccess = oc_rep_get_object(&rep, key, &value);
    ASSERT_TRUE(isSuccess);
}

TEST(TestRep, OCRepGetObjectArrayTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";
    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    oc_rep_t  *value;
    rep.name = name;
    rep.type = OC_REP_OBJECT_ARRAY;
    rep.value.object_array = value;

    bool isSuccess = oc_rep_get_object_array(&rep, key, &value);
    ASSERT_TRUE(isSuccess);
}

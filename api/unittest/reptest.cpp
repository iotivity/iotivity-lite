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
#include "oc_api.h"
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

TEST(TestRep, OCRepGetStringTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";
    int size = 6;

    oc_string_t name;
    name.size = size;
    name.ptr = key;
    rep.name = name;
    rep.type = OC_REP_STRING;

    char *testvalue = key;
    char **retrievedValue = &testvalue;

    int ret_size = size;

    bool isSucess = oc_rep_get_string(&rep, key, retrievedValue, &ret_size);
    ASSERT_TRUE(isSucess);
}

TEST(TestRep, OCRepGetStringTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int *size = NULL;
    char  **value = NULL;

    bool isFailure = oc_rep_get_string(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetStringArrayTest_P)
{

    oc_string_array_t byte_string_value[2];
    byte_string_value[0].ptr = "test";
    byte_string_value[0].size = 4;
    byte_string_value[0].next = NULL;
    byte_string_value[1].ptr = "hello";
    byte_string_value[1].size = 5;
    byte_string_value[1].next = NULL;

    int size = 2;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    oc_rep_t rep;
    rep.name = name;
    rep.type = OC_REP_STRING_ARRAY;

    bool isSucess = oc_rep_get_string_array(&rep, key, byte_string_value, &size);
    ASSERT_TRUE(isSucess);
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
    double value = 10.00000;
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
    int size = 2;

    oc_array_t intArray;
    intArray.size = size;
    intArray.ptr = value;

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_INT_ARRAY;
    rep.value.array = intArray;

    int *retrievedValue = value;

    bool isSuccess = oc_rep_get_int_array(&rep, key, &retrievedValue, &size);
    ASSERT_TRUE(isSuccess);
}

TEST(TestRep, OCRepGetObjectTest_P)
{
    oc_rep_t rep;
    oc_rep_t  *value;
    char key[] = "speed";
    oc_string_t name;

    name.size = 6;
    name.ptr = key;


    rep.name = name;
    rep.type = OC_REP_OBJECT;
    rep.value.object = value;

    bool isSuccess = oc_rep_get_object(&rep, key, &value);
    ASSERT_TRUE(isSuccess);
}

TEST(TestRep, OCRepGetObjectTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    oc_rep_t  *value;

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_OBJECT;
    rep.value.object = value;

    bool isFailure =  oc_rep_get_object(&rep, NULL, NULL);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetObjectArrayTest_P)
{
    oc_rep_t rep;
    oc_rep_t  *value;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_OBJECT_ARRAY;
    rep.value.object_array = value;

    bool isSuccess = oc_rep_get_object_array(&rep, key, &value);
    ASSERT_TRUE(isSuccess);
}

TEST(TestRep, OCRepGetObjectArrayTest_N)
{
    oc_rep_t rep;
    oc_rep_t  *value = NULL;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_OBJECT_ARRAY;
    rep.value.object_array = value;

    bool isFailure = oc_rep_get_object_array(&rep, NULL, NULL);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepFreeTest_N)
{
    oc_free_rep(NULL);
}

TEST(TestRep, OCRepSetPoolTest_P)
{
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
    oc_rep_set_pool(&rep_objects);
}

TEST(TestRep, OCRepSetPoolTest_N)
{
    oc_rep_set_pool(NULL);
}

TEST(TestRep, OCRepParseTest_N)
{
    const uint8_t *payload = NULL;
    int payload_len = 0;
    int isSuccess = oc_parse_rep(payload, payload_len, NULL);
    ASSERT_TRUE(isSuccess);
}

TEST(TestRep, OCRepGetIntTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";
    int value = 1;

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_INT;
    rep.value.integer = value;

    int retrievedValue = 10;

    bool isSucess = oc_rep_get_int(&rep, key, &retrievedValue);
    ASSERT_TRUE(isSucess);
}

TEST(TestRep, OCRepGetIntTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int value = 1;

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_INT;
    rep.value.integer = value;

    int *retrievedValue = NULL;

    bool isFailure = oc_rep_get_int(&rep, key, retrievedValue);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetBoolTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    rep.name = name;
    rep.type = OC_REP_BOOL;
    rep.value.boolean = true;

    bool retrievedValue = true;

    bool isSucess = oc_rep_get_bool(&rep, key, &retrievedValue);
    ASSERT_TRUE(isSucess);
}

TEST(TestRep, OCRepGetBoolTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    rep.name = name;
    rep.type = OC_REP_BOOL;
    rep.value.boolean = true;

    bool *retrievedValue = NULL;

    bool isFailure = oc_rep_get_bool(&rep, key, retrievedValue);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetByteStringTest_P)
{
    oc_rep_t rep;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    rep.name = name;
    rep.type = OC_REP_BYTE_STRING;

    char *testvalue = key;
    char **retrievedValue = &testvalue;


    int ret_size = 6;

    bool isSucess = oc_rep_get_byte_string(&rep, key, retrievedValue, &ret_size);
    ASSERT_TRUE(isSucess);
}

TEST(TestRep, OCRepGetByteStringTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;
    rep.name = name;
    rep.type = OC_REP_BYTE_STRING;

    char **retrievedValue = NULL;
    int ret_size = 0;

    bool isFailure = oc_rep_get_byte_string(&rep, key, retrievedValue, &ret_size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetByteStringSizeTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    char **retrievedValue = NULL;

    bool isFailure = oc_rep_get_byte_string(&rep, key, retrievedValue, NULL);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetBoolArrayTest_P)
{

    bool bool_value[] = {true, false};
    int size = 2;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    oc_rep_t rep;
    rep.name = name;
    rep.type = OC_REP_BOOL_ARRAY;

    bool *testvalue = bool_value;
    bool **retrievedValue = &testvalue;

    bool isSucess = oc_rep_get_bool_array(&rep, key, retrievedValue, &size);
    ASSERT_TRUE(isSucess);

}

TEST(TestRep, OCRepGetBoolArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    bool **value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_bool_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetDoubleArrayTest_P)
{

    double double_value[] = {1.0000, 2.1111};
    int size = 2;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    oc_rep_t rep;
    rep.name = name;
    rep.type = OC_REP_DOUBLE_ARRAY;

    double *testvalue = double_value;
    double **retrievedValue = &testvalue;

    bool isSucess = oc_rep_get_double_array(&rep, key, retrievedValue, &size);
    ASSERT_TRUE(isSucess);

}

TEST(TestRep, OCRepGetDoubleArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    double **value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_double_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepGetByteStringArrayTest_P)
{

    oc_string_array_t byte_string_value[2];
    byte_string_value[0].ptr = "test";
    byte_string_value[0].size = 4;
    byte_string_value[0].next = NULL;
    byte_string_value[1].ptr = "hello";
    byte_string_value[1].size = 5;
    byte_string_value[1].next = NULL;

    int size = 2;
    char key[] = "speed";

    oc_string_t name;
    name.size = 6;
    name.ptr = key;

    oc_rep_t rep;
    rep.name = name;
    rep.type = OC_REP_BYTE_STRING_ARRAY;

    bool isSucess = oc_rep_get_byte_string_array(&rep, key, byte_string_value, &size);
    ASSERT_TRUE(isSucess);

}

TEST(TestRep, OCRepGetByteStringArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    oc_string_array_t *value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_byte_string_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

TEST(TestRep, OCRepResetTest_P)
{
    oc_rep_reset();
}

TEST(TestRep, OCRepGetCborErrorNoTest_P)
{
    int err = oc_rep_get_cbor_errno();
    ASSERT_FALSE(err);
}


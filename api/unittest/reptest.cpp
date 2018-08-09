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

/*
 * @API             : oc_rep_finalize
 * @Description     : test oc_rep_finalize api in positive way
 * @PassCondition   : should not return -1
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepFinalizeTest_P)
{
    int repSize = oc_rep_finalize();
    EXPECT_NE(repSize, -1);
}

/*
 * @API             : oc_rep_get_double
 * @Description     : oc_rep_get_double api in negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetDoubleTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    double *value = NULL;

    bool isFailure = oc_rep_get_double(&rep, key, value);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_int_array
 * @Description     : test oc_rep_get_int_array in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetIntArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int **value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_int_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_string
 * @Description     : test oc_rep_get_string in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_string
 * @Description     : test oc_rep_get_string in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetStringTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int *size = NULL;
    char  **value = NULL;

    bool isFailure = oc_rep_get_string(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_string_array
 * @Description     : test oc_rep_get_string_array in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_string_array
 * @Description     : test oc_rep_get_string_array in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetStringArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    int *size = NULL;
    oc_string_array_t  *value = NULL;

    bool isFailure = oc_rep_get_string_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_double
 * @Description     : test oc_rep_get_double in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_int_array
 * @Description     : test oc_rep_get_int_array in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_object
 * @Description     : test oc_rep_get_object in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_object
 * @Description     : test oc_rep_get_object in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_object_array
 * @Description     : test oc_rep_get_object in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_object_array
 * @Description     : test oc_rep_get_object_array in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_free_rep
 * @Description     : test oc_free_rep in a negative way
 * @PassCondition   : should not throw any exception
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepFreeTest_N)
{
    ASSERT_NO_THROW(oc_free_rep(NULL));
}

/*
 * @API             : oc_rep_set_pool
 * @Description     : test oc_rep_set_pool in a positive way
 * @PassCondition   : should not throw any exception
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepSetPoolTest_P)
{
    struct oc_memb rep_objects = { sizeof(oc_rep_t), 0, 0, 0, 0 };
    ASSERT_NO_THROW(oc_rep_set_pool(&rep_objects));
}

/*
 * @API             : oc_rep_set_pool
 * @Description     : test oc_rep_set_pool in a negative way
 * @PassCondition   : should not throw any exception
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepSetPoolTest_N)
{
    ASSERT_NO_THROW(oc_rep_set_pool(NULL));
}

/*
 * @API             : oc_rep_set_pool
 * @Description     : test oc_rep_set_pool in a negative way
 * @PassCondition   : api should return true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepParseTest_N)
{
    const uint8_t *payload = NULL;
    int payload_len = 0;
    int isSuccess = oc_parse_rep(payload, payload_len, NULL);
    ASSERT_TRUE(isSuccess);
}

/*
 * @API             : oc_rep_get_int
 * @Description     : test oc_rep_get_int in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_int
 * @Description     : test oc_rep_get_int in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_bool
 * @Description     : test oc_rep_get_bool in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_bool
 * @Description     : test oc_rep_get_bool in a negative way
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_byte_string
 * @Description     : test oc_rep_get_byte_string in a positive way
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_byte_string
 * @Description     : negative tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_byte_string
 * @Description     : negative tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetByteStringSizeTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    char **retrievedValue = NULL;

    bool isFailure = oc_rep_get_byte_string(&rep, key, retrievedValue, NULL);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_bool_array
 * @Description     : positive tc
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_bool_array
 * @Description     : negative tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetBoolArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    bool **value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_bool_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_double_array
 * @Description     : positive tc
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_double_array
 * @Description     : negative tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetDoubleArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    double **value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_double_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_get_byte_string_array
 * @Description     : positive tc
 * @PassCondition   : returns true
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
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

/*
 * @API             : oc_rep_get_byte_string_array
 * @Description     : negative tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetByteStringArrayTest_N)
{
    oc_rep_t rep;
    char key[] = "speed";
    oc_string_array_t *value = NULL;
    int *size = NULL;

    bool isFailure = oc_rep_get_byte_string_array(&rep, key, value, size);
    ASSERT_FALSE(isFailure);
}

/*
 * @API             : oc_rep_reset
 * @Description     : positive tc
 * @PassCondition   : N/A
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepResetTest_P)
{
    ASSERT_NO_THROW(oc_rep_reset());
}

/*
 * @API             : oc_rep_get_cbor_errno
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepGetCborErrorNoTest_P)
{
    int err = oc_rep_get_cbor_errno();
    ASSERT_FALSE(err);
}

/*
 * @API             : oc_rep_set_double
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetDouble_p)
{
    char key[] = "speed";
    double value = 1.000;
    oc_rep_set_double(root, key, value);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_uint
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetUIntTest_p)
{
    char key[] = "speed";
    unsigned int value = 1;
    oc_rep_set_uint(root, key, value);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_int
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetIntTest_P)
{
    char key[] = "speed";
    int value = 1;
    oc_rep_set_int(root, key, value);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_boolean
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetBoolTest_P)
{
    char key[] = "speed";
    bool value = true;
    oc_rep_set_boolean(root, key, value);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_text_string
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetTextStringTest_P)
{
    char key[] = "speed";
    char value[] = "Hello Text";
    oc_rep_set_text_string(root, key, value);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_byte_string
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetByteStringTest_P)
{
    char key[] = "speed";
    char value[] = "Hello Text";
    oc_rep_set_byte_string(root, key, value, strlen(value));
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_start_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroStartArrayTest_P)
{
    char key[] = "speed";
    oc_rep_start_array(g_encoder, key);
    oc_rep_end_array(g_encoder, key);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_start_links_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroStartEndLinkArrayTest_P)
{
    oc_rep_start_links_array();
    oc_rep_end_links_array();
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_start_root_object
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroStartEndRootObjectTest_P)
{
    oc_rep_start_root_object();
    oc_rep_end_root_object();
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_add_byte_string
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroAddByteStringTest_P)
{
    oc_rep_set_key(g_encoder, "if");
    oc_rep_start_array(g_encoder, if);
    oc_rep_add_byte_string(if, "oic.if.baseline");
    oc_rep_end_array(g_encoder, if);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_add_text_string
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroAddTextStringTest_P)
{
    oc_rep_set_key(g_encoder, "if");
    oc_rep_start_array(g_encoder, if);
    oc_rep_add_text_string(if, "oic.if.baseline");
    oc_rep_end_array(g_encoder, if);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_add_double
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroAddeDoubleTest_P)
{
    oc_rep_set_key(g_encoder, "if");
    oc_rep_start_array(g_encoder, if);
    oc_rep_add_double(if, 1.0000);
    oc_rep_end_array(g_encoder, if);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_add_int
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroAddeIntTest_P)
{
    oc_rep_set_key(g_encoder, "if");
    oc_rep_start_array(g_encoder, if);
    oc_rep_add_int(if, 1);
    oc_rep_end_array(g_encoder, if);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_add_boolean
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroAddeBooleanTest_P)
{
    oc_rep_set_key(g_encoder, "if");
    oc_rep_start_array(g_encoder, if);
    oc_rep_add_boolean(if, true);
    oc_rep_end_array(g_encoder, if);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_key
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetKeyTest_P)
{
    oc_rep_set_key(g_encoder, "abcdefg");
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetArrayTest_P)
{
    char key[] = "speed";
    oc_rep_set_array(root, key);
    oc_rep_close_array(root, key);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_start_object, oc_rep_end_object
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroStartEndObjectTest_P)
{
    char key[] = "speed";
    oc_rep_start_object(g_encoder, key);
    oc_rep_end_object(g_encoder, key);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_object_array_start_item, oc_rep_object_array_end_item
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroStartEndObjectItemTest_P)
{
    char key[] = "speed";
    oc_rep_set_array(root, key);
    oc_rep_object_array_start_item (key);
    oc_rep_object_array_end_item(key);
    oc_rep_close_array(root, key);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_object, oc_rep_close_object
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetCloseObjectItemTest_P)
{
    char key[] = "speed";
    oc_rep_set_object(root, key);
    oc_rep_close_object(root, key);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_int_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetInitObjectItemTest_P)
{
    char key[] = "speed";
    int arr[2] = {0, 1};
    oc_rep_set_int_array(root, key, arr, 2);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_bool_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetBoolObjectItemTest_P)
{
    char key[] = "speed";
    bool arr[2] = {false, true};
    oc_rep_set_bool_array(root, key, arr, 2);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_double_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetDoubleObjectItemTest_P)
{
    char key[] = "speed";
    double arr[2] = {false, true};
    oc_rep_set_double_array(root, key, arr, 2);
    ASSERT_FALSE(g_err);
}

/*
 * @API             : oc_rep_set_string_array
 * @Description     : positive tc
 * @PassCondition   : returns false
 * @PreCondition    : N/A
 * @PostCondition   : N/A
*/
TEST(TestRep, OCRepMacroSetStringObjectItemTest_P)
{
    char key[] = "speed";
    oc_string_array_t byte_string_value;
    byte_string_value.ptr = "test";
    byte_string_value.size = 4;
    byte_string_value.next = NULL;
    oc_rep_set_string_array(root, key, byte_string_value);
    ASSERT_FALSE(g_err);
}

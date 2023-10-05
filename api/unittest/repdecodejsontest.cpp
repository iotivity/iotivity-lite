/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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

#include "util/oc_features.h"

#ifdef OC_JSON_ENCODER

#include "api/oc_rep_decode_json_internal.h"
#include "api/oc_rep_encode_json_internal.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Utility.h"

#include <gtest/gtest.h>
#include <string>

class TestRepDecodeJson : public testing::Test {
public:
  void SetUp() override
  {
    oc_rep_set_pool(&rep_objects_);
#ifndef OC_DYNAMIC_ALLOCATION
    memset(rep_objects_alloc_, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool_, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
#endif /* !OC_DYNAMIC_ALLOCATION */
  }

private:
#ifdef OC_DYNAMIC_ALLOCATION
  oc_memb rep_objects_{ sizeof(oc_rep_t), 0, nullptr, nullptr, nullptr };
#else  /* !OC_DYNAMIC_ALLOCATION */
  char rep_objects_alloc_[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool_[OC_MAX_NUM_REP_OBJECTS];
  oc_memb rep_objects_{ sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                        rep_objects_alloc_, (void *)rep_objects_pool_,
                        nullptr };
#endif /* OC_DYNAMIC_ALLOCATION */
};

static int
parseJsonToRep(const std::string &json, oc_rep_t **rep)
{
  auto jsonObj =
    oc::GetVector<uint8_t>(std::string("{\"json\": ") + json + "}", true);
  return oc_rep_parse_json(jsonObj.data(), jsonObj.size(), rep);
}

static oc::oc_rep_unique_ptr
parseJson(const std::string &json)
{
  oc_rep_t *rep = nullptr;
  EXPECT_EQ(CborNoError, parseJsonToRep(json, &rep));
  return oc::oc_rep_unique_ptr(rep, &oc_free_rep);
}

TEST_F(TestRepDecodeJson, DecodeNull)
{
  auto jsonRep = parseJson("null");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_NIL, jsonRep->type);
}

TEST_F(TestRepDecodeJson, DecodeBoolean)
{
  auto jsonRep = parseJson("true");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_BOOL, jsonRep->type);
  EXPECT_EQ(true, jsonRep->value.boolean);

  jsonRep = parseJson("false");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_BOOL, jsonRep->type);
  EXPECT_EQ(false, jsonRep->value.boolean);
}

TEST_F(TestRepDecodeJson, Decode_InvalidPrimitive)
{
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep("", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("n", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("nil", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("NULL", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("nnull", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("nulll", &rep));

  ASSERT_NE(CborNoError, parseJsonToRep("t", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("TRUE", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("ttrue", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("truee", &rep));

  ASSERT_NE(CborNoError, parseJsonToRep("f", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("FALSE", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("ffalse", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("falsee", &rep));
}

TEST_F(TestRepDecodeJson, DecodeString)
{
  auto jsonRep = parseJson(R"("Hello World")");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_STRING, jsonRep->type);
  EXPECT_STREQ("Hello World", oc_string(jsonRep->value.string));
}

// empty array is parsed as null
TEST_F(TestRepDecodeJson, DecodeEmptyArray)
{
  auto jsonRep = parseJson("[]");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_NIL, jsonRep->type);
}

// arrays of nulls are not supported and are parsed as null
TEST_F(TestRepDecodeJson, DecodeNullArray)
{
  auto jsonRep = parseJson("[null, null, null]");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_NIL, jsonRep->type);
}

TEST_F(TestRepDecodeJson, DecodeNullArray_InvalidValues)
{
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep("[null, true]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[null, false]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[null, 123]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[null, \"string\"]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[null, {}]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[null, []]", &rep));
}

TEST_F(TestRepDecodeJson, DecodeBoolArray)
{
  auto jsonRep = parseJson("[true, true, false, true]");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_BOOL_ARRAY, jsonRep->type);
  ASSERT_EQ(4, oc_bool_array_size(jsonRep->value.array));
  EXPECT_TRUE(oc_bool_array(jsonRep->value.array)[0]);
  EXPECT_TRUE(oc_bool_array(jsonRep->value.array)[1]);
  EXPECT_FALSE(oc_bool_array(jsonRep->value.array)[2]);
  EXPECT_TRUE(oc_bool_array(jsonRep->value.array)[3]);
}

TEST_F(TestRepDecodeJson, DecodeBoolArray_InvalidValues)
{
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep("[t]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[true, TRUE]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[true, truy]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[TRUE, true]", &rep));

  ASSERT_NE(CborNoError, parseJsonToRep("[f]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[false, FALSE]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[false, falsy]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[FALSE, false]", &rep));

  ASSERT_NE(CborNoError, parseJsonToRep("[true, null]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[true, 123]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[true, \"string\"]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[true, {}]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[true, []]", &rep));
}

TEST_F(TestRepDecodeJson, DecodeIntArray)
{
  auto jsonRep = parseJson("[0, 42, -1337]");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_INT_ARRAY, jsonRep->type);
  ASSERT_EQ(3, oc_int_array_size(jsonRep->value.array));
  EXPECT_EQ(0, oc_int_array(jsonRep->value.array)[0]);
  EXPECT_EQ(42, oc_int_array(jsonRep->value.array)[1]);
  EXPECT_EQ(-1337, oc_int_array(jsonRep->value.array)[2]);
}

TEST_F(TestRepDecodeJson, DecodeIntArray_InvalidValues)
{
  oc_rep_t *rep = nullptr;
  std::string intTooLarge = std::to_string(INT64_MAX) + "0";
  ASSERT_NE(CborNoError, parseJsonToRep("[" + intTooLarge + "]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[1, " + intTooLarge + "]", &rep));

  std::string intTooSmall = std::to_string(INT64_MIN) + "0";
  ASSERT_NE(CborNoError, parseJsonToRep("[" + intTooSmall + "]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[1, " + intTooSmall + "]", &rep));

  ASSERT_NE(CborNoError, parseJsonToRep("[1, null]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[1, true]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[1, \"string\"]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[1, {}]", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep("[1, []]", &rep));
}

TEST_F(TestRepDecodeJson, DecodeStringArray)
{
  auto jsonRep = parseJson(R"(["This", "is", "a", "test"])");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_STRING_ARRAY, jsonRep->type);
  ASSERT_EQ(4, oc_string_array_get_allocated_size(jsonRep->value.array));
  EXPECT_STREQ("This", oc_string_array_get_item(jsonRep->value.array, 0));
  EXPECT_STREQ("is", oc_string_array_get_item(jsonRep->value.array, 1));
  EXPECT_STREQ("a", oc_string_array_get_item(jsonRep->value.array, 2));
  EXPECT_STREQ("test", oc_string_array_get_item(jsonRep->value.array, 3));
}

TEST_F(TestRepDecodeJson, DecodeStringArray_Truncate)
{
  // STRING_ARRAY_ITEM_MAX_LEN is the maximum length of a string array item
  // without null terminator
  auto tooLong = std::string(STRING_ARRAY_ITEM_MAX_LEN, 'a');
  auto jsonRep = parseJson("[\"" + tooLong + "\"]");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_STRING_ARRAY, jsonRep->type);
  ASSERT_EQ(1, oc_string_array_get_allocated_size(jsonRep->value.array));
  EXPECT_STREQ(std::string(STRING_ARRAY_ITEM_MAX_LEN - 1, 'a').c_str(),
               oc_string_array_get_item(jsonRep->value.array, 0));
}

TEST_F(TestRepDecodeJson, DecodeStringArray_InvalidValues)
{
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep(R"(["str", null])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"(["str", true])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"(["str", 1])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"(["str", []])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"(["str", {}])", &rep));
}

TEST_F(TestRepDecodeJson, DecodeArray_InvalidValues)
{
  // arrays of arrays are not supported
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep(R"([[]])", &rep));
  ASSERT_NE(CborNoError,
            parseJsonToRep(R"([[true, false], [true, false]])", &rep));
}

TEST_F(TestRepDecodeJson, DecodeEmptyObject)
{
  auto jsonRep = parseJson("{}");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_OBJECT, jsonRep->type);
}

TEST_F(TestRepDecodeJson, DecodeEmptyKeyObject)
{
  auto jsonRep = parseJson(R"({"": null})");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_OBJECT, jsonRep->type);
}

TEST_F(TestRepDecodeJson, DecodeObjectWithPrimitiveValues)
{
  auto jsonRep = parseJson(
    R"({"null": null, "bool": true, "int": 42, "string": "Hello World"})");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_OBJECT, jsonRep->type);

  bool is_null = false;
  ASSERT_TRUE(oc_rep_is_null(jsonRep->value.object, "null", &is_null));
  EXPECT_TRUE(is_null);

  bool value = false;
  ASSERT_TRUE(oc_rep_get_bool(jsonRep->value.object, "bool", &value));
  EXPECT_TRUE(value);

  int64_t i = 0;
  ASSERT_TRUE(oc_rep_get_int(jsonRep->value.object, "int", &i));
  EXPECT_EQ(42, i);

  char *s = nullptr;
  size_t size = 0;
  ASSERT_TRUE(oc_rep_get_string(jsonRep->value.object, "string", &s, &size));
  ASSERT_EQ(std::string("Hello World").length(), size);
  EXPECT_STREQ("Hello World", s);
}

TEST_F(TestRepDecodeJson, DecodeObjectWithArrays)
{
  auto jsonRep = parseJson(
    R"({"intArray": [1, 42, 1337], "boolArray": [false,true,false,false], )"
    R"("stringArray": ["This", "is", "a", "test"]})");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_OBJECT, jsonRep->type);

  int64_t *intArray = nullptr;
  size_t size = 0;
  ASSERT_TRUE(
    oc_rep_get_int_array(jsonRep->value.object, "intArray", &intArray, &size));
  ASSERT_EQ(3, size);
  EXPECT_EQ(1, intArray[0]);
  EXPECT_EQ(42, intArray[1]);
  EXPECT_EQ(1337, intArray[2]);

  bool *boolArray = nullptr;
  size = 0;
  ASSERT_TRUE(oc_rep_get_bool_array(jsonRep->value.object, "boolArray",
                                    &boolArray, &size));
  ASSERT_EQ(4, size);
  EXPECT_FALSE(boolArray[0]);
  EXPECT_TRUE(boolArray[1]);
  EXPECT_FALSE(boolArray[2]);
  EXPECT_FALSE(boolArray[3]);

  oc_string_array_t str_array{};
  size = 0;
  ASSERT_TRUE(oc_rep_get_string_array(jsonRep->value.object, "stringArray",
                                      &str_array, &size));
  EXPECT_STREQ("This", oc_string_array_get_item(str_array, 0));
  EXPECT_STREQ("is", oc_string_array_get_item(str_array, 1));
  EXPECT_STREQ("a", oc_string_array_get_item(str_array, 2));
  EXPECT_STREQ("test", oc_string_array_get_item(str_array, 3));
}

TEST_F(TestRepDecodeJson, DecodeObjectWithObjects)
{
  auto jsonRep = parseJson(
    R"({"empty": {}, "first_layer": {"second_layer": {"first_value": 13, "second_value": ["Hello", "World"]}}})");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_OBJECT, jsonRep->type);

  oc_rep_t *empty = nullptr;
  ASSERT_TRUE(oc_rep_get_object(jsonRep->value.object, "empty", &empty));
  ASSERT_EQ(nullptr, empty);

  oc_rep_t *first_layer = nullptr;
  ASSERT_TRUE(
    oc_rep_get_object(jsonRep->value.object, "first_layer", &first_layer));
  ASSERT_NE(nullptr, first_layer);
  ASSERT_EQ(OC_REP_OBJECT, first_layer->type);

  int64_t i = 0;
  ASSERT_TRUE(oc_rep_get_int(first_layer->value.object, "first_value", &i));
  EXPECT_EQ(13, i);

  oc_string_array_t str_array{};
  size_t size = 0;
  ASSERT_TRUE(oc_rep_get_string_array(first_layer->value.object, "second_value",
                                      &str_array, &size));
  ASSERT_EQ(2, size);
  EXPECT_STREQ("Hello", oc_string_array_get_item(str_array, 0));
  EXPECT_STREQ("World", oc_string_array_get_item(str_array, 1));
}

TEST_F(TestRepDecodeJson, DecodeObject_InvalidKey)
{
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep(R"({null: null})", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"({true: false})", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"({1: 2})", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"({[]: []})", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"({{}: {}})", &rep));
}

TEST_F(TestRepDecodeJson, DecodeObjectArray)
{
  auto jsonRep = parseJson(
    R"([{"bool": false}, {"int": 1337}, {"stringArray": ["This", "is", "a", "test"]}])");
  ASSERT_NE(nullptr, jsonRep.get());
  ASSERT_EQ(OC_REP_OBJECT_ARRAY, jsonRep->type);

  oc_rep_t *boolObject = nullptr;
  oc_rep_t *intObject = nullptr;
  oc_rep_t *stringArrayObject = nullptr;
  for (oc_rep_t *objects = jsonRep->value.object_array; objects != nullptr;
       objects = objects->next) {
    oc_rep_t *obj = objects->value.object;
    if (std::string(oc_string(obj->name)) == "bool") {
      boolObject = obj;
      continue;
    }
    if (std::string(oc_string(obj->name)) == "int") {
      intObject = obj;
      continue;
    }
    if (std::string(oc_string(obj->name)) == "stringArray") {
      stringArrayObject = obj;
      continue;
    }
    ASSERT_FALSE(true) << "Unexpected object: " << oc_string(obj->name);
  }
  ASSERT_NE(nullptr, boolObject);
  ASSERT_NE(nullptr, intObject);
  ASSERT_NE(nullptr, stringArrayObject);

  bool value{};
  ASSERT_TRUE(oc_rep_get_bool(boolObject, "bool", &value));
  EXPECT_FALSE(value);

  int64_t i = 0;
  ASSERT_TRUE(oc_rep_get_int(intObject, "int", &i));
  EXPECT_EQ(1337, i);

  oc_string_array_t str_array{};
  size_t size = 0;
  ASSERT_TRUE(oc_rep_get_string_array(stringArrayObject, "stringArray",
                                      &str_array, &size));
  ASSERT_EQ(4, size);
  EXPECT_STREQ("This", oc_string_array_get_item(str_array, 0));
  EXPECT_STREQ("is", oc_string_array_get_item(str_array, 1));
  EXPECT_STREQ("a", oc_string_array_get_item(str_array, 2));
  EXPECT_STREQ("test", oc_string_array_get_item(str_array, 3));
}

TEST_F(TestRepDecodeJson, DecodeObjectArray_InvalidValues)
{
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, parseJsonToRep(R"([{}, null])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"([{}, true])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"([{}, 1])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"([{}, "str"])", &rep));
  ASSERT_NE(CborNoError, parseJsonToRep(R"([{}, []])", &rep));
}

TEST_F(TestRepDecodeJson, Decode_InvalidJson)
{
  oc_rep_t *rep = nullptr;
  std::string json = R"({"json":: )";
  auto jsonObj = oc::GetVector<uint8_t>(json, true);
  ASSERT_NE(CborNoError,
            oc_rep_parse_json(jsonObj.data(), jsonObj.size(), &rep));
}

#endif /* OC_JSON_ENCODER */

/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "util/oc_features.h"

#ifdef OC_JSON_ENCODER

#include "api/oc_con_resource_internal.h"
#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "api/oc_rep_encode_json_internal.h"
#include "api/oc_rep_internal.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "tests/gtest/Utility.h"
#include "util/oc_memb.h"
#include "util/oc_secure_string_internal.h"

#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };
static const oc_rep_encoder_type_t g_rep_default_encoder =
  oc_rep_encoder_get_type();
static const oc_rep_decoder_type_t g_rep_default_decoder =
  oc_rep_decoder_get_type();

class TestJsonRepWithPool : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_rep_encoder_set_type(OC_REP_JSON_ENCODER);
    oc_rep_decoder_set_type(OC_REP_JSON_DECODER);
  }

  static void TearDownTestCase()
  {
    oc_rep_encoder_set_type(g_rep_default_encoder);
    oc_rep_decoder_set_type(g_rep_default_decoder);
  }

  void SetUp() override { ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno()); }

  oc_memb *GetRepObjectsPool() { return pool_.GetRepObjectsPool(); }

  oc::oc_rep_unique_ptr ParsePayload() { return pool_.ParsePayload(); }

  static void CheckJson(const oc_rep_t *rep, const std::string &expected,
                        bool pretty_print)
  {
    oc::RepPool::CheckJson(rep, expected, pretty_print);
  }

private:
  oc::RepPool pool_{};
};

TEST_F(TestJsonRepWithPool, OCRepInvalidFormat)
{
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  EXPECT_EQ(CborErrorImproperValue, oc_rep_encode_int(&root_map, 42));
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  auto invalid_json = oc::GetVector<uint8_t>("{42}");
  /* convert JsonEncoder to oc_rep_t */
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError,
            oc_parse_rep(invalid_json.data(), invalid_json.size(), &rep));
  ASSERT_EQ(nullptr, rep);
}

TEST_F(TestJsonRepWithPool, OCRepInvalidArray)
{
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_key(oc_rep_object(root), "mixed");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_begin_array(oc_rep_object(root), mixed);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_int(mixed, 42);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(mixed, "1337");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_array(oc_rep_object(root), mixed);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  ASSERT_NE(nullptr, payload);
  int payload_len = oc_rep_get_encoded_payload_size();
  ASSERT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, oc_parse_rep(payload, payload_len, &rep));
  ASSERT_EQ(nullptr, rep);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetNull)
{
  /* add null value to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_null(root, nothing);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  bool is_null = false;
  EXPECT_TRUE(oc_rep_is_null(rep.get(), "nothing", &is_null));
  EXPECT_TRUE(is_null);

  /* error handling */
  EXPECT_FALSE(oc_rep_is_null(nullptr, "nothing", &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), nullptr, &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), "", &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), "", &is_null));
  EXPECT_FALSE(oc_rep_is_null(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), "nothing", nullptr));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), "not_the_key", &is_null));

  CheckJson(rep.get(), "{\"nothing\":null}", false);
  CheckJson(rep.get(), "{\n  \"nothing\" : null\n}\n", true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetDouble)
{
  /* add double values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_double(root, pi, 3.14159);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  // TODO: implement parsing of double/float values
}

TEST_F(TestJsonRepWithPool, OCRepSetGetInt)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, ultimate_answer, 10000000000);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, negative, -1024);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, zero, 0);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, max_positive, OC_REP_JSON_INT_MAX);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, max_negative, OC_REP_JSON_INT_MIN);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from  the oc_rep_t */
  int64_t ultimate_answer_out = 0;
  EXPECT_TRUE(
    oc_rep_get_int(rep.get(), "ultimate_answer", &ultimate_answer_out));
  EXPECT_EQ(10000000000, ultimate_answer_out);
  int64_t negative_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep.get(), "negative", &negative_out));
  EXPECT_EQ(-1024, negative_out);
  int64_t zero_out = -1;
  EXPECT_TRUE(oc_rep_get_int(rep.get(), "zero", &zero_out));
  EXPECT_EQ(0, zero_out);
  int64_t max_positive_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep.get(), "max_positive", &max_positive_out));
  EXPECT_EQ(OC_REP_JSON_INT_MAX, max_positive_out);
  int64_t max_negative_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep.get(), "max_negative", &max_negative_out));
  EXPECT_EQ(OC_REP_JSON_INT_MIN, max_negative_out);

  /* check error handling */
  EXPECT_FALSE(oc_rep_get_int(nullptr, "zero", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), nullptr, &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "zero", nullptr));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "not_a_key", &zero_out));

  std::string json =
    R"({"ultimate_answer":10000000000,"negative":-1024,"zero":0,"max_positive":)" +
    std::to_string(OC_REP_JSON_INT_MAX) + R"(,"max_negative":)" +
    std::to_string(OC_REP_JSON_INT_MIN) + R"(})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"ultimate_answer\" : 10000000000,\n"
                            "  \"negative\" : -1024,\n"
                            "  \"zero\" : 0,\n"
                            "  \"max_positive\" : " +
                            std::to_string(OC_REP_JSON_INT_MAX) +
                            ",\n"
                            "  \"max_negative\" : " +
                            std::to_string(OC_REP_JSON_INT_MIN) +
                            "\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetUint)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_uint(root, ultimate_answer, 42);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  /*
   * Assuming 32 bit int, which should be true for systems the gtest will
   * be running on, the largest value for 32 bit int is 2,147,483,647 or
   * 0x7FFFFFFF
   */
  oc_rep_set_uint(root, larger_than_int, 3000000000);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_uint(root, zero, 0);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from  the oc_rep_t */
  EXPECT_EQ(OC_REP_INT, rep->type);
  int64_t ultimate_answer_out = 0;
  EXPECT_TRUE(
    oc_rep_get_int(rep.get(), "ultimate_answer", &ultimate_answer_out));
  EXPECT_EQ(42u, (unsigned)ultimate_answer_out);
  int64_t larger_than_int_out = 0;
  EXPECT_TRUE(
    oc_rep_get_int(rep.get(), "larger_than_int", &larger_than_int_out));
  EXPECT_EQ(3000000000u, (unsigned)larger_than_int_out);
  int64_t zero_out = -1;
  EXPECT_TRUE(oc_rep_get_int(rep.get(), "zero", &zero_out));
  EXPECT_EQ(0u, (unsigned)zero_out);

  /* check error handling */
  EXPECT_FALSE(oc_rep_get_int(nullptr, "zero", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), nullptr, &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "zero", nullptr));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "not_a_key", &zero_out));

  std::string json =
    R"({"ultimate_answer":42,"larger_than_int":3000000000,"zero":0})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"ultimate_answer\" : 42,\n"
                            "  \"larger_than_int\" : 3000000000,\n"
                            "  \"zero\" : 0\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetBool)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(root, true_flag, true);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(root, false_flag, false);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the ultimate_answer from  the oc_rep_t */
  bool true_flag_out = false;
  EXPECT_TRUE(oc_rep_get_bool(rep.get(), "true_flag", &true_flag_out));
  EXPECT_TRUE(true_flag_out);
  bool false_flag_out = true;
  EXPECT_TRUE(oc_rep_get_bool(rep.get(), "false_flag", &false_flag_out));
  EXPECT_FALSE(false_flag_out);

  /* check error handling */
  EXPECT_FALSE(oc_rep_get_bool(nullptr, "true_flag", &true_flag_out));
  EXPECT_FALSE(oc_rep_get_bool(rep.get(), nullptr, &true_flag_out));
  EXPECT_FALSE(oc_rep_get_bool(rep.get(), "", &true_flag_out));
  EXPECT_FALSE(oc_rep_get_bool(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &true_flag_out));
  EXPECT_FALSE(oc_rep_get_bool(rep.get(), "true_flag", nullptr));
  EXPECT_FALSE(oc_rep_get_bool(rep.get(), "not_a_key", &true_flag_out));

  std::string json = R"({"true_flag":true,"false_flag":false})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"true_flag\" : true,\n"
                            "  \"false_flag\" : false\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetTextString)
{
  /* add text string value "hal9000":"Dave" to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, empty, "");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hal9000, "Dave");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  /* test utf8 character support "hello world" in russian */
  oc_rep_set_text_string(root, ru_character_set, "Привет, мир");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the hal9000 from  the oc_rep_t */
  char *empty_out = nullptr;
  size_t str_len;
  EXPECT_TRUE(oc_rep_get_string(rep.get(), "empty", &empty_out, &str_len));
  EXPECT_STREQ("", empty_out);
  char *hal9000_out = nullptr;
  EXPECT_TRUE(oc_rep_get_string(rep.get(), "hal9000", &hal9000_out, &str_len));
  EXPECT_STREQ("Dave", hal9000_out);
  EXPECT_EQ(4, str_len);
  char *ru_character_set_out = nullptr;
  EXPECT_TRUE(oc_rep_get_string(rep.get(), "ru_character_set",
                                &ru_character_set_out, &str_len));
  EXPECT_STREQ("Привет, мир", ru_character_set_out);
  /*
   * to encode Привет, мир takes more bytes than the number of characters so
   * calculate the the number of bytes using the strlen function.
   */
  EXPECT_EQ(strlen("Привет, мир"), str_len);

  /* check error handling */
  EXPECT_FALSE(oc_rep_get_string(nullptr, "hal9000", &hal9000_out, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep.get(), nullptr, &hal9000_out, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep.get(), "", &hal9000_out, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep.get(),
                                 std::string(OC_MAX_STRING_LENGTH, 'k').c_str(),
                                 &hal9000_out, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep.get(), "hal9000", nullptr, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep.get(), "hal9000", &hal9000_out, nullptr));
  EXPECT_FALSE(
    oc_rep_get_string(rep.get(), "not_a_key", &hal9000_out, &str_len));

  std::string json =
    R"({"empty":"","hal9000":"Dave","ru_character_set":"Привет, мир"})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"empty\" : \"\",\n"
                            "  \"hal9000\" : \"Dave\",\n"
                            "  \"ru_character_set\" : \"Привет, мир\"\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetEmptyIntArray)
{
  /*
    {
      "emptyInt": null,
    }
  */
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int_array(root, emptyInt, (int64_t *)nullptr, 0);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"emptyInt\":null}", false);
  CheckJson(rep.get(), "{\n  \"emptyInt\" : null\n}\n", true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetIntArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<int64_t> fib = {
    1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 10000000000
  };
  oc_rep_set_int_array(root, fibonacci, fib.data(), fib.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  int64_t *fib_out = nullptr;
  size_t fib_len;
  EXPECT_TRUE(oc_rep_get_int_array(rep.get(), "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(fib.size(), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_int_array(nullptr, "fibonacci", &fib_out, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep.get(), nullptr, &fib_out, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep.get(), "", &fib_out, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &fib_out,
    &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep.get(), "fibonacci", nullptr, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep.get(), "fibonacci", &fib_out, nullptr));
  EXPECT_FALSE(
    oc_rep_get_int_array(rep.get(), "not_a_key", &fib_out, &fib_len));

  std::string json = "{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89,10000000000]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json =
    "{\n"
    "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 10000000000]\n"
    "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepAddGetIntArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<int64_t> fib = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
  oc_rep_open_array(root, fibonacci);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (const auto &v : fib) {
    oc_rep_add_int(fibonacci, v);
    ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_close_array(root, fibonacci);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  int64_t *fib_out = nullptr;
  size_t fib_len = 0;
  EXPECT_TRUE(oc_rep_get_int_array(rep.get(), "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(fib.size(), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  std::string json = "{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json =
    "{\n"
    "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]\n"
    "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepAddGetIntArrayUsingSetKeyAndBeginArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<int64_t> fib = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
  oc_rep_set_key(oc_rep_object(root), "fibonacci");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_begin_array(oc_rep_object(root), fibonacci);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (const auto &v : fib) {
    oc_rep_add_int(fibonacci, v);
    ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_end_array(oc_rep_object(root), fibonacci);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  int64_t *fib_out = nullptr;
  size_t fib_len = 0;
  EXPECT_TRUE(oc_rep_get_int_array(rep.get(), "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(fib.size(), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  std::string json = "{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json =
    "{\n"
    "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]\n"
    "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetEmptyBoolArray)
{
  /*
    {
      "emptyBool": null,
    }
  */
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_bool_array(root, emptyBool, (bool *)nullptr, 0);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"emptyBool\":null}", false);
  CheckJson(rep.get(), "{\n  \"emptyBool\" : null\n}\n", true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetBoolArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::array<bool, 5> flip = { false, false, true, false, false };
  oc_rep_set_bool_array(root, flip, flip.data(), flip.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  bool *flip_out = nullptr;
  size_t flip_len;
  EXPECT_TRUE(oc_rep_get_bool_array(rep.get(), "flip", &flip_out, &flip_len));
  ASSERT_EQ(flip.size(), flip_len);
  for (size_t i = 0; i < flip_len; ++i) {
    EXPECT_EQ(flip[i], flip_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_bool_array(nullptr, "flip", &flip_out, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep.get(), nullptr, &flip_out, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep.get(), "", &flip_out, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &flip_out,
    &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep.get(), "flip", nullptr, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep.get(), "flip", &flip_out, nullptr));
  EXPECT_FALSE(
    oc_rep_get_bool_array(rep.get(), "not_a_key", &flip_out, &flip_len));

  std::string json = "{\"flip\":[false,false,true,false,false]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"flip\" : [false, false, true, false, false]\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepAddGetBoolArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::array<bool, 5> flip = { false, false, true, false, false };
  oc_rep_open_array(root, flip);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (const auto &v : flip) {
    oc_rep_add_boolean(flip, v);
    ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_close_array(root, flip);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  bool *flip_out = nullptr;
  size_t flip_len = 0;
  EXPECT_TRUE(oc_rep_get_bool_array(rep.get(), "flip", &flip_out, &flip_len));
  ASSERT_EQ(flip.size(), flip_len);
  for (size_t i = 0; i < flip_len; ++i) {
    EXPECT_EQ(flip[i], flip_out[i]);
  }

  std::string json = "{\"flip\":[false,false,true,false,false]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"flip\" : [false, false, true, false, false]\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetEmptyObject)
{
  /*
    {
      "empty": {},
    }
  */
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_open_object(root, empty);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(root, empty);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"empty\":{}}", false);
  CheckJson(rep.get(), "{\n  \"empty\" : {\n  }\n}\n", true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetObject)
{
  /*
   * {
   *   "my_object": {
   *     "a": 1
   *     "b": false
   *     "c": "three"
   *   }
   * }
   */
  /* add values to root object */
  std::string c_value = "three";
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(root, my_object);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(my_object, a, 1);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(my_object, b, false);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(my_object, c, c_value.c_str());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(root, my_object);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  oc_rep_t *my_object_out = nullptr;
  EXPECT_TRUE(oc_rep_get_object(rep.get(), "my_object", &my_object_out));
  ASSERT_NE(nullptr, my_object_out);
  int64_t a_out;
  EXPECT_TRUE(oc_rep_get_int(my_object_out, "a", &a_out));
  EXPECT_EQ(1, a_out);
  bool b_out = true;
  EXPECT_TRUE(oc_rep_get_bool(my_object_out, "b", &b_out));
  EXPECT_FALSE(b_out);
  char *c_out = nullptr;
  size_t c_out_size = 0;
  EXPECT_TRUE(oc_rep_get_string(my_object_out, "c", &c_out, &c_out_size));
  EXPECT_EQ(c_value.length(), c_out_size);
  EXPECT_STREQ(c_value.c_str(), c_out);

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_object(nullptr, "my_object", &my_object_out));
  EXPECT_FALSE(oc_rep_get_object(rep.get(), nullptr, &my_object_out));
  EXPECT_FALSE(oc_rep_get_object(rep.get(), "", &my_object_out));
  EXPECT_FALSE(oc_rep_get_object(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &my_object_out));
  EXPECT_FALSE(oc_rep_get_object(rep.get(), "my_object", nullptr));
  EXPECT_FALSE(oc_rep_get_object(rep.get(), "not_a_key", &my_object_out));

  std::string json = R"({"my_object":{"a":1,"b":false,"c":"three"}})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"my_object\" : {\n"
                            "    \"a\" : 1,\n"
                            "    \"b\" : false,\n"
                            "    \"c\" : \"three\"\n"
                            "  }\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetEmptyObjectArray)
{
  /*
    {
      "emptyObj": null,
    }
  */
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_open_array(root, emptyObj);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_array(root, emptyObj);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"emptyObj\":null}", false);
  CheckJson(rep.get(), "{\n  \"emptyObj\" : null\n}\n", true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetObjectArray)
{
  /*
   * {
   *   "space_2001": [
   *     {"name": "Dave Bowman", "job": "astronaut"},
   *     {"name": "Frank Poole", "job": "astronaut"},
   *     {"name": "Hal 9000", "job": "AI computer"}
   *   ]
   */
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_array(root, space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_object_array_start_item(space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, name, "Dave Bowman");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, job, "astronaut");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_object_array_start_item(space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, name, "Frank Poole");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, job, "astronaut");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_object_array_start_item(space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, name, "Hal 9000");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, job, "AI computer");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_close_array(root, space_2001);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  /* calling this an object_array is a bit of a misnomer internally it is a
   * linked list */
  oc_rep_t *space_2001_out = nullptr;
  EXPECT_TRUE(
    oc_rep_get_object_array(rep.get(), "space_2001", &space_2001_out));
  ASSERT_TRUE(space_2001_out != nullptr);

  char *name_out = nullptr;
  size_t name_out_size = 0;
  char *job_out = nullptr;
  size_t job_out_size = 0;
  EXPECT_EQ(OC_REP_OBJECT, space_2001_out->type);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "name", &name_out,
                                &name_out_size));
  EXPECT_EQ(strlen("Dave Bowman"), name_out_size);
  EXPECT_STREQ("Dave Bowman", name_out);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "job", &job_out,
                                &job_out_size));
  EXPECT_EQ(strlen("astronaut"), job_out_size);
  EXPECT_STREQ("astronaut", job_out);

  space_2001_out = space_2001_out->next;
  ASSERT_TRUE(space_2001_out != nullptr);
  EXPECT_EQ(OC_REP_OBJECT, space_2001_out->type);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "name", &name_out,
                                &name_out_size));
  EXPECT_EQ(strlen("Frank Poole"), name_out_size);
  EXPECT_STREQ("Frank Poole", name_out);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "job", &job_out,
                                &job_out_size));
  EXPECT_EQ(strlen("astronaut"), job_out_size);
  EXPECT_STREQ("astronaut", job_out);

  space_2001_out = space_2001_out->next;
  ASSERT_TRUE(space_2001_out != nullptr);
  EXPECT_EQ(OC_REP_OBJECT, space_2001_out->type);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "name", &name_out,
                                &name_out_size));
  EXPECT_EQ(strlen("Hal 9000"), name_out_size);
  EXPECT_STREQ("Hal 9000", name_out);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "job", &job_out,
                                &job_out_size));
  EXPECT_EQ(strlen("AI computer"), job_out_size);
  EXPECT_STREQ("AI computer", job_out);

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_object_array(nullptr, "space_2001", &space_2001_out));
  EXPECT_FALSE(oc_rep_get_object_array(rep.get(), nullptr, &space_2001_out));
  EXPECT_FALSE(oc_rep_get_object_array(rep.get(), "", &space_2001_out));
  EXPECT_FALSE(oc_rep_get_object_array(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(),
    &space_2001_out));
  EXPECT_FALSE(oc_rep_get_object_array(rep.get(), "space_2001", nullptr));
  EXPECT_FALSE(
    oc_rep_get_object_array(rep.get(), "not_a_key", &space_2001_out));

  std::string json =
    R"({"space_2001":[{"name":"Dave Bowman","job":"astronaut"},)"
    R"({"name":"Frank Poole","job":"astronaut"},)"
    R"({"name":"Hal 9000","job":"AI computer"}]})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"space_2001\" : [\n"
                            "    {\n"
                            "      \"name\" : \"Dave Bowman\",\n"
                            "      \"job\" : \"astronaut\"\n    },\n"
                            "    {\n"
                            "      \"name\" : \"Frank Poole\",\n"
                            "      \"job\" : \"astronaut\"\n"
                            "    },\n"
                            "    {\n"
                            "      \"name\" : \"Hal 9000\",\n"
                            "      \"job\" : \"AI computer\"\n"
                            "    }]\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetEmptyStringArray)
{
  /*
    {
      "emptyStr": null,
    }
  */
  /* add values to root object */
  oc_rep_begin_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_string_array_t emptyStr{};
  oc_rep_set_string_array(root, emptyStr, emptyStr);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"emptyStr\":null}", false);
  CheckJson(rep.get(), "{\n  \"emptyStr\" : null\n}\n", true);
}

TEST_F(TestJsonRepWithPool, OCRepSetGetStringArray)
{
  /* Strings for testing
    Note: check STRING_ARRAY_ITEM_MAX_LEN for maximal allowed string item length
    in a string array.
  */
#ifdef OC_DYNAMIC_ALLOCATION
  std::string STR0 =
    "Do not take life too seriously. You will never get out of it alive.";
  std::string STR1 = "All generalizations are false, including this one.";
  std::string STR2 = "Those who believe in telekinetics, raise my hand.";
  std::string STR3 =
    "I refuse to join any club that would have me as a member.";
#else  /* !OC_DYNAMIC_ALLOCATION */
  std::string STR0 = "Do not take life too seriously.";
  std::string STR1 = "All generalizations are false.";
  std::string STR2 = "Raise my hand.";
  std::string STR3 = "I refuse to join any club.";
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_string_array_t quotes;
  oc_new_string_array(&quotes, static_cast<size_t>(4));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR0.c_str()));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR1.c_str()));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR2.c_str()));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR3.c_str()));
  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_string_array(root, quotes, quotes);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_free_string_array(&quotes);

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  oc_string_array_t quotes_out{};
  size_t quotes_len = 0;
  EXPECT_TRUE(
    oc_rep_get_string_array(rep.get(), "quotes", &quotes_out, &quotes_len));
  ASSERT_EQ(4, quotes_len);

  /* Error handling */
  EXPECT_FALSE(
    oc_rep_get_string_array(nullptr, "quotes", &quotes_out, &quotes_len));
  EXPECT_FALSE(
    oc_rep_get_string_array(rep.get(), nullptr, &quotes_out, &quotes_len));
  EXPECT_FALSE(
    oc_rep_get_string_array(rep.get(), "", &quotes_out, &quotes_len));
  EXPECT_FALSE(oc_rep_get_string_array(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &quotes_out,
    &quotes_len));
  EXPECT_FALSE(
    oc_rep_get_string_array(rep.get(), "quotes", nullptr, &quotes_len));
  EXPECT_FALSE(
    oc_rep_get_string_array(rep.get(), "quotes", &quotes_out, nullptr));

  EXPECT_EQ(STR0.length(), oc_string_array_get_item_size(quotes_out, 0));
  EXPECT_STREQ(STR0.c_str(), oc_string_array_get_item(quotes_out, 0));
  EXPECT_EQ(STR1.length(), oc_string_array_get_item_size(quotes_out, 1));
  EXPECT_STREQ(STR1.c_str(), oc_string_array_get_item(quotes_out, 1));
  EXPECT_EQ(STR2.length(), oc_string_array_get_item_size(quotes_out, 2));
  EXPECT_STREQ(STR2.c_str(), oc_string_array_get_item(quotes_out, 2));
  EXPECT_EQ(STR3.length(), oc_string_array_get_item_size(quotes_out, 3));
  EXPECT_STREQ(STR3.c_str(), oc_string_array_get_item(quotes_out, 3));

  // clang-format off
  std::string json = R"({"quotes":)"
                     R"([")" + STR0 + R"(",)"
                     R"(")" + STR1 + R"(",)"
                     R"(")" + STR2 + R"(",)"
                     R"(")" + STR3 + R"("]})";
  // clang-format on
  CheckJson(rep.get(), json, false);
  // clang-format off
  std::string pretty_json = "{\n"
                            "  \"quotes\" : [\n"
                            "    \"" + STR0 + "\",\n"
                            "    \"" + STR1 + "\",\n"
                            "    \"" + STR2 + "\",\n"
                            "    \"" + STR3 + "\"\n"
                            "  ]\n"
                            "}\n";
  // clang-format on
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepAddGetStringArray)
{
  /* Strings for testing
    Note: check STRING_ARRAY_ITEM_MAX_LEN for maximal allowed string item length
    in a string array.
  */
#ifdef OC_DYNAMIC_ALLOCATION
  std::string STR0 =
    "Do not take life too seriously. You will never get out of it alive.";
  std::string STR1 = "All generalizations are false, including this one.";
  std::string STR2 = "Those who believe in telekinetics, raise my hand.";
  std::string STR3 =
    "I refuse to join any club that would have me as a member.";
#else  /* !OC_DYNAMIC_ALLOCATION */
  std::string STR0 = "Do not take life too seriously.";
  std::string STR1 = "All generalizations are false.";
  std::string STR2 = "Raise my hand.";
  std::string STR3 = "I refuse to join any club.";
#endif /* OC_DYNAMIC_ALLOCATION */

  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_open_array(root, quotes);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR0.c_str());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR1.c_str());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR2.c_str());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR3.c_str());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_array(root, quotes);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  oc_string_array_t quotes_out{};
  size_t quotes_len = 0;
  EXPECT_TRUE(
    oc_rep_get_string_array(rep.get(), "quotes", &quotes_out, &quotes_len));
  ASSERT_EQ(4, quotes_len);

  EXPECT_EQ(STR0.length(), oc_string_array_get_item_size(quotes_out, 0));
  EXPECT_STREQ(STR0.c_str(), oc_string_array_get_item(quotes_out, 0));
  EXPECT_EQ(STR1.length(), oc_string_array_get_item_size(quotes_out, 1));
  EXPECT_STREQ(STR1.c_str(), oc_string_array_get_item(quotes_out, 1));
  EXPECT_EQ(STR2.length(), oc_string_array_get_item_size(quotes_out, 2));
  EXPECT_STREQ(STR2.c_str(), oc_string_array_get_item(quotes_out, 2));
  EXPECT_EQ(STR3.length(), oc_string_array_get_item_size(quotes_out, 3));
  EXPECT_STREQ(STR3.c_str(), oc_string_array_get_item(quotes_out, 3));

  // clang-format off
  std::string json = R"({"quotes":)"
                     R"([")" + STR0 + R"(",)"
                     R"(")" + STR1 + R"(",)"
                     R"(")" + STR2 + R"(",)"
                     R"(")" + STR3 + R"("]})";
  // clang-format on                      
  CheckJson(rep.get(), json, false);
  // clang-format off  
  std::string  pretty_json = "{\n"
                            "  \"quotes\" : [\n"
                            "    \"" + STR0 + "\",\n"
                            "    \"" + STR1 + "\",\n"
                            "    \"" + STR2 + "\",\n"
                            "    \"" + STR3 + "\"\n"
                            "  ]\n"
                            "}\n";
  // clang-format on
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestJsonRepWithPool, OCRepRootArrayObject)
{
  /*
   * create root object array
   * "[{"href":"/light/1","rep":{"state":true}},{"href":"/count/1","rep":{"count":100}}]"
   */
  /* add values to root object */
  oc_rep_start_links_array();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_start_item(links);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(links, href, "/light/1");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(links, rep);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(rep, state, true);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(links, rep);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(links);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_start_item(links);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(links, href, "/count/1");
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(links, rep);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(rep, count, 100);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(links, rep);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(links);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_links_array();

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  /* calling this an object_array is a bit of a misnomer internally it is a
   * linked list */
  EXPECT_EQ(0, oc_string_len(rep->name));
  EXPECT_EQ(OC_REP_OBJECT, rep->type);
  oc_rep_t *links = rep.get();
  ASSERT_TRUE(links != nullptr);

  char *href_out = nullptr;
  size_t href_out_size = 0;
  oc_rep_t *rep_out = nullptr;
  EXPECT_TRUE(
    oc_rep_get_string(links->value.object, "href", &href_out, &href_out_size));
  EXPECT_EQ(strlen("/light/1"), href_out_size);
  EXPECT_STREQ("/light/1", href_out);

  EXPECT_TRUE(oc_rep_get_object(links->value.object, "rep", &rep_out));
  ASSERT_TRUE(rep_out != nullptr);

  EXPECT_EQ(OC_REP_BOOL, rep_out->type);
  bool state_out = false;
  EXPECT_TRUE(oc_rep_get_bool(rep_out, "state", &state_out));
  EXPECT_TRUE(state_out);

  links = links->next;
  // "[{"href":"/light/1","rep":{"state":true}},{"href":"/count/1","rep":{"count":100}}]"
  EXPECT_TRUE(
    oc_rep_get_string(links->value.object, "href", &href_out, &href_out_size));
  EXPECT_EQ(strlen("/count/1"), href_out_size);
  EXPECT_STREQ("/count/1", href_out);

  EXPECT_TRUE(oc_rep_get_object(links->value.object, "rep", &rep_out));
  ASSERT_TRUE(rep_out != nullptr);

  EXPECT_EQ(OC_REP_INT, rep_out->type);
  int64_t count_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep_out, "count", &count_out));
  EXPECT_EQ(100, count_out);

  std::string json = R"([{"href":"/light/1","rep":{"state":true}},)"
                     R"({"href":"/count/1","rep":{"count":100}}])";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "[\n"
                            "  {\n"
                            "    \"href\" : \"/light/1\",\n"
                            "    \"rep\" : {\n"
                            "      \"state\" : true\n"
                            "    }\n"
                            "  },\n"
                            "  {\n"
                            "    \"href\" : \"/count/1\",\n"
                            "    \"rep\" : {\n"
                            "      \"count\" : 100\n    }\n"
                            "  }\n"
                            "]\n";
  CheckJson(rep.get(), pretty_json, true);
}

#if !defined(OC_SECURITY) || defined(OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM)

class TestJsonRepWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_rep_encoder_set_type(OC_REP_JSON_ENCODER);
    oc_rep_decoder_set_type(OC_REP_JSON_DECODER);

    oc_set_con_res_announced(true);
    ASSERT_TRUE(oc::TestDevice::StartServer());
#ifdef OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
    ASSERT_TRUE(oc::SetAccessInRFOTM(OCF_CON, kDeviceID, false,
                                     OC_PERM_RETRIEVE | OC_PERM_UPDATE));
#endif /* OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */
  }

  static void TearDownTestCase()
  {
    oc::TestDevice::StopServer();

    oc_rep_encoder_set_type(OC_REP_CBOR_ENCODER);
    oc_rep_decoder_set_type(OC_REP_CBOR_DECODER);
  }
};

TEST_F(TestJsonRepWithServer, EncodePostPayload)
{
  constexpr std::string_view kNewName = "IoTivity Test Server";

  auto epOpt = oc::TestDevice::GetEndpoint(kDeviceID);
  ASSERT_TRUE(epOpt.has_value());
  auto ep = std::move(*epOpt);

  auto post_handler = [](oc_client_response_t *data) {
    EXPECT_EQ(OC_STATUS_CHANGED, data->code);
    oc::TestDevice::Terminate();
    OC_DBG("POST payload: %s", oc::RepPool::GetJson(data->payload).data());
    *static_cast<bool *>(data->user_data) = true;
  };

  bool invoked = false;
  oc_init_post(OC_CON_URI, &ep, nullptr, post_handler, HIGH_QOS, &invoked);

  oc_rep_start_root_object();
  oc_rep_set_text_string_v1(root, n, kNewName.data(), kNewName.length());
  oc_rep_end_root_object();

  auto timeout = 1s;
  ASSERT_TRUE(oc_do_post_with_timeout(timeout.count()));

  oc::TestDevice::PoolEventsMsV1(timeout, true);
  ASSERT_TRUE(invoked);
}

#endif /* !OC_SECURITY || OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM */

#endif /* OC_JSON_ENCODER */

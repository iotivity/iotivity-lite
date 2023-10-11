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

#include "api/oc_con_resource_internal.h"
#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_encode_internal.h"
#include "oc_rep.h"
#include "port/oc_log_internal.h"
#include "tests/gtest/Device.h"
#include "tests/gtest/RepPool.h"
#include "tests/gtest/Resource.h"
#include "util/oc_secure_string_internal.h"

#include <array>
#include <chrono>
#include <gtest/gtest.h>
#include <memory>
#include <stdlib.h>
#include <string>
#include <vector>

using namespace std::chrono_literals;

static constexpr size_t kDeviceID{ 0 };
static const oc_rep_encoder_type_t g_rep_default_encoder =
  oc_rep_encoder_get_type();
static const oc_rep_decoder_type_t g_rep_default_decoder =
  oc_rep_decoder_get_type();

template<class InputIt>
static std::string
BufferToString(InputIt first, InputIt last)
{
  std::string val;
  for (; first != last; ++first) {
    val += static_cast<char>(*first);
  }
  return val;
}

class TestRep : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_rep_encoder_set_type(OC_REP_CBOR_ENCODER);
    oc_rep_decoder_set_type(OC_REP_CBOR_DECODER);
  }

  static void TearDownTestCase()
  {
    oc_rep_encoder_set_type(g_rep_default_encoder);
    oc_rep_decoder_set_type(g_rep_default_decoder);
  }
};

TEST_F(TestRep, OCRepEncodedPayloadSize_P)
{
  int repSize = oc_rep_get_encoded_payload_size();
  EXPECT_NE(repSize, -1);
}

TEST_F(TestRep, OCRepEncodedPayloadSizeTooSmall)
{
  /* buffer for oc_rep_t */
  std::array<uint8_t, 10> buf{}; // Purposely small buffer
  oc_rep_new_v1(buf.data(), buf.size());

  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, "hello", "world");
  EXPECT_EQ(CborErrorOutOfMemory, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborErrorOutOfMemory, oc_rep_get_cbor_errno());

  EXPECT_EQ(-1, oc_rep_get_encoded_payload_size());
}

TEST_F(TestRep, RepToJson_null)
{
  const oc_rep_t *rep = nullptr;
  EXPECT_EQ(2, oc_rep_to_json(rep, nullptr, 0, false));
  EXPECT_EQ(4, oc_rep_to_json(rep, nullptr, 0, true));

  std::array<char, 5> buffer;
  EXPECT_EQ(2, oc_rep_to_json(rep, buffer.data(), buffer.size(), false));
  EXPECT_STREQ("{}", buffer.data());

  EXPECT_EQ(4, oc_rep_to_json(rep, buffer.data(), buffer.size(), true));
  EXPECT_STREQ("{\n}\n", buffer.data());
}

class TestRepWithPool : public testing::Test {
public:
  static void SetUpTestCase()
  {
    oc_rep_encoder_set_type(OC_REP_CBOR_ENCODER);
    oc_rep_decoder_set_type(OC_REP_CBOR_DECODER);
  }

  static void TearDownTestCase()
  {
    oc_rep_encoder_set_type(g_rep_default_encoder);
    oc_rep_decoder_set_type(g_rep_default_decoder);
  }

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

/*
 * Most code done here is to enable testing without passing the code through the
 * framework. End users are not expected to call oc_rep_new, oc_rep_set_pool
 * and oc_parse_rep
 */
TEST_F(TestRepWithPool, OCRepInvalidFormat)
{
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_encode_int(&root_map, 42);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, oc_parse_rep(payload, payload_len, &rep));
  ASSERT_EQ(nullptr, rep);

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepInvalidArray)
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
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = nullptr;
  ASSERT_NE(CborNoError, oc_parse_rep(payload, payload_len, &rep));
  ASSERT_EQ(nullptr, rep);

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetNull)
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
  EXPECT_FALSE(oc_rep_is_null(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), "nothing", nullptr));
  EXPECT_FALSE(oc_rep_is_null(rep.get(), "not_the_key", &is_null));

  CheckJson(rep.get(), "{\"nothing\":null}", false);
  CheckJson(rep.get(), "{\n  \"nothing\" : null\n}\n", true);
}

TEST_F(TestRepWithPool, OCRepSetGetDouble)
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

  /* read values from  the oc_rep_t */
  double pi_out = 0;
  EXPECT_TRUE(oc_rep_get_double(rep.get(), "pi", &pi_out));
  EXPECT_EQ(3.14159, pi_out);

  /* error handling */
  EXPECT_FALSE(oc_rep_get_double(nullptr, "pi", &pi_out));
  EXPECT_FALSE(oc_rep_get_double(rep.get(), nullptr, &pi_out));
  EXPECT_FALSE(oc_rep_get_double(rep.get(), "", &pi_out));
  EXPECT_FALSE(oc_rep_get_double(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &pi_out));
  EXPECT_FALSE(oc_rep_get_double(rep.get(), "pi", nullptr));
  EXPECT_FALSE(oc_rep_get_double(rep.get(), "no_a_key", &pi_out));

  CheckJson(rep.get(), "{\"pi\":3.141590}", false);
  CheckJson(rep.get(), "{\n  \"pi\" : 3.141590\n}\n", true);
}

TEST_F(TestRepWithPool, OCRepSetGetInt)
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
  oc_rep_set_int(root, max_positive, INT64_MAX);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, max_negative, INT64_MIN);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
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
  EXPECT_EQ(INT64_MAX, max_positive_out);
  int64_t max_negative_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep.get(), "max_negative", &max_negative_out));
  EXPECT_EQ(INT64_MIN, max_negative_out);

  /* check error handling */
  EXPECT_FALSE(oc_rep_get_int(nullptr, "zero", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), nullptr, &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "zero", nullptr));
  EXPECT_FALSE(oc_rep_get_int(rep.get(), "not_a_key", &zero_out));

  std::string json =
    R"({"ultimate_answer":10000000000,"negative":-1024,"zero":0,"max_positive":9223372036854775807,"max_negative":-9223372036854775808})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"ultimate_answer\" : 10000000000,\n"
                            "  \"negative\" : -1024,\n"
                            "  \"zero\" : 0,\n"
                            "  \"max_positive\" : 9223372036854775807,\n"
                            "  \"max_negative\" : -9223372036854775808\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

/*
 * Working with uint is a little unusual there is a macro to set the uint type
 * but no function to get the uint type.  In addition the type uint is encoded
 * to use is OC_REP_INT. You can successfully pass a number larger than int but
 * must cast it to uint after reading from the value. This requires the client
 * to know that the service it encoding the uint with no over the wire
 * indication of the fact.
 *
 * Should there be a oc_rep_get_uint() function?
 * Should there be a OC_REP_UINT type?
 * Should the oc_rep_set_uint macro be removed?
 */
TEST_F(TestRepWithPool, OCRepSetGetUint)
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

/* why do we have set_boolean but get_bool shouldn't the function names match */
TEST_F(TestRepWithPool, OCRepSetGetBool)
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

/*
 * This test assumes text in this file is saved using a utf8 format. This is
 * generally a safe assumption since it is the default format use by git.
 *
 * If the test is run on a terminal that does not support utf8 it should still
 * pass the tests.  However, if the test should fail the printed error may be
 * gibberish when read from the terminal. Only place this is a known problem
 * is Windows CMD terminal.
 *
 * TODO Is there a max string length? If so consider adding test that equals and
 * exceeds max sting length.
 */
TEST_F(TestRepWithPool, OCRepSetGetTextString)
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

/*
 * TODO is there a max byte array length? If so consider adding a test that
 * equals and exceeds the max array length.
 */
TEST_F(TestRepWithPool, OCRepSetGetByteString)
{
  /* add text string value "hal9000":"Dave" to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_byte_string(root, empty_byte_string, nullptr, 0);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  const uint8_t test_byte_string[] = { 0x01, 0x02, 0x03, 0x04, 0x02, 0x00 };
  oc_rep_set_byte_string(root, test_byte_string, test_byte_string,
                         sizeof(test_byte_string));
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  size_t str_len;
  char *empty_byte_string_out = nullptr;
  EXPECT_TRUE(oc_rep_get_byte_string(rep.get(), "empty_byte_string",
                                     &empty_byte_string_out, &str_len));
  EXPECT_EQ(0, str_len);
  char *test_byte_string_out = nullptr;
  EXPECT_TRUE(oc_rep_get_byte_string(rep.get(), "test_byte_string",
                                     &test_byte_string_out, &str_len));
  EXPECT_EQ(6, str_len);
  /*
   * cast the array and use STREQ to compare this only works because the
   * test_byte_string was null terminated other wise we would have to loop
   * through the array.
   */
  EXPECT_STREQ((const char *)test_byte_string, test_byte_string_out);

  /* error handling */
  EXPECT_FALSE(oc_rep_get_byte_string(nullptr, "test_byte_string",
                                      &test_byte_string_out, &str_len));
  EXPECT_FALSE(oc_rep_get_byte_string(rep.get(), nullptr, &test_byte_string_out,
                                      &str_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string(rep.get(), "", &test_byte_string_out, &str_len));
  EXPECT_FALSE(oc_rep_get_byte_string(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(),
    &test_byte_string_out, &str_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string(rep.get(), "test_byte_string", nullptr, &str_len));
  EXPECT_FALSE(oc_rep_get_byte_string(rep.get(), "test_byte_string",
                                      &test_byte_string_out, nullptr));
  EXPECT_FALSE(oc_rep_get_byte_string(rep.get(), "not_a_key",
                                      &test_byte_string_out, &str_len));

  std::string json =
    R"({"empty_byte_string":"","test_byte_string":"AQIDBAIA"})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"empty_byte_string\" : \"\",\n"
                            "  \"test_byte_string\" : \"AQIDBAIA\"\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);

  EXPECT_LT(25, oc_rep_to_json(rep.get(), nullptr, 0, false));
  std::array<char, 25> too_small;
  EXPECT_LT(too_small.size(), oc_rep_to_json(rep.get(), too_small.data(),
                                             too_small.size(), false));
  // Decoding of byte string is an all or nothing action. Since there
  // is not enough room in the too_small output buffer nothing is placed in the
  // buffer and remaining space is left empty.
  std::string too_small_json = R"({"empty_byte_string":"",)";
  EXPECT_STREQ(too_small_json.c_str(), too_small.data());
}

TEST_F(TestRepWithPool, OCRepSetGetEmptyIntArray)
{
  /*
    {
      "emptyInt": null,
    }
  */
  /* add values to root object */
  oc_rep_start_root_object();
  oc_rep_set_int_array(root, emptyInt, (int64_t *)nullptr, 0);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"emptyInt\":null}", false);
  CheckJson(rep.get(), "{\n  \"emptyInt\" : null\n}\n", true);
}

TEST_F(TestRepWithPool, OCRepSetGetIntArray)
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
  size_t fib_len = 0;
  EXPECT_TRUE(oc_rep_get_int_array(rep.get(), "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(fib.size(), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_int_array(nullptr, "fibonacci", &fib_out, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep.get(), nullptr, &fib_out, &fib_len));
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

/*
 * This test uses oc_rep_add_int to build the cbor array instead of
 * oc_rep_set_int_array
 */
TEST_F(TestRepWithPool, OCRepAddGetIntArray)
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

/*
 * This test uses oc_rep_add_int to build the cbor array instead of
 * oc_rep_set_int_array
 */
TEST_F(TestRepWithPool, OCRepAddGetIntArrayUsingSetKeyAndBeginArray)
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

TEST_F(TestRepWithPool, OCRepSetGetEmptyBoolArray)
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

TEST_F(TestRepWithPool, OCRepSetGetBoolArray)
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
  size_t flip_len = 0;
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

/*
 * Test the oc_rep_add_boolean to build a boolean array instead of
 * oc_rep_set_array
 */
TEST_F(TestRepWithPool, OCRepAddGetBoolArray)
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

TEST_F(TestRepWithPool, OCRepSetGetEmptyDoubleArray)
{
  /*
    {
      "emptyDouble": null,
    }
  */
  /* add values to root object */
  oc_rep_start_root_object();
  oc_rep_set_double_array(root, emptyDouble, (double *)nullptr, 0);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  CheckJson(rep.get(), "{\"emptyDouble\":null}", false);
  CheckJson(rep.get(), "{\n  \"emptyDouble\" : null\n}\n", true);
}

TEST_F(TestRepWithPool, OCRepSetGetDoubleArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<double> math_constants = { 3.14159, 2.71828, 1.414121, 1.61803 };
  oc_rep_set_double_array(root, math_constants, math_constants.data(),
                          math_constants.size());
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  double *math_constants_out = nullptr;
  size_t math_constants_len;
  EXPECT_TRUE(oc_rep_get_double_array(
    rep.get(), "math_constants", &math_constants_out, &math_constants_len));
  ASSERT_EQ(math_constants.size(), math_constants_len);
  for (size_t i = 0; i < math_constants_len; ++i) {
    EXPECT_EQ(math_constants[i], math_constants_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_double_array(
    nullptr, "math_constants", &math_constants_out, &math_constants_len));
  EXPECT_FALSE(oc_rep_get_double_array(rep.get(), nullptr, &math_constants_out,
                                       &math_constants_len));
  EXPECT_FALSE(oc_rep_get_double_array(rep.get(), "math_constants", nullptr,
                                       &math_constants_len));
  EXPECT_FALSE(oc_rep_get_double_array(rep.get(), "math_constants",
                                       &math_constants_out, nullptr));
  EXPECT_FALSE(oc_rep_get_double_array(
    rep.get(), "not_a_key", &math_constants_out, &math_constants_len));

  std::string json =
    "{\"math_constants\":[3.141590,2.718280,1.414121,1.618030]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json =
    "{\n"
    "  \"math_constants\" : [3.141590, 2.718280, 1.414121, 1.618030]\n"
    "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

/*
 * Build Double Array using oc_rep_add_double instead of oc_rep_set_double
 */
TEST_F(TestRepWithPool, OCRepAddGetDoubleArray)
{
  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  std::vector<double> math_constants = { 3.14159, 2.71828, 1.414121, 1.61803 };
  oc_rep_open_array(root, math_constants);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (const auto &v : math_constants) {
    oc_rep_add_double(math_constants, v);
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_close_array(root, math_constants);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  double *math_constants_out = nullptr;
  size_t math_constants_len;
  EXPECT_TRUE(oc_rep_get_double_array(
    rep.get(), "math_constants", &math_constants_out, &math_constants_len));
  ASSERT_EQ(math_constants.size(), math_constants_len);
  for (size_t i = 0; i < math_constants_len; ++i) {
    EXPECT_EQ(math_constants[i], math_constants_out[i]);
  }

  std::string json =
    "{\"math_constants\":[3.141590,2.718280,1.414121,1.618030]}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json =
    "{\n"
    "  \"math_constants\" : [3.141590, 2.718280, 1.414121, 1.618030]\n"
    "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestRepWithPool, OCRepSetGetEmptyObject)
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

TEST_F(TestRepWithPool, OCRepSetGetObject)
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

#ifndef OC_DYNAMIC_ALLOCATION

static int
oc_rep_encode_tagged_string(CborEncoder *encoder, CborTag tag,
                            const std::string &key, const std::string &value)
{
  oc_rep_encoder_convert_offset_to_ptr(oc_rep_global_encoder(), encoder);
  int err = cbor_encode_text_string(encoder, key.c_str(), key.length());
  err |= cbor_encode_tag(encoder, tag);
  err |= cbor_encode_text_string(encoder, value.c_str(), value.length());
  oc_rep_encoder_convert_ptr_to_offset(oc_rep_global_encoder(), encoder);
  return err;
}

TEST_F(TestRepWithPool, OCRepSetGetObjectWithTag)
{
  /*
   * {
   *   "tagged_url": {
   *     "url": "iotivity.org"
   *   }
   * }
   */
  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(root, tagged_url);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  EXPECT_EQ(CborNoError,
            oc_rep_encode_tagged_string(oc_rep_object(tagged_url), CborUrlTag,
                                        "url", "iotivity.org"));
  oc_rep_close_object(root, tagged_url);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  std::string json = "{\"tagged_url\":{\"url\":\"iotivity.org\"}}";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"tagged_url\" : {\n"
                            "    \"url\" : \"iotivity.org\"\n"
                            "  }\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

#endif /* !OC_DYNAMIC_ALLOCATION  */

TEST_F(TestRepWithPool, OCRepSetGetEmptyObjectArray)
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

TEST_F(TestRepWithPool, OCRepSetGetObjectArray)
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

TEST_F(TestRepWithPool, OCRepAddGetByteStringArray)
{
  /* jagged arrays for testing */
  std::vector<uint8_t> ba1 = { 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
  std::vector<uint8_t> ba2 = { 0x01, 0x01, 0x02, 0x03, 0x05, 0x08,
                               0x13, 0x21, 0x34, 0x55, 0x89 };
  std::vector<uint8_t> ba3 = { 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                               0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
                               0x42, 0x42, 0x42, 0x42, 0x42, 0x42 };
  // at lease on byte array not nul terminated.
  std::vector<uint8_t> ba4 = { 0x00, 0x00, 0xff, 0x00, 0x00 };

  /* add values to root object */
  oc_rep_start_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_array(root, barray);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba1.data(), ba1.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba2.data(), ba2.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba3.data(), ba3.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba4.data(), ba4.size());
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_array(root, barray);
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  ASSERT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  oc::oc_rep_unique_ptr rep = ParsePayload();
  ASSERT_NE(nullptr, rep.get());

  /* read the values from the oc_rep_t */
  oc_string_array_t barray_out;
  size_t barray_len;
  EXPECT_TRUE(oc_rep_get_byte_string_array(rep.get(), "barray", &barray_out,
                                           &barray_len));
  ASSERT_EQ(4, barray_len);

  /* Error handling */
  EXPECT_FALSE(
    oc_rep_get_byte_string_array(nullptr, "barray", &barray_out, &barray_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string_array(rep.get(), nullptr, &barray_out, &barray_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string_array(rep.get(), "", &barray_out, &barray_len));
  EXPECT_FALSE(oc_rep_get_byte_string_array(
    rep.get(), std::string(OC_MAX_STRING_LENGTH, 'k').c_str(), &barray_out,
    &barray_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string_array(rep.get(), "barray", nullptr, &barray_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string_array(rep.get(), "barray", &barray_out, nullptr));

  EXPECT_EQ(ba1.size(), oc_byte_string_array_get_item_size(barray_out, 0));
  EXPECT_EQ(memcmp(ba1.data(), oc_byte_string_array_get_item(barray_out, 0),
                   oc_byte_string_array_get_item_size(barray_out, 0)),
            0);
  EXPECT_EQ(ba2.size(), oc_byte_string_array_get_item_size(barray_out, 1));
  EXPECT_EQ(memcmp(ba2.data(), oc_byte_string_array_get_item(barray_out, 1),
                   oc_byte_string_array_get_item_size(barray_out, 1)),
            0);
  EXPECT_EQ(ba3.size(), oc_byte_string_array_get_item_size(barray_out, 2));
  EXPECT_EQ(memcmp(ba3.data(), oc_byte_string_array_get_item(barray_out, 2),
                   oc_byte_string_array_get_item_size(barray_out, 2)),
            0);
  EXPECT_EQ(ba4.size(), oc_byte_string_array_get_item_size(barray_out, 3));
  EXPECT_EQ(memcmp(ba4.data(), oc_byte_string_array_get_item(barray_out, 3),
                   oc_byte_string_array_get_item_size(barray_out, 3)),
            0);

  std::string json =
    R"({"barray":["AQECAwQFBg==",)"
    R"("AQECAwUIEyE0VYk=","QkJCQkJCQkJCQkJCQkJCQkJCQkI=","AAD/AAA="]})";
  CheckJson(rep.get(), json, false);
  std::string pretty_json = "{\n"
                            "  \"barray\" : [\n"
                            "    \"AQECAwQFBg==\",\n"
                            "    \"AQECAwUIEyE0VYk=\",\n"
                            "    \"QkJCQkJCQkJCQkJCQkJCQkJCQkI=\",\n"
                            "    \"AAD/AAA=\"\n"
                            "  ]\n"
                            "}\n";
  CheckJson(rep.get(), pretty_json, true);
}

TEST_F(TestRepWithPool, OCRepSetGetEmptyStringArray)
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

/* use oc_rep_set_string_array to build the string array. */
TEST_F(TestRepWithPool, OCRepSetGetStringArray)
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

/* use oc_rep_add_text_string to build string array */
TEST_F(TestRepWithPool, OCRepAddGetStringArray)
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

TEST_F(TestRepWithPool, OCRepRootArrayObject)
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

class TestRepWithServer : public testing::Test {
public:
  static void SetUpTestCase()
  {
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
  }
};

TEST_F(TestRepWithServer, EncodePostPayload)
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

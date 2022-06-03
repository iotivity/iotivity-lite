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

#include "gtest/gtest.h"
#include <stdlib.h>

#include "oc_rep.h"

class TestRepWithPool : public testing::Test {
protected:
  void SetUp() override
  {
#ifndef OC_DYNAMIC_ALLOCATION
    memset(rep_objects_alloc, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(char));
    memset(rep_objects_pool, 0, OC_MAX_NUM_REP_OBJECTS * sizeof(oc_rep_t));
#endif
  }
  void TearDown() override {}

public:
  oc_memb *GetRepObjectsPool();

private:
#ifdef OC_DYNAMIC_ALLOCATION
  oc_memb rep_objects{ sizeof(oc_rep_t), 0, 0, 0, 0 };
#else
  char rep_objects_alloc[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool[OC_MAX_NUM_REP_OBJECTS];
  oc_memb rep_objects{ sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                       rep_objects_alloc, (void *)rep_objects_pool, 0 };
#endif
};

oc_memb *
TestRepWithPool::GetRepObjectsPool()
{
  return &rep_objects;
}

TEST(TestRep, OCRepEncodedPayloadSize_P)
{
  int repSize = oc_rep_get_encoded_payload_size();
  EXPECT_NE(repSize, -1);
}

TEST(TestRep, OCRepEncodedPayloadSizeTooSmall)
{
  /* buffer for oc_rep_t */
  uint8_t buf[10]; // Purposely small buffer
  oc_rep_new(&buf[0], 10);

  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, "hello", "world");
  EXPECT_EQ(CborErrorOutOfMemory, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborErrorOutOfMemory, oc_rep_get_cbor_errno());

  EXPECT_EQ(-1, oc_rep_get_encoded_payload_size());
}

TEST(TestRep, RepToJson_null)
{
  oc_rep_t *rep = NULL;
  EXPECT_EQ(2, oc_rep_to_json(rep, NULL, 0, false));
  EXPECT_EQ(4, oc_rep_to_json(rep, NULL, 0, true));
  char buf[5];
  EXPECT_EQ(2, oc_rep_to_json(rep, buf, 5, false));
  EXPECT_STREQ("{}", buf);
  EXPECT_EQ(4, oc_rep_to_json(rep, buf, 5, true));
  EXPECT_STREQ("{\n}\n", buf);
}

/*
 * Most code done here is to enable testing without passing the code through the
 * framework. End users are not expected to call oc_rep_new, oc_rep_set_pool
 * and oc_parse_rep
 */
TEST_F(TestRepWithPool, OCRepSetGetNull)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add null value to root object */
  oc_rep_start_root_object();
  oc_rep_set_null(root, nothing);
  oc_rep_end_root_object();

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  bool is_null = false;
  EXPECT_TRUE(oc_rep_is_null(rep, "nothing", &is_null));
  EXPECT_TRUE(is_null);
  /* error handling */
  EXPECT_FALSE(oc_rep_is_null(NULL, "nothing", &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep, NULL, &is_null));
  EXPECT_FALSE(oc_rep_is_null(rep, "nothing", NULL));
  EXPECT_FALSE(oc_rep_is_null(rep, "not_the_key", &is_null));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  EXPECT_STREQ("{\"nothing\":null}", json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  EXPECT_STREQ("{\n  \"nothing\" : null\n}\n", json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetDouble)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add int values to root object */
  oc_rep_start_root_object();
  oc_rep_set_double(root, pi, 3.14159);
  oc_rep_end_root_object();

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read values from  the oc_rep_t */
  double pi_out = 0;
  EXPECT_TRUE(oc_rep_get_double(rep, "pi", &pi_out));
  EXPECT_EQ(3.14159, pi_out);
  /* error handling */
  EXPECT_FALSE(oc_rep_get_double(NULL, "pi", &pi_out));
  EXPECT_FALSE(oc_rep_get_double(rep, NULL, &pi_out));
  EXPECT_FALSE(oc_rep_get_double(rep, "pi", NULL));
  EXPECT_FALSE(oc_rep_get_double(rep, "no_a_key", &pi_out));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  EXPECT_STREQ("{\"pi\":3.141590}", json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  EXPECT_STREQ("{\n  \"pi\" : 3.141590\n}\n", json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetInt)
{

  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, ultimate_answer, 10000000000);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, negative, -1024);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, zero, 0);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from  the oc_rep_t */
  int64_t ultimate_answer_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep, "ultimate_answer", &ultimate_answer_out));
  EXPECT_EQ(10000000000, ultimate_answer_out);
  int64_t negative_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep, "negative", &negative_out));
  EXPECT_EQ(-1024, negative_out);
  int64_t zero_out = -1;
  EXPECT_TRUE(oc_rep_get_int(rep, "zero", &zero_out));
  EXPECT_EQ(0, zero_out);
  /* check error handling */
  EXPECT_FALSE(oc_rep_get_int(NULL, "zero", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep, NULL, &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep, "zero", NULL));
  EXPECT_FALSE(oc_rep_get_int(rep, "not_a_key", &zero_out));

  char json_buf[75];
  EXPECT_EQ(57, oc_rep_to_json(rep, json_buf, 75, false));
  EXPECT_STREQ(
    "{\"ultimate_answer\":10000000000,\"negative\":-1024,\"zero\":0}",
    json_buf);
  const char json[] = "{\n"
                      "  \"ultimate_answer\" : 10000000000,\n"
                      "  \"negative\" : -1024,\n"
                      "  \"zero\" : 0\n"
                      "}\n";
  EXPECT_EQ(74, oc_rep_to_json(rep, json_buf, 75, true));
  EXPECT_STREQ(json, json_buf);

  oc_free_rep(rep);
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
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_uint(root, ultimate_answer, 42);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  /*
   * Assuming 32 bit int, which should be true for systems the gtest will
   * be running on, the largest value for 32 bit int is 2,147,483,647 or
   * 0x7FFFFFFF
   */
  oc_rep_set_uint(root, larger_than_int, 3000000000);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_uint(root, zero, 0);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from  the oc_rep_t */
  EXPECT_EQ(OC_REP_INT, rep->type);
  int64_t ultimate_answer_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep, "ultimate_answer", &ultimate_answer_out));
  EXPECT_EQ(42u, (unsigned)ultimate_answer_out);
  int64_t larger_than_int_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep, "larger_than_int", &larger_than_int_out));
  EXPECT_EQ(3000000000u, (unsigned)larger_than_int_out);
  int64_t zero_out = -1;
  EXPECT_TRUE(oc_rep_get_int(rep, "zero", &zero_out));
  EXPECT_EQ(0u, (unsigned)zero_out);
  /* check error handling */
  EXPECT_FALSE(oc_rep_get_int(NULL, "zero", &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep, NULL, &zero_out));
  EXPECT_FALSE(oc_rep_get_int(rep, "zero", NULL));
  EXPECT_FALSE(oc_rep_get_int(rep, "not_a_key", &zero_out));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  EXPECT_STREQ(
    "{\"ultimate_answer\":42,\"larger_than_int\":3000000000,\"zero\":0}", json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"ultimate_answer\" : 42,\n"
                             "  \"larger_than_int\" : 3000000000,\n"
                             "  \"zero\" : 0\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/* why do we have set_boolean but get_bool shouldn't the function names match */
TEST_F(TestRepWithPool, OCRepSetGetBool)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(root, true_flag, true);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(root, false_flag, false);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the ultimate_answer from  the oc_rep_t */
  bool true_flag_out = false;
  EXPECT_TRUE(oc_rep_get_bool(rep, "true_flag", &true_flag_out));
  EXPECT_TRUE(true_flag_out);
  bool false_flag_out = true;
  EXPECT_TRUE(oc_rep_get_bool(rep, "false_flag", &false_flag_out));
  EXPECT_FALSE(false_flag_out);
  /* check error handling */
  EXPECT_FALSE(oc_rep_get_bool(NULL, "true_flag", &true_flag_out));
  EXPECT_FALSE(oc_rep_get_bool(rep, NULL, &true_flag_out));
  EXPECT_FALSE(oc_rep_get_bool(rep, "true_flag", NULL));
  EXPECT_FALSE(oc_rep_get_bool(rep, "not_a_key", &true_flag_out));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"true_flag\":true,\"false_flag\":false}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"true_flag\" : true,\n"
                             "  \"false_flag\" : false\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
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
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add text string value "hal9000":"Dave" to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, hal9000, "Dave");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  /* test utf8 character support "hello world" in russian */
  oc_rep_set_text_string(root, ru_character_set, "Привет, мир");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the hal9000 from  the oc_rep_t */
  char *hal9000_out = NULL;
  size_t str_len;
  EXPECT_TRUE(oc_rep_get_string(rep, "hal9000", &hal9000_out, &str_len));
  EXPECT_STREQ("Dave", hal9000_out);
  EXPECT_EQ(4, str_len);
  char *ru_character_set_out = NULL;
  EXPECT_TRUE(oc_rep_get_string(rep, "ru_character_set", &ru_character_set_out,
                                &str_len));
  EXPECT_STREQ("Привет, мир", ru_character_set_out);
  /*
   * to encode Привет, мир takes more bytes than the number of characters so
   * calculate the the number of bytes using the strlen function.
   */
  EXPECT_EQ(strlen("Привет, мир"), str_len);
  /* check error handling */
  EXPECT_FALSE(oc_rep_get_string(NULL, "hal9000", &hal9000_out, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep, NULL, &hal9000_out, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep, "hal9000", NULL, &str_len));
  EXPECT_FALSE(oc_rep_get_string(rep, "hal9000", &hal9000_out, NULL));
  EXPECT_FALSE(oc_rep_get_string(rep, "not_a_key", &hal9000_out, &str_len));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"hal9000\":\"Dave\","
                                 "\"ru_character_set\":\"Привет, мир\"}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"hal9000\" : \"Dave\",\n"
                             "  \"ru_character_set\" : \"Привет, мир\"\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/*
 * TODO is there a max byte array length? If so consider adding a test that
 * equals and exceeds the max array length.
 */
TEST_F(TestRepWithPool, OCRepSetGetByteString)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add text string value "hal9000":"Dave" to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  const uint8_t test_byte_string[] = { 0x01, 0x02, 0x03, 0x04, 0x02, 0x00 };
  oc_rep_set_byte_string(root, test_byte_string, test_byte_string, 6u);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  char *test_byte_string_out = NULL;
  size_t str_len;
  EXPECT_TRUE(oc_rep_get_byte_string(rep, "test_byte_string",
                                     &test_byte_string_out, &str_len));
  EXPECT_EQ(6, str_len);
  /*
   * cast the array and use STREQ to compare this only works because the
   * test_byte_string was nul terminated other wise we would have to loop
   * through the array.
   */
  EXPECT_STREQ((const char *)test_byte_string, test_byte_string_out);
  /* error handling */
  EXPECT_FALSE(oc_rep_get_byte_string(NULL, "test_byte_string",
                                      &test_byte_string_out, &str_len));
  EXPECT_FALSE(
    oc_rep_get_byte_string(rep, NULL, &test_byte_string_out, &str_len));
  EXPECT_FALSE(oc_rep_get_byte_string(rep, "test_byte_string", NULL, &str_len));
  EXPECT_FALSE(oc_rep_get_byte_string(rep, "test_byte_string",
                                      &test_byte_string_out, NULL));
  EXPECT_FALSE(
    oc_rep_get_byte_string(rep, "not_a_key", &test_byte_string_out, &str_len));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"test_byte_string\":\"AQIDBAIA\"}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"test_byte_string\" : \"AQIDBAIA\"\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  EXPECT_LT(28, oc_rep_to_json(rep, NULL, 0, false));
  char too_small[28];
  EXPECT_LT(28, oc_rep_to_json(rep, too_small, sizeof(too_small), false));
  // Decoding of byte string is an all or nothing action. Since there
  // is not enough room in the too_small output buffer nothing is placed in the
  // buffer and remaining space is left empty.
  const char too_small_json[] = "{\"test_byte_string\":\"";
  EXPECT_STREQ(too_small_json, too_small);
  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetIntArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  int64_t fib[] = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 10000000000 };
  oc_rep_set_int_array(root, fibonacci, fib,
                       (int)(sizeof(fib) / sizeof(fib[0])));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  int64_t *fib_out = 0;
  size_t fib_len;
  EXPECT_TRUE(oc_rep_get_int_array(rep, "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(sizeof(fib) / sizeof(fib[0]), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_int_array(NULL, "fibonacci", &fib_out, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep, NULL, &fib_out, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep, "fibonacci", NULL, &fib_len));
  EXPECT_FALSE(oc_rep_get_int_array(rep, "fibonacci", &fib_out, NULL));
  EXPECT_FALSE(oc_rep_get_int_array(rep, "not_a_key", &fib_out, &fib_len));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89,10000000000]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] =
    "{\n"
    "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 10000000000]\n"
    "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/*
 * This test uses oc_rep_add_int to build the cbor array instead of
 * oc_rep_set_int_array
 */
TEST_F(TestRepWithPool, OCRepAddGetIntArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  int64_t fib[] = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };

  oc_rep_open_array(root, fibonacci);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (size_t i = 0; i < (sizeof(fib) / sizeof(fib[0])); i++) {
    oc_rep_add_int(fibonacci, fib[i]);
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_close_array(root, fibonacci);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  int64_t *fib_out = 0;
  size_t fib_len;
  EXPECT_TRUE(oc_rep_get_int_array(rep, "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(sizeof(fib) / sizeof(fib[0]), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] =
    "{\n"
    "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]\n"
    "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/*
 * This test uses oc_rep_add_int to build the cbor array instead of
 * oc_rep_set_int_array
 */
TEST_F(TestRepWithPool, OCRepAddGetIntArrayUsingSetKeyAndBeginArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  int64_t fib[] = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };

  oc_rep_set_key(oc_rep_object(root), "fibonacci");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_begin_array(oc_rep_object(root), fibonacci);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (size_t i = 0; i < (sizeof(fib) / sizeof(fib[0])); i++) {
    oc_rep_add_int(fibonacci, fib[i]);
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_end_array(oc_rep_object(root), fibonacci);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  int64_t *fib_out = 0;
  size_t fib_len;
  EXPECT_TRUE(oc_rep_get_int_array(rep, "fibonacci", &fib_out, &fib_len));
  ASSERT_EQ(sizeof(fib) / sizeof(fib[0]), fib_len);
  for (size_t i = 0; i < fib_len; ++i) {
    EXPECT_EQ(fib[i], fib_out[i]);
  }

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"fibonacci\":[1,1,2,3,5,8,13,21,34,55,89]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] =
    "{\n"
    "  \"fibonacci\" : [1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89]\n"
    "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetBoolArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  bool flip[] = { false, false, true, false, false };
  oc_rep_set_bool_array(root, flip, flip,
                        (int)(sizeof(flip) / sizeof(flip[0])));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  bool *flip_out = 0;
  size_t flip_len;
  EXPECT_TRUE(oc_rep_get_bool_array(rep, "flip", &flip_out, &flip_len));
  ASSERT_EQ(sizeof(flip) / sizeof(flip[0]), flip_len);
  for (size_t i = 0; i < flip_len; ++i) {
    EXPECT_EQ(flip[i], flip_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_bool_array(NULL, "flip", &flip_out, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep, NULL, &flip_out, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep, "flip", NULL, &flip_len));
  EXPECT_FALSE(oc_rep_get_bool_array(rep, "flip", &flip_out, NULL));
  EXPECT_FALSE(oc_rep_get_bool_array(rep, "not_a_key", &flip_out, &flip_len));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"flip\":[false,false,true,false,false]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"flip\" : [false, false, true, false, false]\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/*
 * Test the oc_rep_add_boolean to build a boolean array instead of
 * oc_rep_set_array
 */
TEST_F(TestRepWithPool, OCRepAddGetBoolArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  bool flip[] = { false, false, true, false, false };

  oc_rep_open_array(root, flip);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (size_t i = 0; i < (sizeof(flip) / sizeof(flip[0])); i++) {
    oc_rep_add_boolean(flip, flip[i]);
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_close_array(root, flip);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  bool *flip_out = 0;
  size_t flip_len;
  EXPECT_TRUE(oc_rep_get_bool_array(rep, "flip", &flip_out, &flip_len));
  ASSERT_EQ(sizeof(flip) / sizeof(flip[0]), flip_len);
  for (size_t i = 0; i < flip_len; ++i) {
    EXPECT_EQ(flip[i], flip_out[i]);
  }

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"flip\":[false,false,true,false,false]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"flip\" : [false, false, true, false, false]\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetDoubleArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  double math_constants[] = { 3.14159, 2.71828, 1.414121, 1.61803 };
  oc_rep_set_double_array(
    root, math_constants, math_constants,
    (int)(sizeof(math_constants) / sizeof(math_constants[0])));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  double *math_constants_out = 0;
  size_t math_constants_len;
  EXPECT_TRUE(oc_rep_get_double_array(
    rep, "math_constants", &math_constants_out, &math_constants_len));
  ASSERT_EQ(sizeof(math_constants) / sizeof(math_constants[0]),
            math_constants_len);
  for (size_t i = 0; i < math_constants_len; ++i) {
    EXPECT_EQ(math_constants[i], math_constants_out[i]);
  }

  /* Error handling */
  EXPECT_FALSE(oc_rep_get_double_array(
    NULL, "math_constants", &math_constants_out, &math_constants_len));
  EXPECT_FALSE(oc_rep_get_double_array(rep, NULL, &math_constants_out,
                                       &math_constants_len));
  EXPECT_FALSE(
    oc_rep_get_double_array(rep, "math_constants", NULL, &math_constants_len));
  EXPECT_FALSE(
    oc_rep_get_double_array(rep, "math_constants", &math_constants_out, NULL));
  EXPECT_FALSE(oc_rep_get_double_array(rep, "not_a_key", &math_constants_out,
                                       &math_constants_len));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "{\"math_constants\":[3.141590,2.718280,1.414121,1.618030]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] =
    "{\n"
    "  \"math_constants\" : [3.141590, 2.718280, 1.414121, 1.618030]\n"
    "}\n";

  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/*
 * Build Double Array using oc_rep_add_double instead of oc_rep_set_double
 */
TEST_F(TestRepWithPool, OCRepAddGetDoubleArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  double math_constants[] = { 3.14159, 2.71828, 1.414121, 1.61803 };
  oc_rep_open_array(root, math_constants);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (size_t i = 0; i < (sizeof(math_constants) / sizeof(math_constants[0]));
       i++) {
    oc_rep_add_double(math_constants, math_constants[i]);
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_close_array(root, math_constants);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  double *math_constants_out = 0;
  size_t math_constants_len;
  EXPECT_TRUE(oc_rep_get_double_array(
    rep, "math_constants", &math_constants_out, &math_constants_len));
  ASSERT_EQ(sizeof(math_constants) / sizeof(math_constants[0]),
            math_constants_len);
  for (size_t i = 0; i < math_constants_len; ++i) {
    EXPECT_EQ(math_constants[i], math_constants_out[i]);
  }

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "{\"math_constants\":[3.141590,2.718280,1.414121,1.618030]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] =
    "{\n"
    "  \"math_constants\" : [3.141590, 2.718280, 1.414121, 1.618030]\n"
    "}\n";

  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetObject)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

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
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(root, my_object);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(my_object, a, 1);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(my_object, b, false);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(my_object, c, "three");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(root, my_object);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  oc_rep_t *my_object_out = NULL;
  EXPECT_TRUE(oc_rep_get_object(rep, "my_object", &my_object_out));
  ASSERT_TRUE(my_object_out != NULL);
  int64_t a_out;
  EXPECT_TRUE(oc_rep_get_int(my_object_out, "a", &a_out));
  EXPECT_EQ(1, a_out);
  bool b_out = true;
  EXPECT_TRUE(oc_rep_get_bool(my_object_out, "b", &b_out));
  EXPECT_FALSE(b_out);
  char *c_out = NULL;
  size_t c_out_size = 0;
  EXPECT_TRUE(oc_rep_get_string(my_object_out, "c", &c_out, &c_out_size));
  EXPECT_EQ(5, c_out_size);
  EXPECT_STREQ("three", c_out);

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "{\"my_object\":{\"a\":1,\"b\":false,\"c\":\"three\"}}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"my_object\" : {\n"
                             "    \"a\" : 1,\n"
                             "    \"b\" : false,\n"
                             "    \"c\" : \"three\"\n"
                             "  }\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepSetGetObjectArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

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
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_array(root, space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_object_array_start_item(space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, name, "Dave Bowman");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, job, "astronaut");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_object_array_start_item(space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, name, "Frank Poole");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, job, "astronaut");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_object_array_start_item(space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, name, "Hal 9000");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(space_2001, job, "AI computer");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  oc_rep_close_array(root, space_2001);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  /* calling this an object_array is a bit of a misnomer internally it is a
   * linked list */
  oc_rep_t *space_2001_out = NULL;
  EXPECT_TRUE(oc_rep_get_object_array(rep, "space_2001", &space_2001_out));
  ASSERT_TRUE(space_2001_out != NULL);

  char *name_out = NULL;
  size_t name_out_size = 0;

  char *job_out = NULL;
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
  ASSERT_TRUE(space_2001_out != NULL);
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
  ASSERT_TRUE(space_2001_out != NULL);
  EXPECT_EQ(OC_REP_OBJECT, space_2001_out->type);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "name", &name_out,
                                &name_out_size));
  EXPECT_EQ(strlen("Hal 9000"), name_out_size);
  EXPECT_STREQ("Hal 9000", name_out);
  EXPECT_TRUE(oc_rep_get_string(space_2001_out->value.object, "job", &job_out,
                                &job_out_size));
  EXPECT_EQ(strlen("AI computer"), job_out_size);
  EXPECT_STREQ("AI computer", job_out);

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "{\"space_2001\":[{\"name\":\"Dave Bowman\","
    "\"job\":\"astronaut\"},{\"name\":\"Frank Poole\",\"job\":\"astronaut\"}"
    ",{\"name\":\"Hal 9000\",\"job\":\"AI computer\"}]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
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
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepAddGetByteStringArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* jagged arrays for testing */
  uint8_t ba1[] = { 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
  uint8_t ba2[] = { 0x01, 0x01, 0x02, 0x03, 0x05, 0x08,
                    0x13, 0x21, 0x34, 0x55, 0x89 };
  uint8_t ba3[] = {
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42
  };
  // at lease on byte array not nul terminated.
  uint8_t ba4[] = { 0x00, 0x00, 0xff, 0x00, 0x00 };

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_array(root, barray);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba1, sizeof(ba1));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba2, sizeof(ba2));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba3, sizeof(ba3));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_byte_string(barray, ba4, sizeof(ba4));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_array(root, barray);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  oc_string_array_t barray_out;
  size_t barray_len;
  EXPECT_TRUE(
    oc_rep_get_byte_string_array(rep, "barray", &barray_out, &barray_len));
  ASSERT_EQ(4, barray_len);

  EXPECT_EQ(sizeof(ba1), oc_byte_string_array_get_item_size(barray_out, 0));
  EXPECT_EQ(memcmp(ba1, oc_byte_string_array_get_item(barray_out, 0),
                   oc_byte_string_array_get_item_size(barray_out, 0)),
            0);
  EXPECT_EQ(sizeof(ba2), oc_byte_string_array_get_item_size(barray_out, 1));
  EXPECT_EQ(memcmp(ba2, oc_byte_string_array_get_item(barray_out, 1),
                   oc_byte_string_array_get_item_size(barray_out, 1)),
            0);
  EXPECT_EQ(sizeof(ba3), oc_byte_string_array_get_item_size(barray_out, 2));
  EXPECT_EQ(memcmp(ba3, oc_byte_string_array_get_item(barray_out, 2),
                   oc_byte_string_array_get_item_size(barray_out, 2)),
            0);
  EXPECT_EQ(sizeof(ba4), oc_byte_string_array_get_item_size(barray_out, 3));
  EXPECT_EQ(memcmp(ba4, oc_byte_string_array_get_item(barray_out, 3),
                   oc_byte_string_array_get_item_size(barray_out, 3)),
            0);

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "{\"barray\":[\"AQECAwQFBg==\","
    "\"AQECAwUIEyE0VYk=\",\"QkJCQkJCQkJCQkJCQkJCQkJCQkI=\",\"AAD/AAA=\"]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"barray\" : [\n"
                             "    \"AQECAwQFBg==\",\n"
                             "    \"AQECAwUIEyE0VYk=\",\n"
                             "    \"QkJCQkJCQkJCQkJCQkJCQkJCQkI=\",\n"
                             "    \"AAD/AAA=\"\n"
                             "  ]\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/* use oc_rep_set_string_array to build the string array. */
TEST_F(TestRepWithPool, OCRepSetGetStringArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* Strings for testing
    Note: check STRING_ARRAY_ITEM_MAX_LEN for maximal allowed string item length
    in a string array.
  */
#ifdef OC_DYNAMIC_ALLOCATION
#define STR0                                                                   \
  "Do not take life too seriously. You will never get out of it alive."
#define STR1 "All generalizations are false, including this one."
#define STR2 "Those who believe in telekinetics, raise my hand."
#define STR3 "I refuse to join any club that would have me as a member."
#else /* !OC_DYNAMIC_ALLOCATION */
#define STR0 "Do not take life too seriously."
#define STR1 "All generalizations are false."
#define STR2 "Raise my hand."
#define STR3 "I refuse to join any club."
#endif /* OC_DYNAMIC_ALLOCATION */

  oc_string_array_t quotes;
  oc_new_string_array(&quotes, (size_t)4);
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR0));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR1));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR2));
  EXPECT_TRUE(oc_string_array_add_item(quotes, STR3));
  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_string_array(root, quotes, quotes);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_free_string_array(&quotes);
  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  EXPECT_EQ(CborNoError, oc_parse_rep(payload, payload_len, &rep));
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  oc_string_array_t quotes_out;
  size_t quotes_len;
  EXPECT_TRUE(oc_rep_get_string_array(rep, "quotes", &quotes_out, &quotes_len));
  ASSERT_EQ(4, quotes_len);

  EXPECT_EQ(strlen(STR0), oc_string_array_get_item_size(quotes_out, 0));
  EXPECT_STREQ(STR0, oc_string_array_get_item(quotes_out, 0));
  EXPECT_EQ(strlen(STR1), oc_string_array_get_item_size(quotes_out, 1));
  EXPECT_STREQ(STR1, oc_string_array_get_item(quotes_out, 1));
  EXPECT_EQ(strlen(STR2), oc_string_array_get_item_size(quotes_out, 2));
  EXPECT_STREQ(STR2, oc_string_array_get_item(quotes_out, 2));
  EXPECT_EQ(strlen(STR3), oc_string_array_get_item_size(quotes_out, 3));
  EXPECT_STREQ(STR3, oc_string_array_get_item(quotes_out, 3));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"quotes\":"
                                 "[\"" STR0 "\","
                                 "\"" STR1 "\","
                                 "\"" STR2 "\","
                                 "\"" STR3 "\"]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"quotes\" : [\n"
                             "    \"" STR0 "\",\n"
                             "    \"" STR1 "\",\n"
                             "    \"" STR2 "\",\n"
                             "    \"" STR3 "\"\n"
                             "  ]\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

/* use oc_rep_add_text_string to build string array */
TEST_F(TestRepWithPool, OCRepAddGetStringArray)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /* Strings for testing
    Note: check STRING_ARRAY_ITEM_MAX_LEN for maximal allowed string item length
    in a string array.
  */
#ifdef OC_DYNAMIC_ALLOCATION
#define STR0                                                                   \
  "Do not take life too seriously. You will never get out of it alive."
#define STR1 "All generalizations are false, including this one."
#define STR2 "Those who believe in telekinetics, raise my hand."
#define STR3 "I refuse to join any club that would have me as a member."
#else /* !OC_DYNAMIC_ALLOCATION */
#define STR0 "Do not take life too seriously."
#define STR1 "All generalizations are false."
#define STR2 "Raise my hand."
#define STR3 "I refuse to join any club."
#endif /* OC_DYNAMIC_ALLOCATION */

  /* add values to root object */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_open_array(root, quotes);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR0);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR1);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR2);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_add_text_string(quotes, STR3);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_array(root, quotes);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  oc_string_array_t quotes_out;
  size_t quotes_len;
  EXPECT_TRUE(oc_rep_get_string_array(rep, "quotes", &quotes_out, &quotes_len));
  ASSERT_EQ(4, quotes_len);

  EXPECT_EQ(strlen(STR0), oc_string_array_get_item_size(quotes_out, 0));
  EXPECT_STREQ(STR0, oc_string_array_get_item(quotes_out, 0));
  EXPECT_EQ(strlen(STR1), oc_string_array_get_item_size(quotes_out, 1));
  EXPECT_STREQ(STR1, oc_string_array_get_item(quotes_out, 1));
  EXPECT_EQ(strlen(STR2), oc_string_array_get_item_size(quotes_out, 2));
  EXPECT_STREQ(STR2, oc_string_array_get_item(quotes_out, 2));
  EXPECT_EQ(strlen(STR3), oc_string_array_get_item_size(quotes_out, 3));
  EXPECT_STREQ(STR3, oc_string_array_get_item(quotes_out, 3));

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] = "{\"quotes\":"
                                 "[\"" STR0 "\","
                                 "\"" STR1 "\","
                                 "\"" STR2 "\","
                                 "\"" STR3 "\"]}";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "{\n"
                             "  \"quotes\" : [\n"
                             "    \"" STR0 "\",\n"
                             "    \"" STR1 "\",\n"
                             "    \"" STR2 "\",\n"
                             "    \"" STR3 "\"\n"
                             "  ]\n"
                             "}\n";
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST_F(TestRepWithPool, OCRepRootArrayObject)
{
  /*buffer for oc_rep_t */
  uint8_t buf[1024];
  oc_rep_new(&buf[0], sizeof(buf));

  /*
   * create root object array
   * "[{"href":"/light/1","rep":{"state":true}},{"href":"/count/1","rep":{"count":100}}]"
   */
  /* add values to root object */
  oc_rep_start_links_array();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_start_item(links);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(links, href, "/light/1");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(links, rep);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(rep, state, true);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(links, rep);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(links);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_start_item(links);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(links, href, "/count/1");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_object(links, rep);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(rep, count, 100);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_close_object(links, rep);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_object_array_end_item(links);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_links_array();

  /* convert CborEncoder to oc_rep_t */
  const uint8_t *payload = oc_rep_get_encoder_buf();
  int payload_len = oc_rep_get_encoded_payload_size();
  EXPECT_NE(payload_len, -1);
  oc_rep_set_pool(GetRepObjectsPool());
  oc_rep_t *rep = NULL;
  oc_parse_rep(payload, payload_len, &rep);
  ASSERT_TRUE(rep != NULL);

  /* read the values from the oc_rep_t */
  /* calling this an object_array is a bit of a misnomer internally it is a
   * linked list */
  EXPECT_EQ(0, oc_string_len(rep->name));
  EXPECT_EQ(OC_REP_OBJECT, rep->type);
  oc_rep_t *links = rep;
  ASSERT_TRUE(links != NULL);

  char *href_out = NULL;
  size_t href_out_size = 0;

  oc_rep_t *rep_out = NULL;

  EXPECT_TRUE(
    oc_rep_get_string(links->value.object, "href", &href_out, &href_out_size));
  EXPECT_EQ(strlen("/light/1"), href_out_size);
  EXPECT_STREQ("/light/1", href_out);

  EXPECT_TRUE(oc_rep_get_object(links->value.object, "rep", &rep_out));
  ASSERT_TRUE(rep_out != NULL);

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
  ASSERT_TRUE(rep_out != NULL);

  EXPECT_EQ(OC_REP_INT, rep_out->type);
  int64_t count_out = 0;
  EXPECT_TRUE(oc_rep_get_int(rep_out, "count", &count_out));
  EXPECT_EQ(100, count_out);

  char *json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, false);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, false);
  const char non_pretty_json[] =
    "[{\"href\":\"/light/1\",\"rep\":{\"state\":true}},"
    "{\"href\":\"/count/1\",\"rep\":{\"count\":100}}]";
  EXPECT_STREQ(non_pretty_json, json);
  free(json);
  json = NULL;
  json_size = oc_rep_to_json(rep, NULL, 0, true);
  json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
  const char pretty_json[] = "[\n"
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
  EXPECT_STREQ(pretty_json, json);
  free(json);
  json = NULL;

  oc_free_rep(rep);
}

TEST(TestRep, OCRepEncodedPayloadRealloc)
{
  /* buffer for oc_rep_t */
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *b = (uint8_t *)malloc(0);
  oc_rep_new_realloc(&b, 0, 1024);
#else  /* OC_DYNAMIC_ALLOCATION */
  uint8_t buffer[1024];
  uint8_t *b = buffer;
  oc_rep_new(buffer, sizeof(buffer));
#endif /* !OC_DYNAMIC_ALLOCATION */
  oc_rep_start_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_text_string(root, "hello", "world");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_double(root, "double", 3.14);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_boolean(root, "bool", true);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_int(root, "int", -1);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_set_uint(root, "uint", -1);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  uint8_t byte_string[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
  oc_rep_set_byte_string(root, byte_string_key, byte_string,
                         sizeof(byte_string));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  int fib[] = { 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89 };
  oc_rep_set_key(oc_rep_object(root), "fibonacci");
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_begin_array(oc_rep_object(root), fibonacci);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  for (size_t i = 0; i < (sizeof(fib) / sizeof(fib[0])); i++) {
    oc_rep_add_int(fibonacci, fib[i]);
    EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  }
  oc_rep_end_array(oc_rep_object(root), fibonacci);
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  double math_constants[] = { 3.14159, 2.71828, 1.414121, 1.61803 };
  oc_rep_set_double_array(
    root, math_constants, math_constants,
    (int)(sizeof(math_constants) / sizeof(math_constants[0])));
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  oc_rep_end_root_object();
  EXPECT_EQ(CborNoError, oc_rep_get_cbor_errno());
  b = oc_rep_shrink_encoder_buf(b);
  EXPECT_EQ(166, oc_rep_get_encoded_payload_size());
#ifdef OC_DYNAMIC_ALLOCATION
  free(b);
#endif
}

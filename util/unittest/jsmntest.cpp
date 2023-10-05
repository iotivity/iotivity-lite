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

#include "util/jsmn/jsmn_internal.h"

#include <cctype>
#include <climits>
#include <gtest/gtest.h>
#include <vector>

TEST(TestJsmn, ParseEmpty)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  EXPECT_EQ(0, jsmn_parse(&parser, nullptr, 0, nullptr, nullptr));

  jsmn_init(&parser);
  EXPECT_EQ(0, jsmn_parse(&parser, "", 0, nullptr, nullptr));

  std::vector<char> empty(2, '\0');
  jsmn_init(&parser);
  EXPECT_EQ(0,
            jsmn_parse(&parser, empty.data(), empty.size(), nullptr, nullptr));
}

TEST(TestJsmn, ParseInteger)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  std::string json = "1337";
  std::vector<jsmntok_t> tokens{};
  ASSERT_EQ(1, jsmn_parse(
                 &parser, json.c_str(), json.length(),
                 [](const jsmntok_t *token, const char *, void *data) {
                   auto &tokens = *static_cast<std::vector<jsmntok_t> *>(data);
                   tokens.push_back(*token);
                   return true;
                 },
                 &tokens));
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_PRIMITIVE, tokens[0].type);
}

TEST(TestJsmn, ParseIntegerNoTokens)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  std::string json = "1337";
  EXPECT_EQ(1,
            jsmn_parse(&parser, json.c_str(), json.length(), nullptr, nullptr));
}

static void
parseTokens(const std::string &json, std::vector<jsmntok_t> &tokens)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  ASSERT_LT(0, jsmn_parse(
                 &parser, json.c_str(), json.length(),
                 [](const jsmntok_t *token, const char *, void *data) {
                   auto &tokens = *static_cast<std::vector<jsmntok_t> *>(data);
                   tokens.push_back(*token);
                   return true;
                 },
                 &tokens))
    << "parsing of " << json << " should succeed";
}

static void
parseString(const std::string &str)
{
  std::string json = "\"" + str + "\"";
  std::vector<jsmntok_t> tokens{};
  parseTokens(json, tokens);
  ASSERT_EQ(1, tokens.size())
    << "parsing of " << json << " should result in 1 token";
  ASSERT_EQ(JSMN_STRING, tokens[0].type)
    << "parsing of " << json << " should result in a string token";
  std::string token_str(json.c_str() + tokens[0].start,
                        tokens[0].end - tokens[0].start);
  EXPECT_STREQ(str.c_str(), token_str.c_str())
    << "parsing of " << json << " should resulted in " << token_str;
}

// Parse string
TEST(TestJsmn, ParseString)
{
  parseString("");
  parseString("Hello World!");

  parseString(R"(\"\/\\\b\f\r\n\t)");

  parseString(R"(\u0123)");
  parseString(R"(\u4567)");
  parseString(R"(\u89ab)");
  parseString(R"(\ucdef)");
  parseString(R"(\uABCD)");
  parseString(R"(\uEF01)");
}

TEST(TestJsmn, ParseStringNoTokens)
{
  std::string json = R"("Hello World!")";
  jsmn_parser_t parser;
  jsmn_init(&parser);
  EXPECT_EQ(1,
            jsmn_parse(&parser, json.c_str(), json.length(), nullptr, nullptr));
}

static void
parseJsonFail(const std::string &json)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  ASSERT_GT(0,
            jsmn_parse(&parser, json.c_str(), json.length(), nullptr, nullptr))
    << "parsing of " << json << " should fail";
}

static void
parseVectorFail(const std::vector<char> &json)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  std::string json_printable(json.data(), json.size());
  ASSERT_GT(0, jsmn_parse(&parser, json.data(), json.size(), nullptr, nullptr))
    << "parsing of " << json_printable << " should fail";
}

TEST(TestJsmn, ParseString_Fail)
{
  // missing ending quote
  parseJsonFail(R"(")");
  parseJsonFail(R"("\)");
  // escaped ending quote
  parseJsonFail(R"("\")");
  // invalid escape sequence
  parseJsonFail(R"("\l")");

  // invalid unicode escape sequence
  parseJsonFail(R"("\u")");
  parseJsonFail(R"("\u0")");
  parseJsonFail(R"("\u01")");
  parseJsonFail(R"("\u012")");
  parseJsonFail(R"("\u012g")");

  // invalid strings
  parseVectorFail({ '"', '\0', '\0', '\0', '\0', '\0' });
  parseVectorFail({ '"', '\\', 'u' });
  parseVectorFail({ '"', '\\', 'u', '\0' });

  parseJsonFail("[}");
  parseJsonFail("{]");
}

static void
parseCharFail(char c)
{
  jsmn_parser_t parser;
  jsmn_init(&parser);
  ASSERT_GT(0, jsmn_parse(&parser, &c, 1, nullptr, nullptr))
    << "parsing of " << (int)c << " should fail";
}

TEST(TestJsmn, ParseArray)
{
  std::vector<jsmntok_t> tokens{};
  parseTokens("[]", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_ARRAY, tokens[0].type);

  tokens = {};
  parseTokens("[[]]", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_ARRAY, tokens[0].type);

  tokens = {};
  parseTokens("[true, false, false]", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_ARRAY, tokens[0].type);

  tokens = {};
  parseTokens("[1,2,3]", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_ARRAY, tokens[0].type);

  tokens = {};
  parseTokens(R"(["a", "b", "c"])", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_ARRAY, tokens[0].type);
}

TEST(TestJsmn, ParseArrayNoTokens)
{
  std::string json = "[123, 456, 789]";
  jsmn_parser_t parser;
  jsmn_init(&parser);
  EXPECT_LT(0,
            jsmn_parse(&parser, json.c_str(), json.length(), nullptr, nullptr));
}

TEST(TestJsmn, ParseArrayFail)
{
  parseJsonFail("[");
  parseJsonFail("]");
}

TEST(TestJsmn, ParseObject)
{
  std::vector<jsmntok_t> tokens{};
  parseTokens("{}", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_OBJECT, tokens[0].type);

  tokens = {};
  parseTokens(R"({"k1": 123, "k2": "abc", "k3": [], "k4":{}})", tokens);
  ASSERT_EQ(1, tokens.size());
  EXPECT_EQ(JSMN_OBJECT, tokens[0].type);
}

TEST(TestJsmn, ParseObjectNoTokens)
{
  std::string json = R"({"k1": 123, "k2": "abc"})";
  jsmn_parser_t parser;
  jsmn_init(&parser);
  EXPECT_LT(0,
            jsmn_parse(&parser, json.c_str(), json.length(), nullptr, nullptr));
}

TEST(TestJsmn, ParseObjectFail)
{
  parseJsonFail("{");
  parseJsonFail("}");
}

TEST(TestJsmn, ParseFail)
{
  for (int i = 1; i <= UCHAR_MAX; ++i) {
    if (std::isprint(i) || isspace(i)) {
      continue;
    }
    parseCharFail(static_cast<char>(i));
  }

  auto parse_cb_fail = [](const jsmntok_t *, const char *, void *) {
    return false;
  };

  jsmn_parser_t parser;
  jsmn_init(&parser);
  std::string json = "1";
  EXPECT_GT(0, jsmn_parse(&parser, json.c_str(), json.length(), parse_cb_fail,
                          nullptr));

  jsmn_init(&parser);
  json = R"(a multi word sentence)";
  EXPECT_GT(0, jsmn_parse(&parser, json.c_str(), json.length(), parse_cb_fail,
                          nullptr));

  jsmn_init(&parser);
  json = R"({"key": "value"})";
  EXPECT_GT(0, jsmn_parse(&parser, json.c_str(), json.length(), parse_cb_fail,
                          nullptr));

  jsmn_init(&parser);
  json = R"([1, 2, 3])";
  EXPECT_GT(0, jsmn_parse(&parser, json.c_str(), json.length(), parse_cb_fail,
                          nullptr));
}

#endif // OC_JSON_ENCODER

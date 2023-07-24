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

#include "oc_log.h"
#include "port/oc_log_internal.h"
#include "util/oc_compiler.h"

#include <cstdarg>
#include <cstdio>
#include <gtest/gtest.h>
#include <map>

class TestLog : public testing::Test {
public:
  static void TearDownTestCase()
  {
    oc_log_set_function(nullptr);
    oc_log_set_level(OC_LOG_LEVEL_INFO);
    oc_log_set_components(OC_LOG_COMPONENT_ALL);
  }
};

TEST_F(TestLog, LogToStdout)
{
  OC_ERR("error");
  OC_WRN("warning");
  OC_NOTE("notice");
  OC_INFO("info");
  OC_DBG("debug");
  OC_TRACE("trace");

  oc_log_set_level(OC_LOG_LEVEL_DEBUG);
  EXPECT_EQ(OC_LOG_LEVEL_DEBUG, oc_log_get_level());
  OC_DBG("debug");
}

static void expectWarningOrError(oc_log_level_t log_level,
                                 oc_log_component_t component, const char *file,
                                 int line, const char *func_name,
                                 const char *format, ...)
  OC_PRINTF_FORMAT(6, 7);

static void
expectWarningOrError(oc_log_level_t log_level, oc_log_component_t component,
                     const char *file, int line, const char *func_name,
                     const char *format, ...)
{
  EXPECT_TRUE(log_level == OC_LOG_LEVEL_ERROR ||
              log_level == OC_LOG_LEVEL_WARNING);

  printf("[%s:%d %s]<%s>: ", file, line, func_name,
         oc_log_component_name(component));
  va_list ap;
  va_start(ap, format);
  vprintf(format, ap);
  va_end(ap);
  printf("\n");
  fflush(stdout);
}

TEST_F(TestLog, LogToFunction)
{
  oc_log_set_level(OC_LOG_LEVEL_ERROR);
  oc_log_set_function(expectWarningOrError);

  OC_LOG(OC_LOG_LEVEL_ERROR, "error");
  OC_LOG(OC_LOG_LEVEL_WARNING, "warning");
  OC_LOG(OC_LOG_LEVEL_NOTICE, "notice");
  OC_LOG(OC_LOG_LEVEL_INFO, "info");
  OC_LOG(OC_LOG_LEVEL_DEBUG, "debug");
  OC_LOG(OC_LOG_LEVEL_TRACE, "trace");
}

TEST_F(TestLog, LogLevelToLabel)
{
  oc_log_set_level(OC_LOG_LEVEL_ERROR);
  oc_log_set_function(expectWarningOrError);

  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_DISABLED), "DISABLED");
  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_ERROR), "ERROR");
  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_WARNING), "WARNING");
  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_NOTICE), "NOTICE");
  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_INFO), "INFO");
  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_DEBUG), "DEBUG");
  EXPECT_STREQ(oc_log_level_to_label(OC_LOG_LEVEL_TRACE), "TRACE");
}

TEST_F(TestLog, LogComponentName)
{
  EXPECT_STREQ(oc_log_component_name(static_cast<oc_log_component_t>(-1)), "");

  EXPECT_STREQ(oc_log_component_name(OC_LOG_COMPONENT_DEFAULT), "default");
#ifdef OC_CLOUD
  EXPECT_STREQ(oc_log_component_name(OC_LOG_COMPONENT_CLOUD), "cloud");
#endif /* OC_CLOUD */
  EXPECT_STREQ(oc_log_component_name(OC_LOG_COMPONENT_COAP), "coap");
}

namespace {
std::map<oc_log_component_t, int> gComponentInvoked{};

void
expectNonDefault(oc_log_level_t, oc_log_component_t component, const char *,
                 int, const char *, const char *, ...)
{
  EXPECT_NE(component, OC_LOG_COMPONENT_DEFAULT);
  gComponentInvoked[component]++;
}

}

TEST_F(TestLog, FilterByComponent)
{
  oc_log_set_level(OC_LOG_LEVEL_ERROR);
  oc_log_set_components(OC_LOG_COMPONENT_ALL & ~OC_LOG_COMPONENT_DEFAULT);
  oc_log_set_function(expectNonDefault);
  gComponentInvoked.clear();

  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_ERROR, OC_LOG_COMPONENT_DEFAULT,
                        "default");
#ifdef OC_CLOUD
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_ERROR, OC_LOG_COMPONENT_CLOUD, "cloud");
#endif /* OC_CLOUD */
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_ERROR, OC_LOG_COMPONENT_COAP, "coap");

  EXPECT_EQ(gComponentInvoked[OC_LOG_COMPONENT_DEFAULT], 0);
#ifdef OC_CLOUD
  EXPECT_EQ(gComponentInvoked[OC_LOG_COMPONENT_CLOUD], 1);
#endif /* OC_CLOUD */
  EXPECT_EQ(gComponentInvoked[OC_LOG_COMPONENT_COAP], 1);
}

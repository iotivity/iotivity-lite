/****************************************************************************
 *
 * Copyright (c) 2022-2024 plgd.dev, s.r.o.
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

#ifdef OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING

#include "api/plgd/device-provisioning-client/plgd_dps_log_internal.h"
#include "plgd/plgd_dps.h"

#include "gtest/gtest.h"

#include <stdarg.h>

class TestDPSLog : public testing::Test {
public:
  void TearDown() override
  {
    plgd_dps_set_log_fn(nullptr);
    plgd_dps_log_set_level(OC_LOG_LEVEL_INFO);
  }
};

TEST_F(TestDPSLog, LogToStdout)
{
  DPS_ERR("error");
  DPS_WRN("warning");
  DPS_NOTE("notice");
  DPS_INFO("info");
  DPS_DBG("debug");
  DPS_TRACE("trace");

  plgd_dps_log_set_level(OC_LOG_LEVEL_TRACE);
  EXPECT_EQ(OC_LOG_LEVEL_TRACE, plgd_dps_log_get_level());
  DPS_DBG("debug");
  DPS_TRACE("trace");
}

static void printLog(oc_log_level_t log_level, const char *file, int line,
                     const char *func_name, const char *format, va_list args)
  OC_PRINTF_FORMAT(5, 0);

static void
printLog(oc_log_level_t log_level, const char *file, int line,
         const char *func_name, const char *format, va_list args)
{
  printf("[%s:%d %s]<%s>: ", file, line, func_name,
         oc_log_level_to_label(log_level));
  vprintf(format, args);
  printf("\n");
  fflush(stdout);
}

static void expectUpToNotice(oc_log_level_t log_level,

                             const char *file, int line, const char *func_name,
                             const char *format, ...) OC_PRINTF_FORMAT(5, 6);
static void
expectUpToNotice(oc_log_level_t log_level, const char *file, int line,
                 const char *func_name, const char *format, ...)
{
  EXPECT_TRUE(log_level == OC_LOG_LEVEL_ERROR ||
              log_level == OC_LOG_LEVEL_WARNING ||
              log_level == OC_LOG_LEVEL_NOTICE);
  va_list ap;
  va_start(ap, format);
  printLog(log_level, file, line, func_name, format, ap);
  va_end(ap);
}

TEST_F(TestDPSLog, LogToFunction)
{
  plgd_dps_log_set_level(OC_LOG_LEVEL_NOTICE);
  plgd_dps_set_log_fn(expectUpToNotice);

  DPS_LOG(OC_LOG_LEVEL_ERROR, "error");
  DPS_LOG(OC_LOG_LEVEL_WARNING, "warning");
  DPS_LOG(OC_LOG_LEVEL_NOTICE, "notice");
  DPS_LOG(OC_LOG_LEVEL_INFO, "info");
  DPS_LOG(OC_LOG_LEVEL_DEBUG, "debug");
  DPS_LOG(OC_LOG_LEVEL_TRACE, "trace");
}

static void
expectNoLog(oc_log_level_t, const char *, int, const char *, const char *, ...)
{
  FAIL() << "unexpected log";
}

TEST_F(TestDPSLog, SkipLogByComponent)
{
  plgd_dps_log_set_level(OC_LOG_LEVEL_TRACE);
  plgd_dps_set_log_fn(expectNoLog);

  DPS_ERR("error");
  DPS_WRN("warning");
  DPS_NOTE("notice");
  DPS_INFO("info");
  DPS_DBG("debug");
  DPS_TRACE("trace");
}

#endif /* OC_HAS_FEATURE_PLGD_DEVICE_PROVISIONING */

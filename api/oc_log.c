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

/**
 * @file oc_log.c
 *
 * @author Jozef Kralik, Daniel Adam
 */

#include "oc_log_internal.h"
#include "port/oc_log_internal.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

static oc_logger_t g_logger = {
  .fn = NULL,
  .level = OC_LOG_LEVEL_INFO,
};

oc_logger_t *
oc_log_get_logger(void)
{
  return &g_logger;
}

void
oc_log_set_level(oc_log_level_t level)
{
  assert(level < UINT8_MAX);
  g_logger.level = (uint8_t)level;
}

oc_log_level_t
oc_log_get_level(void)
{
  return g_logger.level;
}

const char *
oc_log_level_to_label(oc_log_level_t level)
{
  switch (level) {
  case OC_LOG_LEVEL_DISABLED:
    return "DISABLED";
  case OC_LOG_LEVEL_ERROR:
    return "ERROR";
  case OC_LOG_LEVEL_WARNING:
    return "WARNING";
  case OC_LOG_LEVEL_NOTICE:
    return "NOTICE";
  case OC_LOG_LEVEL_INFO:
    return "INFO";
  case OC_LOG_LEVEL_DEBUG:
    return "DEBUG";
  case OC_LOG_LEVEL_TRACE:
    return "TRACE";
  }
  return "";
}

const char *
oc_log_component_name(oc_log_component_t component)
{
  switch (component) {
  case OC_LOG_COMPONENT_DEFAULT:
    return "default";
  }
  return "";
}

void
oc_log_set_function(oc_print_log_fn_t log_fn)
{
  g_logger.fn = log_fn;
}

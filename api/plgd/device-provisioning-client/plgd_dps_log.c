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

#include "plgd_dps_log_internal.h"

#include "oc_clock_util.h"
#include "oc_log.h"
#include "util/oc_atomic.h"
#include "util/oc_compiler.h"

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

static struct
{
  plgd_dps_print_log_fn_t fn; ///< logging function
  OC_ATOMIC_INT8_T level;     ///< enabled log level
} g_dps_logger = {
  .fn = NULL,
  .level = OC_LOG_LEVEL_INFO,
};

void
plgd_dps_set_log_fn(plgd_dps_print_log_fn_t log_fn)
{
  g_dps_logger.fn = log_fn;
}

plgd_dps_print_log_fn_t
plgd_dps_get_log_fn(void)
{
  return g_dps_logger.fn;
}

void
plgd_dps_log_set_level(oc_log_level_t level)
{
  assert(level >= INT8_MIN);
  assert(level <= INT8_MAX);
  OC_ATOMIC_STORE8(g_dps_logger.level, (int8_t)level);
}

oc_log_level_t
plgd_dps_log_get_level(void)
{
  return OC_ATOMIC_LOAD8(g_dps_logger.level);
}

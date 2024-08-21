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

#ifndef PLGD_DPS_LOG_INTERNAL_H
#define PLGD_DPS_LOG_INTERNAL_H

#include "plgd/plgd_dps.h"
#include "port/oc_log_internal.h"
#include "util/oc_compiler.h"

#include "string.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PLGD_DPS_LOG_MAXIMUM_LEVEL
#define PLGD_DPS_LOG_MAXIMUM_LEVEL (OC_LOG_LEVEL_DISABLED_MACRO)
#endif

#define PLGD_DPS_LOG_LEVEL_IS_ENABLED(level)                                   \
  ((level) <= (PLGD_DPS_LOG_MAXIMUM_LEVEL))

#define DPS_LOG(log_level, ...)                                                \
  do {                                                                         \
    if (plgd_dps_log_get_level() >= (log_level)) {                             \
      plgd_dps_print_log_fn_t _dps_logger_fn = plgd_dps_get_log_fn();          \
      if (_dps_logger_fn != NULL) {                                            \
        _dps_logger_fn((log_level), __FILENAME__, __LINE__, __func__,          \
                       __VA_ARGS__);                                           \
        break;                                                                 \
      }                                                                        \
      OC_LOG_WITH_COMPONENT(log_level, OC_LOG_COMPONENT_DEVICE_PROVISIONING,   \
                            __VA_ARGS__);                                      \
    }                                                                          \
  } while (0)

#define DPS_TRACE_IS_ENABLED                                                   \
  PLGD_DPS_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE_MACRO)
#if DPS_TRACE_IS_ENABLED
#define DPS_TRACE(...) DPS_LOG(OC_LOG_LEVEL_TRACE, __VA_ARGS__)
#else /* !DPS_TRACE_IS_ENABLED */
#define DPS_TRACE(...)
#endif /* DPS_TRACE_IS_ENABLED */

#define DPS_DBG_IS_ENABLED                                                     \
  PLGD_DPS_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_DEBUG_MACRO)
#if DPS_DBG_IS_ENABLED
#define DPS_DBG(...) DPS_LOG(OC_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else /* !DPS_DBG_IS_ENABLED */
#define DPS_DBG(...)
#endif /* DPS_DBG_IS_ENABLED */

#define DPS_INFO_IS_ENABLED                                                    \
  PLGD_DPS_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_INFO_MACRO)
#if DPS_INFO_IS_ENABLED
#define DPS_INFO(...) DPS_LOG(OC_LOG_LEVEL_INFO, __VA_ARGS__)
#else /* !DPS_INFO_IS_ENABLED */
#define DPS_INFO(...)
#endif /* DPS_INFO_IS_ENABLED */

#define DPS_NOTE_IS_ENABLED                                                    \
  PLGD_DPS_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_NOTICE_MACRO)
#if DPS_NOTE_IS_ENABLED
#define DPS_NOTE(...) DPS_LOG(OC_LOG_LEVEL_NOTICE, __VA_ARGS__)
#else /* !DPS_NOTE_IS_ENABLED */
#define DPS_NOTE(...)
#endif /* DPS_NOTE_IS_ENABLED */

#define DPS_WRN_IS_ENABLED                                                     \
  PLGD_DPS_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_WARNING_MACRO)
#if DPS_WRN_IS_ENABLED
#define DPS_WRN(...) DPS_LOG(OC_LOG_LEVEL_WARNING, __VA_ARGS__)
#else /* !DPS_WRN_IS_ENABLED */
#define DPS_WRN(...)
#endif /* DPS_WRN_IS_ENABLED */

#define DPS_ERR_IS_ENABLED                                                     \
  PLGD_DPS_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_ERROR_MACRO)
#if DPS_ERR_IS_ENABLED
#define DPS_ERR(...) DPS_LOG(OC_LOG_LEVEL_ERROR, __VA_ARGS__)
#else /* !DPS_ERR_IS_ENABLED */
#define DPS_ERR(...)
#endif /* DPS_ERR_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* PLGD_DPS_LOG_INTERNAL_H */

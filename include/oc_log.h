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

/**
 * @file oc_log.h
 *
 * OCF public log functions
 *
 * Allow to set log callback function and level.
 *
 * @author Jozef Kralik, Daniel Adam
 */

#ifndef OC_LOG_H
#define OC_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include "oc_export.h"
#include "util/oc_compiler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef OC_LOG_MAXIMUM_LEVEL
#define OC_LOG_LEVEL_IS_ENABLED(level) (level <= OC_LOG_MAXIMUM_LEVEL)
#else
#define OC_LOG_LEVEL_IS_ENABLED(level) (0)
#endif /* OC_LOG_MAXIMUM_LEVEL */

#define OC_LOG_LEVEL_DISABLED_MACRO (-1)
#define OC_LOG_LEVEL_ERROR_MACRO (3)
#define OC_LOG_LEVEL_WARNING_MACRO (4)
#define OC_LOG_LEVEL_NOTICE_MACRO (5)
#define OC_LOG_LEVEL_INFO_MACRO (6)
#define OC_LOG_LEVEL_DEBUG_MACRO (7)
#define OC_LOG_LEVEL_TRACE_MACRO (8)

/**
 * Log level determines the importance of the message. The levels are in order
 * of decreasing importance.
 */
typedef enum {
  OC_LOG_LEVEL_DISABLED = OC_LOG_LEVEL_DISABLED_MACRO, ///< disable logging
  OC_LOG_LEVEL_ERROR = OC_LOG_LEVEL_ERROR_MACRO,       ///< error conditions
  OC_LOG_LEVEL_WARNING = OC_LOG_LEVEL_WARNING_MACRO,   ///< warning conditions
  OC_LOG_LEVEL_NOTICE =
    OC_LOG_LEVEL_NOTICE_MACRO, ///< normal, but significant condition
  OC_LOG_LEVEL_INFO = OC_LOG_LEVEL_INFO_MACRO,   ///< informational message
  OC_LOG_LEVEL_DEBUG = OC_LOG_LEVEL_DEBUG_MACRO, ///< debug level message
  OC_LOG_LEVEL_TRACE = OC_LOG_LEVEL_TRACE_MACRO, ///< trace level message
} oc_log_level_t;

/**
 * Log component determines the source of the message. The components are
 * defined as bit flags.
 */
typedef enum {
  OC_LOG_COMPONENT_DEFAULT = 1 << 0, ///< default, non-specific component
} oc_log_component_t;

/**
 * @brief Custom logging function
 *
 * @param level log level of the message
 * @param component log component of the message
 * @param file file of the log message call
 * @param line line of the log message call in \p file
 * @param func_name function name in which the log message call is invoked
 * @param format format of the log message
 */
typedef void (*oc_print_log_fn_t)(oc_log_level_t level,
                                  oc_log_component_t component,
                                  const char *file, int line,
                                  const char *func_name, const char *format,
                                  ...) OC_PRINTF_FORMAT(6, 7) OC_NONNULL();

/**
 * @brief Set log callback function. It is recommended to set it before
 * oc_main_init because it is not thread safe.
 *
 * @param log_func Log callback function
 * @note If log_func is NULL, the default log function will be used which prints
 * to a message in format "[OC <rfc3339 time>] <label>: <filename>:<line>
 * <message>" to stdout.
 */
OC_API
void oc_log_set_function(oc_print_log_fn_t log_func);

/**
 * @brief Set log level of the global logger, logs with lower importance will be
 * ignored. It is thread safe.
 *
 * @param level Log level
 * @note If log level is not set, the default log level is OC_LOG_LEVEL_INFO.
 */
OC_API
void oc_log_set_level(oc_log_level_t level);

/**
 * @brief Get log level of the global logger. It is thread safe.
 *
 * @return Log level
 */
OC_API
oc_log_level_t oc_log_get_level(void);

/**
 * @brief Convert log level to string. It is thread safe.
 *
 * @return Log level in const char *.
 * @return Empty string for an invalid log level value
 */
OC_API
const char *oc_log_level_to_label(oc_log_level_t level) OC_RETURNS_NONNULL;

/**
 * @brief Get component name. It is thread safe.
 *
 * @param component Component type
 * @return const char* Name of a component.
 * @return Empty string for an invalid IoTivity-lite component type.
 */
OC_API
const char *oc_log_component_name(oc_log_component_t component)
  OC_RETURNS_NONNULL;

#ifdef __cplusplus
}
#endif

#endif /* OC_LOG_H */

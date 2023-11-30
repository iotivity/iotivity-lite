/******************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
  @file oc_log_internal.h

  generic logging functions for ports:
  - OC_LOGipaddr
    prints the endpoint information to stdout
  - OC_LOGbytes
    prints the bytes to stdout
  - OC_DBG
    prints information as Debug level
  - OC_WRN
    prints information as Warning level
  - OC_ERR
    prints information as Error level

  compile flags:
  - OC_DEBUG
    enables output of logging functions for android
  - OC_NO_LOG_BYTES
    disables output of OC_LOGbytes logging function
    if OC_DEBUG is enabled.
*/

#ifndef OC_PORT_LOG_INTERNAL_H
#define OC_PORT_LOG_INTERNAL_H

#include "api/oc_log_internal.h"
#include "oc_clock_util.h"
#include "oc_helpers.h"
#include "oc_log.h"

#include <inttypes.h>

#ifndef __FILENAME__
#ifdef _WIN32
#define __FILENAME__                                                           \
  (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define __FILENAME__                                                           \
  (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif
#endif /* !__FILENAME__ */

#ifdef __ANDROID__
#include "android/oc_log_android.h"

#if defined(OC_DEBUG) || defined(OC_PUSHDEBUG)
#define OC_LOG_WITH_COMPONENT(level, component, ...)                           \
  android_log((level), (component), __FILE__, __func__, __LINE__, __VA_ARGS__)
#define OC_LOG(level, ...)                                                     \
  OC_LOG_WITH_COMPONENT(level, OC_LOG_COMPONENT_DEFAULT, __VA_ARGS__)
#define OC_LOGipaddr(endpoint)                                                 \
  android_log_ipaddr(OC_LOG_LEVEL_DEBUG, __FILE__, __func__, __LINE__, endpoint)
#define OC_LOGbytes(bytes, length)                                             \
  android_log_bytes(OC_LOG_LEVEL_DEBUG, __FILE__, __func__, __LINE__, bytes,   \
                    length)
#else /* defined(OC_DEBUG) || defined(OC_PUSHDEBUG) */
#define OC_LOG(level, ...)
#define OC_LOGipaddr(endpoint)
#define OC_LOGbytes(bytes, length)
#endif /* !defined(OC_DEBUG) && !defined(OC_PUSHDEBUG) */
#endif /* __ANDROID__ */

// port's layer can override this macro to provide its own logger
#ifndef OC_LOG_WITH_COMPONENT
#define OC_LOG_WITH_COMPONENT(log_level, log_component, ...)                   \
  do {                                                                         \
    const oc_logger_t *_logger = oc_log_get_logger();                          \
    if (_logger->level < (log_level)) {                                        \
      break;                                                                   \
    }                                                                          \
    if ((_logger->components & (log_component)) == 0) {                        \
      break;                                                                   \
    }                                                                          \
    if (_logger->fn != NULL) {                                                 \
      _logger->fn((log_level), (log_component), __FILENAME__, __LINE__,        \
                  __func__, __VA_ARGS__);                                      \
      break;                                                                   \
    }                                                                          \
    char _oc_log_fn_buf[64] = { 0 };                                           \
    oc_clock_time_rfc3339(_oc_log_fn_buf, sizeof(_oc_log_fn_buf));             \
    OC_PRINTF("[OC %s] ", _oc_log_fn_buf);                                     \
    if ((log_component) != OC_LOG_COMPONENT_DEFAULT) {                         \
      OC_PRINTF("(%s) ", oc_log_component_name(log_component));                \
    }                                                                          \
    OC_PRINTF("%s: %s:%d <%s>: ", oc_log_level_to_label(log_level),            \
              __FILENAME__, __LINE__, __func__);                               \
    OC_PRINTF(__VA_ARGS__);                                                    \
    OC_PRINTF("\n");                                                           \
    fflush(stdout);                                                            \
  } while (0)
#endif /* !OC_LOG_WITH_COMPONENT */

#ifndef OC_LOG
#define OC_LOG(log_level, ...)                                                 \
  OC_LOG_WITH_COMPONENT(log_level, OC_LOG_COMPONENT_DEFAULT, __VA_ARGS__)
#endif /* !OC_LOG */

#ifndef OC_LOG_MAXIMUM_LEVEL
#define OC_LOG_MAXIMUM_LEVEL (OC_LOG_LEVEL_DISABLED_MACRO)
#endif /* !OC_LOG_MAXIMUM_LEVEL */

#define OC_TRACE_IS_ENABLED OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE_MACRO)
#ifndef OC_TRACE
#if OC_TRACE_IS_ENABLED
#define OC_TRACE(...) OC_LOG(OC_LOG_LEVEL_TRACE, __VA_ARGS__)
#else
#define OC_TRACE(...)
#endif
#endif /* !OC_TRACE */

#define OC_DBG_IS_ENABLED OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_DEBUG_MACRO)
#ifndef OC_DBG
#if OC_DBG_IS_ENABLED
#define OC_DBG(...) OC_LOG(OC_LOG_LEVEL_DEBUG, __VA_ARGS__)
#else
#define OC_DBG(...)
#endif
#endif /* !OC_DBG */

#define OC_INFO_IS_ENABLED OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_INFO_MACRO)
#ifndef OC_INFO
#if OC_INFO_IS_ENABLED
#define OC_INFO(...) OC_LOG(OC_LOG_LEVEL_INFO, __VA_ARGS__)
#else
#define OC_INFO(...)
#endif
#endif /* !OC_INFO */

#define OC_NOTE_IS_ENABLED OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_NOTICE_MACRO)
#ifndef OC_NOTE
#if OC_NOTE_IS_ENABLED
#define OC_NOTE(...) OC_LOG(OC_LOG_LEVEL_NOTICE, __VA_ARGS__)
#else
#define OC_NOTE(...)
#endif
#endif /* !OC_NOTE */

#define OC_WRN_IS_ENABLED OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_WARNING_MACRO)
#ifndef OC_WRN
#if OC_WRN_IS_ENABLED
#define OC_WRN(...) OC_LOG(OC_LOG_LEVEL_WARNING, __VA_ARGS__)
#else
#define OC_WRN(...)
#endif
#endif /* !OC_WRN */

#define OC_ERR_IS_ENABLED OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_ERROR_MACRO)
#ifndef OC_ERR
#if OC_ERR_IS_ENABLED
#define OC_ERR(...) OC_LOG(OC_LOG_LEVEL_ERROR, __VA_ARGS__)
#else
#define OC_ERR(...)
#endif
#endif /* !OC_ERR */

#define SNPRINTFbytes(buff, size, data, len)                                   \
  do {                                                                         \
    char *beg = (buff);                                                        \
    char *end = (buff) + (size);                                               \
    /* without _oc_log_ret = 9 has sometimes */                                \
    uint8_t *_oc_log_data = (uint8_t *)(data);                                 \
    for (size_t i = 0; (beg <= (end - 3)) && (i < (size_t)(len)); i++) {       \
      int _oc_log_ret =                                                        \
        (i == 0) ? OC_SNPRINTF(beg, end - beg, "%02x", _oc_log_data[i])        \
                 : OC_SNPRINTF(beg, end - beg, ":%02x", _oc_log_data[i]);      \
      if (_oc_log_ret < 0) {                                                   \
        break;                                                                 \
      }                                                                        \
      beg += _oc_log_ret;                                                      \
    }                                                                          \
  } while (0)

#if OC_DBG_IS_ENABLED
#define OC_LOG_ENDPOINT_ADDR(component, endpoint, addr_memb)                   \
  do {                                                                         \
    const oc_logger_t *_logger = oc_log_get_logger();                          \
    if (_logger->level < OC_LOG_LEVEL_DEBUG) {                                 \
      break;                                                                   \
    }                                                                          \
    if ((_logger->components & (component)) == 0) {                            \
      break;                                                                   \
    }                                                                          \
    char _oc_log_endpoint_buf[256];                                            \
    memset(_oc_log_endpoint_buf, 0, sizeof(_oc_log_endpoint_buf));             \
    OC_SNPRINT_ENDPOINT_ADDR(_oc_log_endpoint_buf,                             \
                             sizeof(_oc_log_endpoint_buf), endpoint,           \
                             addr_memb);                                       \
    if (_logger->fn != NULL) {                                                 \
      _logger->fn(OC_LOG_LEVEL_DEBUG, (component), __FILENAME__, __LINE__,     \
                  __func__, "%s", _oc_log_endpoint_buf);                       \
      break;                                                                   \
    }                                                                          \
    char _oc_log_fn_buf[64] = { 0 };                                           \
    oc_clock_time_rfc3339(_oc_log_fn_buf, sizeof(_oc_log_fn_buf));             \
    OC_PRINTF("[OC %s] ", _oc_log_fn_buf);                                     \
    if ((component) != OC_LOG_COMPONENT_DEFAULT) {                             \
      OC_PRINTF("(%s) ", oc_log_component_name(component));                    \
    }                                                                          \
    OC_PRINTF("%s: %s:%d <%s>: endpoint %s\n",                                 \
              oc_log_level_to_label(OC_LOG_LEVEL_DEBUG), __FILENAME__,         \
              __LINE__, __func__, _oc_log_endpoint_buf);                       \
    fflush(stdout);                                                            \
  } while (0)
#ifndef OC_LOGipaddr_WITH_COMPONENT
#define OC_LOGipaddr_WITH_COMPONENT(component, endpoint)                       \
  OC_LOG_ENDPOINT_ADDR(component, endpoint, addr)
#endif /* !OC_LOGipaddr_WITH_COMPONENT */
#ifndef OC_LOGipaddr
#define OC_LOGipaddr(endpoint)                                                 \
  OC_LOGipaddr_WITH_COMPONENT(OC_LOG_COMPONENT_DEFAULT, endpoint)
#endif /* !OC_LOGipaddr */
#ifndef OC_LOGipaddr_local_WITH_COMPONENT
#define OC_LOGipaddr_local_WITH_COMPONENT(component, endpoint)                 \
  OC_LOG_ENDPOINT_ADDR(component, endpoint, addr_local)
#endif /* !OC_LOGipaddr_local_WITH_COMPONENT */
#ifndef OC_LOGipaddr_local
#define OC_LOGipaddr_local(endpoint)                                           \
  OC_LOGipaddr_local_WITH_COMPONENT(OC_LOG_COMPONENT_DEFAULT, endpoint)
#endif /* !OC_LOGipaddr_local */
#else  /* OC_DBG_IS_ENABLED */
#ifndef OC_LOGipaddr_WITH_COMPONENT
#define OC_LOGipaddr_WITH_COMPONENT(component, endpoint)
#endif /* !OC_LOGipaddr_WITH_COMPONENT */
#ifndef OC_LOGipaddr
#define OC_LOGipaddr(endpoint)
#endif /* !OC_LOGipaddr */
#ifndef OC_LOGipaddr_local_WITH_COMPONENT
#define OC_LOGipaddr_local_WITH_COMPONENT(component, endpoint)
#endif /* !OC_LOGipaddr_local_WITH_COMPONENT */
#ifndef OC_LOGipaddr_local
#define OC_LOGipaddr_local(endpoint)
#endif /* !OC_LOGipaddr_local */
#endif /* !OC_DBG_IS_ENABLED */

#ifndef OC_LOGbytes_WITH_COMPONENT
#if defined(OC_NO_LOG_BYTES) || !defined(OC_DEBUG) ||                          \
  !OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE)
#define OC_LOGbytes_WITH_COMPONENT(component, bytes, length)
#else /* OC_NO_LOG_BYTES || !OC_DEBUG */
#define OC_LOGbytes_WITH_COMPONENT(component, bytes, length)                   \
  do {                                                                         \
    if ((length) == 0) {                                                       \
      break;                                                                   \
    }                                                                          \
    const oc_logger_t *_logger = oc_log_get_logger();                          \
    if (_logger->level < OC_LOG_LEVEL_TRACE) {                                 \
      break;                                                                   \
    }                                                                          \
    if ((_logger->components & (component)) == 0) {                            \
      break;                                                                   \
    }                                                                          \
    oc_string_t _oc_log_bytes_buf;                                             \
    memset(&_oc_log_bytes_buf, 0, sizeof(_oc_log_bytes_buf));                  \
    oc_alloc_string(&_oc_log_bytes_buf,                                        \
                    (length)*3 + 1 < 2048 ? (length)*3 + 1 : 2048);            \
    size_t _oc_log_bytes_buf_size = oc_string_len(_oc_log_bytes_buf);          \
    if (_oc_log_bytes_buf_size == 0) {                                         \
      break;                                                                   \
    }                                                                          \
    char *_oc_log_bytes_buf_ptr = oc_string(_oc_log_bytes_buf);                \
    memset(_oc_log_bytes_buf_ptr, 0, _oc_log_bytes_buf_size);                  \
    SNPRINTFbytes(_oc_log_bytes_buf_ptr, _oc_log_bytes_buf_size - 1, bytes,    \
                  length);                                                     \
    if (_logger->fn != NULL) {                                                 \
      _logger->fn(OC_LOG_LEVEL_TRACE, component, __FILENAME__, __LINE__,       \
                  __func__, "%s", _oc_log_bytes_buf_ptr);                      \
      oc_free_string(&_oc_log_bytes_buf);                                      \
      break;                                                                   \
    }                                                                          \
    char _oc_log_fn_buf[64] = { 0 };                                           \
    oc_clock_time_rfc3339(_oc_log_fn_buf, sizeof(_oc_log_fn_buf));             \
    OC_PRINTF("[OC %s]", _oc_log_fn_buf);                                      \
    if ((component) != OC_LOG_COMPONENT_DEFAULT) {                             \
      OC_PRINTF(" (%s)", oc_log_component_name(component));                    \
    }                                                                          \
    OC_PRINTF(": %s:%d <%s>: bytes %s\n", __FILENAME__, __LINE__, __func__,    \
              _oc_log_bytes_buf_ptr);                                          \
    oc_free_string(&_oc_log_bytes_buf);                                        \
    fflush(stdout);                                                            \
  } while (0)
#endif /* !OC_NO_LOG_BYTES && OC_DEBUG */
#endif /* !OC_LOGbytes_WITH_COMPONENT */

#ifndef OC_LOGbytes
#if defined(OC_NO_LOG_BYTES) || !defined(OC_DEBUG) ||                          \
  !OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE)
#define OC_LOGbytes(bytes, length)
#else /* OC_NO_LOG_BYTES || !OC_DEBUG */
#define OC_LOGbytes(bytes, length)                                             \
  OC_LOGbytes_WITH_COMPONENT(OC_LOG_COMPONENT_DEFAULT, bytes, length)
#endif /* !OC_NO_LOG_BYTES && OC_DEBUG */
#endif /* !OC_LOGbytes */

#endif /* OC_PORT_LOG_INTERNAL_H */

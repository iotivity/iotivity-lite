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
#include "oc_log.h"
#include "oc_helpers.h"

#include <inttypes.h>

#ifndef __FILENAME__
#ifdef WIN32
#define __FILENAME__                                                           \
  (strrchr(__FILE__, '\\') ? strrchr(__FILE__, '\\') + 1 : __FILE__)
#else
#define __FILENAME__                                                           \
  (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif
#endif /* !__FILENAME__ */

#define SPRINTF(...) sprintf(__VA_ARGS__)
#define SNPRINTF(...) snprintf(__VA_ARGS__)

#ifdef __ANDROID__
#include "android/oc_log_android.h"
#define TAG "OC-JNI"
#define PRINT(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

#if defined(OC_DEBUG) || defined(OC_PUSHDEBUG)
#define OC_LOG(level, ...)                                                     \
  android_log(oc_log_level_to_label(level), __FILE__, __func__, __LINE__,      \
              __VA_ARGS__)
#define OC_LOGipaddr(endpoint)                                                 \
  android_log_ipaddr("DEBUG", __FILE__, __func__, __LINE__, endpoint)
#define OC_LOGbytes(bytes, length)                                             \
  android_log_bytes("DEBUG", __FILE__, __func__, __LINE__, bytes, length)
#else /* defined(OC_DEBUG) || defined(OC_PUSHDEBUG) */
#define OC_LOG(level, ...)
#define OC_LOGipaddr(endpoint)
#define OC_LOGbytes(bytes, length)
#endif /* !defined(OC_DEBUG) && !defined(OC_PUSHDEBUG) */
#endif

#ifndef PRINT
#define PRINT(...) printf(__VA_ARGS__)
#endif /* !PRINT */

// port's layer can override this macro to provide its own logger
#ifndef OC_LOG
#define OC_LOG(log_level, ...)                                                 \
  do {                                                                         \
    oc_logger_t *logger = oc_log_get_logger();                                 \
    if (logger->level < (log_level)) {                                         \
      break;                                                                   \
    }                                                                          \
    if (logger->fn != NULL) {                                                  \
      logger->fn(log_level, OC_LOG_COMPONENT_DEFAULT, __FILENAME__, __LINE__,  \
                 __func__, __VA_ARGS__);                                       \
      break;                                                                   \
    }                                                                          \
    char _oc_log_fn_buf[64] = { 0 };                                           \
    oc_clock_time_rfc3339(_oc_log_fn_buf, sizeof(_oc_log_fn_buf));             \
    PRINT("[OC %s] %s: %s:%d <%s>: ", _oc_log_fn_buf,                          \
          oc_log_level_to_label(log_level), __FILENAME__, __LINE__, __func__); \
    PRINT(__VA_ARGS__);                                                        \
    PRINT("\n");                                                               \
    fflush(stdout);                                                            \
  } while (0)
#endif /* !OC_LOG */

#ifndef OC_LOG_MAXIMUM_LEVEL
#define OC_LOG_MAXIMUM_LEVEL OC_LOG_LEVEL_DISABLED_MACRO
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

#define PRINT_ENDPOINT_ADDR(endpoint, addr_memb)                               \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    if ((endpoint).flags & SECURED)                                            \
      scheme = "coaps";                                                        \
    if ((endpoint).flags & TCP)                                                \
      scheme = "coap+tcp";                                                     \
    if ((endpoint).flags & TCP && (endpoint).flags & SECURED)                  \
      scheme = "coaps+tcp";                                                    \
    if ((endpoint).flags & IPV4) {                                             \
      PRINT("%s://%d.%d.%d.%d:%d", scheme,                                     \
            ((endpoint).addr_memb.ipv4.address)[0],                            \
            ((endpoint).addr_memb.ipv4.address)[1],                            \
            ((endpoint).addr_memb.ipv4.address)[2],                            \
            ((endpoint).addr_memb.ipv4.address)[3],                            \
            (endpoint).addr_memb.ipv4.port);                                   \
    } else {                                                                   \
      PRINT("%s://[", scheme);                                                 \
      PRINT("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"            \
            ":%02x%02x:%02x%02x",                                              \
            ((endpoint).addr_memb.ipv6.address)[0],                            \
            ((endpoint).addr_memb.ipv6.address)[1],                            \
            ((endpoint).addr_memb.ipv6.address)[2],                            \
            ((endpoint).addr_memb.ipv6.address)[3],                            \
            ((endpoint).addr_memb.ipv6.address)[4],                            \
            ((endpoint).addr_memb.ipv6.address)[5],                            \
            ((endpoint).addr_memb.ipv6.address)[6],                            \
            ((endpoint).addr_memb.ipv6.address)[7],                            \
            ((endpoint).addr_memb.ipv6.address)[8],                            \
            ((endpoint).addr_memb.ipv6.address)[9],                            \
            ((endpoint).addr_memb.ipv6.address)[10],                           \
            ((endpoint).addr_memb.ipv6.address)[11],                           \
            ((endpoint).addr_memb.ipv6.address)[12],                           \
            ((endpoint).addr_memb.ipv6.address)[13],                           \
            ((endpoint).addr_memb.ipv6.address)[14],                           \
            ((endpoint).addr_memb.ipv6.address)[15]);                          \
      if ((endpoint).addr_memb.ipv6.scope > 0) {                               \
        PRINT("%%%d", (int)(endpoint).addr_memb.ipv6.scope);                   \
      }                                                                        \
      PRINT("]:%d", (int)(endpoint).addr_memb.ipv6.port);                      \
    }                                                                          \
  } while (0)

#define PRINTipaddr(endpoint) PRINT_ENDPOINT_ADDR(endpoint, addr)
#define PRINTipaddr_local(endpoint) PRINT_ENDPOINT_ADDR(endpoint, addr_local)

#define IPADDR_BUFF_SIZE 64 // max size : scheme://[ipv6%scope]:port = 63 bytes

#define SNPRINT_ENDPOINT_ADDR(str, size, endpoint, addr_memb)                  \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    if ((endpoint).flags & SECURED)                                            \
      scheme = "coaps";                                                        \
    if ((endpoint).flags & TCP)                                                \
      scheme = "coap+tcp";                                                     \
    if ((endpoint).flags & TCP && (endpoint).flags & SECURED)                  \
      scheme = "coaps+tcp";                                                    \
    memset(str, 0, size);                                                      \
    if ((endpoint).flags & IPV4) {                                             \
      SNPRINTF(str, size, "%s://%d.%d.%d.%d:%d", scheme,                       \
               ((endpoint).addr_memb.ipv4.address)[0],                         \
               ((endpoint).addr_memb.ipv4.address)[1],                         \
               ((endpoint).addr_memb.ipv4.address)[2],                         \
               ((endpoint).addr_memb.ipv4.address)[3],                         \
               (endpoint).addr_memb.ipv4.port);                                \
    } else {                                                                   \
      char scope[5] = { 0 };                                                   \
      if ((endpoint).addr_memb.ipv6.scope > 0) {                               \
        SNPRINTF(scope, sizeof(scope), "%%%d",                                 \
                 (int)(endpoint).addr_memb.ipv6.scope);                        \
      }                                                                        \
      SNPRINTF(                                                                \
        str, size,                                                             \
        "%s://"                                                                \
        "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"     \
        "%02x%02x%s]:%d",                                                      \
        scheme, ((endpoint).addr_memb.ipv6.address)[0],                        \
        ((endpoint).addr_memb.ipv6.address)[1],                                \
        ((endpoint).addr_memb.ipv6.address)[2],                                \
        ((endpoint).addr_memb.ipv6.address)[3],                                \
        ((endpoint).addr_memb.ipv6.address)[4],                                \
        ((endpoint).addr_memb.ipv6.address)[5],                                \
        ((endpoint).addr_memb.ipv6.address)[6],                                \
        ((endpoint).addr_memb.ipv6.address)[7],                                \
        ((endpoint).addr_memb.ipv6.address)[8],                                \
        ((endpoint).addr_memb.ipv6.address)[9],                                \
        ((endpoint).addr_memb.ipv6.address)[10],                               \
        ((endpoint).addr_memb.ipv6.address)[11],                               \
        ((endpoint).addr_memb.ipv6.address)[12],                               \
        ((endpoint).addr_memb.ipv6.address)[13],                               \
        ((endpoint).addr_memb.ipv6.address)[14],                               \
        ((endpoint).addr_memb.ipv6.address)[15], scope,                        \
        (endpoint).addr_memb.ipv6.port);                                       \
    }                                                                          \
  } while (0)

#define SNPRINTFipaddr(str, size, endpoint)                                    \
  SNPRINT_ENDPOINT_ADDR(str, size, endpoint, addr)

#define SNPRINTFbytes(buff, size, data, len)                                   \
  do {                                                                         \
    char *beg = (buff);                                                        \
    char *end = (buff) + (size);                                               \
    /* without _oc_log_ret = 9 has sometimes */                                \
    uint8_t *_oc_log_data = (uint8_t *)(data);                                 \
    for (size_t i = 0; (beg <= (end - 3)) && (i < (size_t)(len)); i++) {       \
      int _oc_log_ret = (i == 0) ? SPRINTF(beg, "%02x", _oc_log_data[i])       \
                                 : SPRINTF(beg, ":%02x", _oc_log_data[i]);     \
      if (_oc_log_ret < 0) {                                                   \
        break;                                                                 \
      }                                                                        \
      beg += _oc_log_ret;                                                      \
    }                                                                          \
  } while (0)

#if OC_DBG_IS_ENABLED
#define OC_LOG_ENDPOINT_ADDR(endpoint, addr_memb)                              \
  do {                                                                         \
    oc_logger_t *logger = oc_log_get_logger();                                 \
    if (logger->level < OC_LOG_LEVEL_DEBUG) {                                  \
      break;                                                                   \
    }                                                                          \
    char _oc_log_endpoint_buf[256];                                            \
    memset(_oc_log_endpoint_buf, 0, sizeof(_oc_log_endpoint_buf));             \
    SNPRINT_ENDPOINT_ADDR(_oc_log_endpoint_buf, sizeof(_oc_log_endpoint_buf),  \
                          endpoint, addr_memb);                                \
    if (logger->fn != NULL) {                                                  \
      logger->fn(OC_LOG_LEVEL_DEBUG, OC_LOG_COMPONENT_DEFAULT, __FILENAME__,   \
                 __LINE__, __func__, "%s", _oc_log_endpoint_buf);              \
      break;                                                                   \
    }                                                                          \
    char _oc_log_fn_buf[64] = { 0 };                                           \
    oc_clock_time_rfc3339(_oc_log_fn_buf, sizeof(_oc_log_fn_buf));             \
    PRINT("[OC %s] %s: %s:%d <%s>: endpoint %s\n", _oc_log_fn_buf,             \
          oc_log_level_to_label(OC_LOG_LEVEL_DEBUG), __FILENAME__, __LINE__,   \
          __func__, _oc_log_endpoint_buf);                                     \
    fflush(stdout);                                                            \
  } while (0)
#ifndef OC_LOGipaddr
#define OC_LOGipaddr(endpoint) OC_LOG_ENDPOINT_ADDR(endpoint, addr)
#endif /* !OC_LOGipaddr */
#ifndef OC_LOGipaddr_local
#define OC_LOGipaddr_local(endpoint) OC_LOG_ENDPOINT_ADDR(endpoint, addr_local)
#endif /* !OC_LOGipaddr_local */
#else  /* OC_DBG_IS_ENABLED */
#define OC_LOGipaddr(endpoint)
#define OC_LOGipaddr_local(endpoint)
#endif /* !OC_DBG_IS_ENABLED */

#ifndef OC_LOGbytes
#if defined(OC_NO_LOG_BYTES) || !defined(OC_DEBUG) ||                          \
  !OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE)
#define OC_LOGbytes(bytes, length)
#else /* OC_NO_LOG_BYTES || !OC_DEBUG */
#define OC_LOGbytes(bytes, length)                                             \
  do {                                                                         \
    if ((length) == 0) {                                                       \
      break;                                                                   \
    }                                                                          \
    oc_logger_t *logger = oc_log_get_logger();                                 \
    if (logger->level < OC_LOG_LEVEL_TRACE) {                                  \
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
    if (logger->fn != NULL) {                                                  \
      logger->fn(OC_LOG_LEVEL_TRACE, OC_LOG_COMPONENT_DEFAULT, __FILENAME__,   \
                 __LINE__, __func__, "%s", _oc_log_bytes_buf_ptr);             \
      oc_free_string(&_oc_log_bytes_buf);                                      \
      break;                                                                   \
    }                                                                          \
    char _oc_log_fn_buf[64] = { 0 };                                           \
    oc_clock_time_rfc3339(_oc_log_fn_buf, sizeof(_oc_log_fn_buf));             \
    PRINT("[OC %s] V: %s:%d <%s>: bytes %s\n", _oc_log_fn_buf, __FILENAME__,   \
          __LINE__, __func__, _oc_log_bytes_buf_ptr);                          \
    oc_free_string(&_oc_log_bytes_buf);                                        \
    fflush(stdout);                                                            \
  } while (0)
#endif /* !OC_NO_LOG_BYTES && OC_DEBUG */
#endif /* !OC_LOGbytes */

#endif /* OC_PORT_LOG_INTERNAL_H */

/*
// Copyright (c) 2016 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
/**
  @file
*/
#ifndef OC_LOG_H
#define OC_LOG_H

#include <stdio.h>

#ifdef __ANDROID__
#include "android/oc_log_android.h"
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#ifdef __ANDROID__
#define TAG "OC-JNI"
#define PRINT(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#else
#define PRINT(...) printf(__VA_ARGS__)
#endif

#define SPRINTF(...) sprintf(__VA_ARGS__)
#define SNPRINTF(...) snprintf(__VA_ARGS__)

#define PRINTipaddr(endpoint)                                                  \
  do {                                                                         \
    const char *scheme = "coap";                                               \
    if ((endpoint).flags & SECURED)                                            \
      scheme = "coaps";                                                        \
    if ((endpoint).flags & TCP)                                                \
      scheme = "coap+tcp";                                                     \
    if ((endpoint).flags & TCP && (endpoint).flags & SECURED)                  \
      scheme = "coaps+tcp";                                                    \
    if ((endpoint).flags & IPV4) {                                             \
      PRINT("%s://%d.%d.%d.%d:%d", scheme, ((endpoint).addr.ipv4.address)[0],  \
            ((endpoint).addr.ipv4.address)[1],                                 \
            ((endpoint).addr.ipv4.address)[2],                                 \
            ((endpoint).addr.ipv4.address)[3], (endpoint).addr.ipv4.port);     \
    } else {                                                                   \
      PRINT(                                                                   \
        "%s://[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"    \
        "02x:%"                                                                \
        "02x%"                                                                 \
        "02x]:%d",                                                             \
        scheme, ((endpoint).addr.ipv6.address)[0],                             \
        ((endpoint).addr.ipv6.address)[1], ((endpoint).addr.ipv6.address)[2],  \
        ((endpoint).addr.ipv6.address)[3], ((endpoint).addr.ipv6.address)[4],  \
        ((endpoint).addr.ipv6.address)[5], ((endpoint).addr.ipv6.address)[6],  \
        ((endpoint).addr.ipv6.address)[7], ((endpoint).addr.ipv6.address)[8],  \
        ((endpoint).addr.ipv6.address)[9], ((endpoint).addr.ipv6.address)[10], \
        ((endpoint).addr.ipv6.address)[11],                                    \
        ((endpoint).addr.ipv6.address)[12],                                    \
        ((endpoint).addr.ipv6.address)[13],                                    \
        ((endpoint).addr.ipv6.address)[14],                                    \
        ((endpoint).addr.ipv6.address)[15], (endpoint).addr.ipv6.port);        \
    }                                                                          \
  } while (0)

#define PRINTipaddr_local(endpoint)                                            \
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
            ((endpoint).addr_local.ipv4.address)[0],                           \
            ((endpoint).addr_local.ipv4.address)[1],                           \
            ((endpoint).addr_local.ipv4.address)[2],                           \
            ((endpoint).addr_local.ipv4.address)[3],                           \
            (endpoint).addr_local.ipv4.port);                                  \
    } else {                                                                   \
      PRINT(                                                                   \
        "%s://[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%"    \
        "02x:%"                                                                \
        "02x%"                                                                 \
        "02x]:%d",                                                             \
        scheme, ((endpoint).addr_local.ipv6.address)[0],                       \
        ((endpoint).addr_local.ipv6.address)[1],                               \
        ((endpoint).addr_local.ipv6.address)[2],                               \
        ((endpoint).addr_local.ipv6.address)[3],                               \
        ((endpoint).addr_local.ipv6.address)[4],                               \
        ((endpoint).addr_local.ipv6.address)[5],                               \
        ((endpoint).addr_local.ipv6.address)[6],                               \
        ((endpoint).addr_local.ipv6.address)[7],                               \
        ((endpoint).addr_local.ipv6.address)[8],                               \
        ((endpoint).addr_local.ipv6.address)[9],                               \
        ((endpoint).addr_local.ipv6.address)[10],                              \
        ((endpoint).addr_local.ipv6.address)[11],                              \
        ((endpoint).addr_local.ipv6.address)[12],                              \
        ((endpoint).addr_local.ipv6.address)[13],                              \
        ((endpoint).addr_local.ipv6.address)[14],                              \
        ((endpoint).addr_local.ipv6.address)[15],                              \
        (endpoint).addr_local.ipv6.port);                                      \
    }                                                                          \
  } while (0)

#define IPADDR_BUFF_SIZE    64 // max size : scheme://[ipv6]:port = 59 bytes

#define SNPRINTFipaddr(str, size, endpoint)                                    \
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
            ((endpoint).addr.ipv4.address)[0],                                 \
            ((endpoint).addr.ipv4.address)[1],                                 \
            ((endpoint).addr.ipv4.address)[2],                                 \
            ((endpoint).addr.ipv4.address)[3], (endpoint).addr.ipv4.port);     \
    } else {                                                                   \
      SNPRINTF(str, size,                                                      \
        "%s://"                                                                \
        "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:"     \
        "%02x%02x]:%d",                                                        \
        scheme, ((endpoint).addr.ipv6.address)[0],                             \
        ((endpoint).addr.ipv6.address)[1], ((endpoint).addr.ipv6.address)[2],  \
        ((endpoint).addr.ipv6.address)[3], ((endpoint).addr.ipv6.address)[4],  \
        ((endpoint).addr.ipv6.address)[5], ((endpoint).addr.ipv6.address)[6],  \
        ((endpoint).addr.ipv6.address)[7], ((endpoint).addr.ipv6.address)[8],  \
        ((endpoint).addr.ipv6.address)[9], ((endpoint).addr.ipv6.address)[10], \
        ((endpoint).addr.ipv6.address)[11],                                    \
        ((endpoint).addr.ipv6.address)[12],                                    \
        ((endpoint).addr.ipv6.address)[13],                                    \
        ((endpoint).addr.ipv6.address)[14],                                    \
        ((endpoint).addr.ipv6.address)[15], (endpoint).addr.ipv6.port);        \
    }                                                                          \
  } while (0)

#define SNPRINTFbytes(buff, size, data, len)                                   \
  do {                                                                         \
    char *beg = (buff);                                                        \
    char *end = (buff) + (size);                                               \
    for (size_t i = 0; beg <= (end - 3) && i < (len); i++) {                   \
      beg += (i == 0) ? SPRINTF(beg, "%02x", data[i]) :                        \
                        SPRINTF(beg, ":%02x", data[i]);                        \
    }                                                                          \
  } while (0)

#ifdef OC_DEBUG
#ifdef __ANDROID__
#define OC_LOG(level, ...)          android_log(level, __FILE__, __func__, __LINE__, __VA_ARGS__)
#define OC_LOGipaddr(endpoint)      android_log_ipaddr("DEBUG", __FILE__, __func__, __LINE__, endpoint)
#define OC_LOGbytes(bytes, length)  android_log_bytes("DEBUG", __FILE__, __func__, __LINE__, bytes, length)
#else  /* ! __ANDROID */
#define OC_LOG(level, ...)                                                     \
  do {                                                                         \
    PRINT("%s: %s <%s:%d>: ", level, __FILE__, __func__, __LINE__);            \
    PRINT(__VA_ARGS__);                                                        \
    PRINT("\n");                                                               \
  } while (0)
#define OC_LOGipaddr(endpoint)                                                 \
  do {                                                                         \
    PRINT("DEBUG: %s <%s:%d>: ", __FILE__, __func__, __LINE__);                \
    PRINTipaddr(endpoint);                                                     \
    PRINT("\n");                                                               \
  } while (0)
#define OC_LOGbytes(bytes, length)                                             \
  do {                                                                         \
    PRINT("DEBUG: %s <%s:%d>: ", __FILE__, __func__, __LINE__);                \
    uint16_t i;                                                                \
    for (i = 0; i < length; i++)                                               \
      PRINT(" %02X", bytes[i]);                                                \
    PRINT("\n");                                                               \
  } while (0)
#endif /* __ANDROID__ */
#define OC_DBG(...) OC_LOG("DEBUG", __VA_ARGS__)
#define OC_WRN(...) OC_LOG("WARNING", __VA_ARGS__)
#define OC_ERR(...) OC_LOG("ERROR", __VA_ARGS__)
#else
#define OC_LOG(...)
#define OC_DBG(...)
#define OC_WRN(...)
#define OC_ERR(...)
#define OC_LOGipaddr(endpoint)
#define OC_LOGbytes(bytes, length)
#endif

#ifdef __cplusplus
}
#endif

#endif /* OC_LOG_H */

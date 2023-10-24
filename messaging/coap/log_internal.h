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

#ifndef COAP_LOG_INTERNAL_H
#define COAP_LOG_INTERNAL_H

#include "port/oc_log_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef COAP_TRACE
#if OC_TRACE_IS_ENABLED
#define COAP_TRACE(...)                                                        \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_TRACE, OC_LOG_COMPONENT_COAP, __VA_ARGS__)
#else /* !OC_TRACE_IS_ENABLED */
#define COAP_TRACE(...)
#endif /* OC_TRACE_IS_ENABLED */
#endif /* !COAP_TRACE */

#ifndef COAP_DBG
#if OC_DBG_IS_ENABLED
#define COAP_DBG(...)                                                          \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_DEBUG, OC_LOG_COMPONENT_COAP, __VA_ARGS__)
#else /* !OC_DBG_IS_ENABLED */
#define COAP_DBG(...)
#endif /* OC_DBG_IS_ENABLED */
#endif /* !COAP_DBG */

#ifndef COAP_INFO
#if OC_INFO_IS_ENABLED
#define COAP_INFO(...)                                                         \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_INFO, OC_LOG_COMPONENT_COAP, __VA_ARGS__)
#else /* !OC_INFO_IS_ENABLED */
#define COAP_INFO(...)
#endif /* OC_INFO_IS_ENABLED */
#endif /* !COAP_INFO */

#ifndef COAP_NOTE
#if OC_NOTE_IS_ENABLED
#define COAP_NOTE(...)                                                         \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_NOTE, OC_LOG_COMPONENT_COAP, __VA_ARGS__)
#else /* !OC_NOTE_IS_ENABLED */
#define COAP_NOTE(...)
#endif /* OC_NOTE_IS_ENABLED */
#endif /* !COAP_NOTE */

#ifndef COAP_WRN
#if OC_WRN_IS_ENABLED
#define COAP_WRN(...)                                                          \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_WARNING, OC_LOG_COMPONENT_COAP,           \
                        __VA_ARGS__)
#else /* !OC_WRN_IS_ENABLED */
#define COAP_WRN(...)
#endif /* OC_WRN_IS_ENABLED */
#endif /* !COAP_WRN */

#ifndef COAP_ERR
#if OC_ERR_IS_ENABLED
#define COAP_ERR(...)                                                          \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_ERROR, OC_LOG_COMPONENT_COAP, __VA_ARGS__)
#else /* !OC_ERR_IS_ENABLED */
#define COAP_ERR(...)
#endif /* OC_ERR_IS_ENABLED */
#endif /* !COAP_ERR */

#if !defined(OC_NO_LOG_BYTES) && OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE)
#define COAP_LOGbytes(bytes, length)                                           \
  OC_LOGbytes_WITH_COMPONENT(OC_LOG_COMPONENT_COAP, bytes, length)
#else /* OC_NO_LOG_BYTES || !OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE) */
#define COAP_LOGbytes(bytes, length)
#endif /* !OC_NO_LOG_BYTES && OC_LOG_LEVEL_IS_ENABLED(OC_LOG_LEVEL_TRACE) */

#if OC_DBG_IS_ENABLED
#define COAP_LOGipaddr(endpoint)                                               \
  OC_LOGipaddr_WITH_COMPONENT(OC_LOG_COMPONENT_COAP, endpoint)
#define COAP_LOGipaddr_local(endpoint)                                         \
  OC_LOGipaddr_local_WITH_COMPONENT(OC_LOG_COMPONENT_COAP, endpoint)
#else /* !OC_DBG_IS_ENABLED */
#define COAP_LOGipaddr(endpoint)
#define COAP_LOGipaddr_local(endpoint)
#endif /* OC_DBG_IS_ENABLED */

#ifdef __cplusplus
}
#endif

#endif /* COAP_LOG_INTERNAL_H */

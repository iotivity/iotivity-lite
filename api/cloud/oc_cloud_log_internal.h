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

#ifndef OC_CLOUD_LOG_INTERNAL_H
#define OC_CLOUD_LOG_INTERNAL_H

#include "port/oc_log_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OC_CLOUD_TRACE
#if OC_TRACE_IS_ENABLED
#define OC_CLOUD_TRACE(...)                                                    \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_TRACE, OC_LOG_COMPONENT_CLOUD, __VA_ARGS__)
#else /* !OC_TRACE_IS_ENABLED */
#define OC_CLOUD_TRACE(...)
#endif /* OC_TRACE_IS_ENABLED */
#endif /* !OC_CLOUD_TRACE */

#ifndef OC_CLOUD_DBG
#if OC_DBG_IS_ENABLED
#define OC_CLOUD_DBG(...)                                                      \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_DEBUG, OC_LOG_COMPONENT_CLOUD, __VA_ARGS__)
#else /* !OC_DBG_IS_ENABLED */
#define OC_CLOUD_DBG(...)
#endif /* OC_DBG_IS_ENABLED */
#endif /* !OC_CLOUD_DBG */

#ifndef OC_CLOUD_INFO
#if OC_INFO_IS_ENABLED
#define OC_CLOUD_INFO(...)                                                     \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_INFO, OC_LOG_COMPONENT_CLOUD, __VA_ARGS__)
#else /* !OC_INFO_IS_ENABLED */
#define OC_CLOUD_INFO(...)
#endif /* OC_INFO_IS_ENABLED */
#endif /* !OC_CLOUD_INFO */

#ifndef OC_CLOUD_NOTE
#if OC_NOTE_IS_ENABLED
#define OC_CLOUD_NOTE(...)                                                     \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_NOTICE, OC_LOG_COMPONENT_CLOUD,           \
                        __VA_ARGS__)
#else /* !OC_NOTE_IS_ENABLED */
#define OC_CLOUD_NOTE(...)
#endif /* OC_NOTE_IS_ENABLED */
#endif /* !OC_CLOUD_NOTE */

#ifndef OC_CLOUD_WRN
#if OC_WRN_IS_ENABLED
#define OC_CLOUD_WRN(...)                                                      \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_WARNING, OC_LOG_COMPONENT_CLOUD,          \
                        __VA_ARGS__)
#else /* !OC_WRN_IS_ENABLED */
#define OC_CLOUD_WRN(...)
#endif /* OC_WRN_IS_ENABLED */
#endif /* !OC_CLOUD_WRN */

#ifndef OC_CLOUD_ERR
#if OC_ERR_IS_ENABLED
#define OC_CLOUD_ERR(...)                                                      \
  OC_LOG_WITH_COMPONENT(OC_LOG_LEVEL_ERROR, OC_LOG_COMPONENT_CLOUD, __VA_ARGS__)
#else /* !OC_ERR_IS_ENABLED */
#define OC_CLOUD_ERR(...)
#endif /* OC_ERR_IS_ENABLED */
#endif /* !OC_CLOUD_ERR */

#ifdef __cplusplus
}
#endif

#endif /* OC_LOG_INTERNAL_H */

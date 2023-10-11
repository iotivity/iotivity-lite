/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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
 * @file oc_features.h
 *
 * @brief Compile time features.
 *
 * @author Daniel Adam
 */

#ifndef OC_FEATURES_H
#define OC_FEATURES_H

#include "oc_config.h"
#if defined(__linux__) && !defined(__ANDROID_API__) && defined(OC_CLIENT) &&   \
  defined(OC_TCP)
/* Support asynchronous TCP connect */
#define OC_HAS_FEATURE_TCP_ASYNC_CONNECT
#endif /* __linux__ && !__ANDROID_API__ && OC_CLIENT && OC_TCP */

#if defined(OC_PUSH) && defined(OC_SERVER) && defined(OC_CLIENT) &&            \
  defined(OC_DYNAMIC_ALLOCATION) && defined(OC_COLLECTIONS_IF_CREATE)
#define OC_HAS_FEATURE_PUSH
#endif

#if defined(OC_SECURITY) && defined(OC_RESOURCE_ACCESS_IN_RFOTM)
#define OC_HAS_FEATURE_RESOURCE_ACCESS_IN_RFOTM
#endif

#if defined(PLGD_DEV_TIME) && (defined(_WIN64) || defined(_WIN32) ||           \
                               defined(__linux__) || defined(__ANDROID__))
#define OC_HAS_FEATURE_PLGD_TIME
#endif /* PLGD_DEV_TIME */

#if defined(PLGD_DEV_HAWKBIT) && defined(OC_SOFTWARE_UPDATE) &&                \
  defined(ESP_PLATFORM)
#define OC_HAS_FEATURE_PLGD_HAWKBIT
#endif /* PLGD_DEV_HAWKBIT */

#if defined(OC_ETAG) && defined(OC_SERVER)
#define OC_HAS_FEATURE_ETAG

#ifdef OC_RES_BATCH_SUPPORT
#define OC_HAS_FEATURE_ETAG_INCREMENTAL_CHANGES
#endif /* OC_RES_BATCH_SUPPORT */

#endif /* OC_ETAG && OC_SERVER */

#ifdef OC_HAS_FEATURE_ETAG
#define OC_HAS_FEATURE_CRC_ENCODER
#endif /* OC_HAS_FEATURE_ETAG */

#endif /* OC_FEATURES_H */

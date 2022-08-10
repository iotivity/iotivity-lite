/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef OC_FEATURES_H
#define OC_FEATURES_H

#include "oc_config.h"
#if defined(__linux__) && !defined(__ANDROID_API__) && defined(OC_CLIENT) &&   \
  defined(OC_TCP)
/* Support asynchronous TCP connect */
#define OC_HAS_FEATURE_TCP_ASYNC_CONNECT
#endif /* __linux__ && OC_CLIENT && OC_TCP */

#endif /* OC_FEATURES_H */

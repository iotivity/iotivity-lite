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

#ifndef OC_PORT_WINDOWS_CLOCK_INTERNAL_H
#define OC_PORT_WINDOWS_CLOCK_INTERNAL_H

#include "port/oc_clock.h"

#define WIN32_LEAN_AND_MEAN
#include "windows.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Convert oc_clock_time_t to Windows filetime.  */
FILETIME oc_clock_time_to_filetime(oc_clock_time_t time);

/** @brief Convert Windows filetime to oc_clock_time_t. */
oc_clock_time_t oc_clock_time_from_filetime(FILETIME ftime);

#ifdef __cplusplus
}
#endif

#endif /* OC_PORT_WINDOWS_CLOCK_INTERNAL_H */

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

#include "utility.h"

#include "port/oc_clock.h"

#ifdef __unix__
#include <sys/time.h>
#endif /* __unix__ */

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "port/windows/oc_clock_internal.h"
#endif /* _WIN32 */

#include <chrono>

namespace oc {

#ifdef __unix__
bool
SetSystemTimeUnix(oc_clock_time_t now, std::chrono::milliseconds shift)
{
  struct timeval time = {};
  time.tv_sec = (now / OC_CLOCK_SECOND) +
                std::chrono::duration_cast<std::chrono::seconds>(shift).count();
  oc_clock_time_t rem_ticks = now % OC_CLOCK_SECOND;
  time.tv_usec = static_cast<suseconds_t>(
    (static_cast<double>(rem_ticks) * 1.e06) / OC_CLOCK_SECOND);
  return settimeofday(&time, nullptr) == 0;
}
#endif /* __unix__ */

#ifdef _WIN32
bool
SetSystemTimeWin(oc_clock_time_t now, std::chrono::milliseconds shift)
{
  oc_clock_time_t ct =
    now + (oc_clock_time_t)((shift.count() / (double)1000) * OC_CLOCK_SECOND);
  FILETIME ftime{ oc_clock_time_to_filetime(ct) };
  SYSTEMTIME stime{};
  if (!FileTimeToSystemTime(&ftime, &stime)) {
    return false;
  }
  return SetSystemTime(&stime);
}
#endif /* _WIN32 */

bool
SetSystemTime(oc_clock_time_t now, std::chrono::milliseconds shift)
{
#ifdef __unix__
  return SetSystemTimeUnix(now, shift);
#endif /* __unix__ */
#ifdef _WIN32
  return SetSystemTimeWin(now, shift);
#endif /* _WIN32 */
  return false;
}

} // namespace oc

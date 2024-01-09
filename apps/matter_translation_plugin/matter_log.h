/****************************************************************************
 *
 *   Copyright (c) 2020 Project CHIP Authors
 *   Copyright (c) 2023 ETRI Joo-Chul Kevin Lee (rune@etri.re.kr)
 *   All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 *
 ****************************************************************************/

#pragma once

#ifdef OC_BRG_DEBUG
#define OC_BRG_LOG(...) \
    do { \
      printf("=> %s:%d <%s()>: ", __FILE__, __LINE__, __func__); \
      printf(__VA_ARGS__); \
      printf("\n"); \
    } while(0)
#else
#define OC_BRG_LOG(...)
#endif

#define OC_BRG_ERR(...) \
    do { \
      printf("=> %s:%d <%s()>: ", __FILE__, __LINE__, __func__); \
      printf(__VA_ARGS__); \
      printf("\n"); \
    } while(0)


/**
 *  @def VerifyOrReturn(expr, ...)
 *
 *  @brief
 *    Returns from the void function if expression evaluates to false
 *
 *  Example usage:
 *
 *  @code
 *    VerifyOrReturn(param != nullptr, LogError("param is nullptr"));
 *  @endcode
 *
 *  @param[in]  expr        A Boolean expression to be evaluated.
 *  @param[in]  ...         Statements to execute before returning. Optional.
 */
#define VerifyOrReturn(expr, ...) \
    do \
    { \
      if (!(expr)) \
      { \
        __VA_ARGS__; \
        return; \
      } \
    } while (false)


/**
 *  @def VerifyOrReturnValue(expr, value, ...)
 *
 *  @brief
 *    Returns a specified value if expression evaluates to false
 *
 *  Example usage:
 *
 *  @code
 *    VerifyOrReturnError(param != nullptr, Foo());
 *  @endcode
 *
 *  @param[in]  expr        A Boolean expression to be evaluated.
 *  @param[in]  value       A value to return if @a expr is false.
 *  @param[in]  ...         Statements to execute before returning. Optional.
 */
#define VerifyOrReturnValue(expr, value, ...) \
    do \
    { \
      if (!(expr)) \
      { \
        __VA_ARGS__; \
        return (value); \
      } \
    } while (false)


/**
 *  @def VerifyOrDo(expr, ...)
 *
 *  @brief
 *    do something if expression evaluates to false
 *
 *  Example usage:
 *
 * @code
 *    VerifyOrDo(param != nullptr, LogError("param is nullptr"));
 *  @endcode
 *
 *  @param[in]  expr        A Boolean expression to be evaluated.
 *  @param[in]  ...         Statements to execute.
 */
#define VerifyOrDo(expr, ...) \
    do \
    { \
      if (!(expr)) \
      { \
        __VA_ARGS__; \
      } \
    } while (false)

/****************************************************************************
 *
 * Copyright 2021 Daniel Adam All Rights Reserved.
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
 * @file oc_compiler.h
 *
 * @brief Compiler-specific features.
 *
 * @author Daniel Adam
 */

#ifndef OC_COMPILER_H
#define OC_COMPILER_H

#if defined(__MINGW32__) && (!defined(__GNUC__) || __GNUC__ < 9)
#error "Unsupported compiler on MinGW platform"
#endif /* __MINGW32__ && (!__GNUC__ || __GNUC__ < 9) */

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif /* !__has_attribute */

#ifndef __has_c_attribute
#define __has_c_attribute(x) 0
#endif /* !__has_c_attribute */

#ifndef __has_feature
#define __has_feature(x) 0
#endif /* !__has_feature */

#if defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR >= 6))
#define OC_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#elif __has_feature(c_static_assert)
#define OC_STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)
#else
#define OC_STATIC_ASSERT(...)
#endif

#if defined(__clang__) || defined(__GNUC__)
#define OC_NO_DISCARD_RETURN __attribute__((warn_unused_result))
#else
#define OC_NO_DISCARD_RETURN
#endif

#if defined(__clang__) || defined(__GNUC__)
#define OC_NO_RETURN __attribute__((noreturn))
#else
#define OC_NO_RETURN
#endif

#if (!defined(__clang__) && defined(__GNUC__) && __GNUC__ >= 7) ||             \
  (defined(__clang__) && __clang_major__ >= 10)
#define OC_FALLTHROUGH __attribute__((fallthrough))
#elif __has_c_attribute(fallthrough)
#define OC_FALLTHROUGH [[fallthrough]]
#else
#define OC_FALLTHROUGH /* FALLTHROUGH */
#endif

#if defined(__clang__) || defined(__GNUC__)
#define OC_DEPRECATED(...) __attribute__((deprecated(__VA_ARGS__)))
#else
#define OC_DEPRECATED(...)
#endif

#if defined(__clang__) || defined(__GNUC__)
#define OC_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define OC_NONNULL(...)
#endif

#if defined(__clang__) || defined(__GNUC__)
#define OC_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define OC_RETURNS_NONNULL
#endif

#if defined(__clang__) || defined(__GNUC__)
#define OC_NO_SANITIZE(...) __attribute__((no_sanitize(__VA_ARGS__)))
#else
#define OC_NO_SANITIZE(...)
#endif

#if defined(__clang__) || defined(__GNUC__)
#if defined(__MINGW32__) && defined(__USE_MINGW_ANSI_STDIO) &&                 \
  __USE_MINGW_ANSI_STDIO == 1
#define OC_PRINTF_FORMAT(...) __attribute__((format(gnu_printf, __VA_ARGS__)))
#else
#define OC_PRINTF_FORMAT(...) __attribute__((format(printf, __VA_ARGS__)))
#endif
#else
#define OC_PRINTF_FORMAT(...)
#endif

#if defined(__GNUC__) && __GNUC__ >= 8 && !defined(__clang__)
#define OC_NONSTRING __attribute__((nonstring))
#else
#define OC_NONSTRING
#endif

/* GCC: check for __SANITIZE_ADDRESS__; clang: use __has_feature */
#if defined(__SANITIZE_ADDRESS__) || __has_feature(address_sanitizer)
#define OC_SANITIZE_ADDRESS
#endif

/* GCC: check for __SANITIZE_THREAD__; clang: use __has_feature */
#if defined(__SANITIZE_THREAD__) || __has_feature(thread_sanitizer)
#define OC_SANITIZE_THREAD
#endif

#endif // OC_COMPILER_H

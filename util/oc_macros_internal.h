/****************************************************************************
 *
 * Copyright 2023 Daniel Adam All Rights Reserved.
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

#ifndef OC_MACROS_INTERNAL_H
#define OC_MACROS_INTERNAL_H

#define OC_TO_STR(x) #x

// use only for C-string constants to get string length and not size of a
// pointer, OC_CHAR_ARRAY_LEN(x) should be equal to strlen(x)
#define OC_CHAR_ARRAY_LEN(x) (sizeof(x) - 1)

#define OC_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#if defined(__GNUC__) && !defined(__clang__)
#define OC_DO_PRAGMA(x) _Pragma(#x)
#define GCC_IGNORE_WARNING_START OC_DO_PRAGMA(GCC diagnostic push)
#define GCC_IGNORE_WARNING(warning) OC_DO_PRAGMA(GCC diagnostic ignored warning)
#define GCC_IGNORE_WARNING_END OC_DO_PRAGMA(GCC diagnostic pop)
#else
#define GCC_IGNORE_WARNING_START
#define GCC_IGNORE_WARNING(warning)
#define GCC_IGNORE_WARNING_END
#endif /* __GNUC__ && !__clang__ */

#ifdef __clang__
#define OC_DO_PRAGMA(x) _Pragma(#x)
#define CLANG_IGNORE_WARNING_START OC_DO_PRAGMA(clang diagnostic push)
#define CLANG_IGNORE_WARNING(warning)                                          \
  OC_DO_PRAGMA(clang diagnostic ignored warning)
#define CLANG_IGNORE_WARNING_END OC_DO_PRAGMA(clang diagnostic pop)
#else
#define CLANG_IGNORE_WARNING_START
#define CLANG_IGNORE_WARNING(warning)
#define CLANG_IGNORE_WARNING_END
#endif /* __clang__ */

#endif // OC_MACROS_INTERNAL_H

/****************************************************************************
 *
 * Copyright 2021 Daniel Adam All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_ATOMIC_H
#define OC_ATOMIC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __linux__

#if defined(__GNUC__) && defined(__GNUC_MINOR__) &&                            \
  (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1))

#define OC_ATOMIC

#define OC_ATOMIC_LOAD32(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)

#define OC_ATOMIC_STORE32(x, val)                                              \
  __atomic_store_n(&(x), (val), __ATOMIC_SEQ_CST)

#define OC_ATOMIC_INCREMENT32(x) __atomic_add_fetch(&(x), 1, __ATOMIC_SEQ_CST)

#define OC_ATOMIC_DECREMENT32(x) __atomic_sub_fetch(&(x), 1, __ATOMIC_SEQ_CST)

// Function compares the contents of x with the contents of expected. If equal,
// the operation is a read-modify-write operation that writes desired into x.
// If they are not equal, the operation is a read and the current contents of
// x are written into expected.
//
// If desired is written into x then result is set to true. Otherwise, result
// is set to false.
#define OC_ATOMIC_COMPARE_AND_SWAP32(x, expected, desired, result)             \
  do {                                                                         \
    (result) = __atomic_compare_exchange_n(                                    \
      &(x), &(expected), desired, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);  \
  } while (0)

// aliases for compatibility
#define OC_ATOMIC_LOAD8(x) OC_ATOMIC_LOAD32(x)
#define OC_ATOMIC_STORE8(x, val) OC_ATOMIC_STORE32(x, val)
#define OC_ATOMIC_COMPARE_AND_SWAP8(x, expected, desired, result)              \
  OC_ATOMIC_COMPARE_AND_SWAP32(x, expected, desired, result)

#endif // __GNUC__ >= 4 && __GNUC_MINOR__ >= 1

#endif // __linux__

#if defined(_WIN32) || defined(_WIN64)

#if _MSC_VER

#include <intrin.h>

#define OC_ATOMIC

#define OC_ATOMIC_LOAD8(x) _InterlockedOr8((&x), 0)
#define OC_ATOMIC_LOAD32(x) _InterlockedOr((&x), 0)

#define OC_ATOMIC_STORE8(x, val) _InterlockedExchange8((&x), val)
#define OC_ATOMIC_STORE32(x, val) _InterlockedExchange((&x), val)

#define OC_ATOMIC_INCREMENT32(x) _InterlockedIncrement((&x))

#define OC_ATOMIC_DECREMENT32(x) _InterlockedDecrement((&x))

#define OC_ATOMIC_COMPARE_AND_SWAP8(x, expected, desired, result)              \
  do {                                                                         \
    char _oc_compare_and_swap_initial =                                        \
      _InterlockedCompareExchange8(&(x), (desired), (expected));               \
    (result) = ((expected) == _oc_compare_and_swap_initial);                   \
    if (!result) {                                                             \
      (expected) = _oc_compare_and_swap_initial;                               \
    }                                                                          \
  } while (0)

// Copy the semantics of the Unix version of OC_ATOMIC_COMPARE_AND_SWAP32
// using Windows intrinsics.
#define OC_ATOMIC_COMPARE_AND_SWAP32(x, expected, desired, result)             \
  do {                                                                         \
    int32_t _oc_compare_and_swap_initial =                                     \
      _InterlockedCompareExchange(&(x), (desired), (expected));                \
    (result) = ((expected) == _oc_compare_and_swap_initial);                   \
    if (!result) {                                                             \
      (expected) = _oc_compare_and_swap_initial;                               \
    }                                                                          \
  } while (0)

#endif // _MSC_VER

#endif // defined(_WIN32) || defined(_WIN64)

// fallback to volatile on platforms without atomic support
#ifndef OC_ATOMIC

#pragma message(                                                               \
  "Please check whether volatile guarantees atomicity on your platform, if yes \
then you can disable this warning, if not then please add implementation of \
atomics for your platform to this file")

#define OC_ATOMIC_NOT_SUPPORTED

#define OC_ATOMIC volatile

#define OC_ATOMIC_LOAD32(x) (x)

#define OC_ATOMIC_STORE32(x, val) (x) = (val)

#define OC_ATOMIC_INCREMENT32(x) ++(x)

#define OC_ATOMIC_DECREMENT32(x) --(x)

// Copy the semantics of the Unix version of OC_ATOMIC_COMPARE_AND_SWAP32
// using non-atomic operations.
#define OC_ATOMIC_COMPARE_AND_SWAP32(x, expected, desired, result)             \
  do {                                                                         \
    if ((x) == (expected)) {                                                   \
      (x) = (desired);                                                         \
      (result) = true;                                                         \
    } else {                                                                   \
      (expected) = (x);                                                        \
      (result) = false;                                                        \
    }                                                                          \
  } while (0)

// aliases for compatibility
#define OC_ATOMIC_LOAD8(x) OC_ATOMIC_LOAD32(x)
#define OC_ATOMIC_STORE8(x, val) OC_ATOMIC_STORE32(x, val)
#define OC_ATOMIC_COMPARE_AND_SWAP8(x, expected, desired, result)              \
  OC_ATOMIC_COMPARE_AND_SWAP32(x, expected, desired, result)

#endif

#ifdef __cplusplus
}
#endif

#endif // OC_ATOMIC_H

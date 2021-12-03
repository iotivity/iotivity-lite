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

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __linux__

#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 1)

#define ATOMIC

#define ATOMIC_LOAD(x) __atomic_load_n(&(x), __ATOMIC_SEQ_CST)

#define ATOMIC_STORE(x, val) __atomic_store_n(&(x), (val), __ATOMIC_SEQ_CST)

#define ATOMIC_INCREMENT(x) __atomic_add_fetch(&(x), 1, __ATOMIC_SEQ_CST)

#define ATOMIC_DECREMENT(x) __atomic_sub_fetch(&(x), 1, __ATOMIC_SEQ_CST)

#define ATOMIC_COMPARE_AND_SWAP(x, expected, desired, result)                  \
  do {                                                                         \
    (result) = __atomic_compare_exchange(&(x), &(expected), &(desired), false, \
                                         __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);  \
  } while (0)

#endif // __GNUC__ >= 4 && __GNUC_MINOR__ >= 1

#endif // __linux__

// fallback to volatile on platforms without atomic support
#ifndef ATOMIC

#define ATOMIC volatile

#warning                                                                       \
  "Please implement atomicity on your platform, volatile does not guarantee correct memory ordering"

#define ATOMIC_LOAD(x) (x)

#define ATOMIC_STORE(x, val) (x) = (val)

#define ATOMIC_INCREMENT(x) ++(x)

#define ATOMIC_DECREMENT(x) --(x)

// Simulate behavior of GCC's __atomic_compare_exchange
//
// This function implements a non-atomic compare and exchange operation with
// the same parameters as GCC's __atomic_compare_exchange builtin.
// This compares the contents of x with the contents of expected. If equal,
// the operation is a read-modify-write operation that writes desired into x.
// If they are not equal, the operation is a read and the current contents of
// x are written into expected.
//
// If desired is written into x then result is set to true. Otherwise, result
// is set to false.
#define ATOMIC_COMPARE_AND_SWAP(x, expected, desired, result)                  \
  do {                                                                         \
    if ((x) == (expected)) {                                                   \
      (x) = (desired);                                                         \
      (result) = true;                                                         \
    } else {                                                                   \
      (expected) = (x);                                                        \
      (result) = false;                                                        \
    }                                                                          \
  } while (0)

#endif

#ifdef __cplusplus
}
#endif

#endif // OC_ATOMIC_H

/*
// Copyright (c) 2017 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/
/**
 * @file
 * @brief functions for introspection
 *
 * The IDD information is served up as encoded CBOR content (read as is).
 * If the size of the IDD data is to big for the buffer, then an internal error
 * is returned.  Note that some build options can only serve up introspection
 * data for one device and can not be used if multiple devices are implemented.
 *
 * There are multiple mechanisms for adding introspection data to a server.
 *
 * Add OC_IDD_API (recommended) to the compilers preprocessor macro defines.
 * Then set the introspection data for each device using
 * oc_set_introspection_data function.
 *
 * If OC_IDD_API was added to the preprocessor and the server does not call
 * oc_set_introspection_data the server will look for the file
 * `IDD_<device_index>` in the location specified by oc_storage_config.
 *
 * The final option is to build without OC_IDD_API compiler preprocessor macro
 * define. This is **not recommended** but is provided for backwards
 * compatibility. The instrospection data is read from the headerfile
 * `server_introspection.dat.h`. Introspection data can only be added for a
 * single device.
 *
 * When using the final option the `server_introspeciton.dat.h` must
 * contain two items:
 *  1. A macro `introspection_data_size` that specifies the size of the
 * introspection data in bytes
 *  2. An array `uint8_t introspection_data[]` containing the hex data
 * representing the IDD. The header file must be placed in a folder that gets
 * included in the build.
 */

#ifndef OC_INTROSPECTION_H
#define OC_INTROSPECTION_H

#include <wchar.h>
#include <inttypes.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *
 * @brief Set the IDD by passing in an array containing the data
 *
 * @param device index of the device to which the IDD describes
 * @param IDD an array of CBOR encoded bytes containing the introspection device
 * data
 * @param IDD_size the size of the IDD array
 */
void oc_set_introspection_data(size_t device, uint8_t *IDD, size_t IDD_size);

#ifdef __cplusplus
}
#endif

#endif /* OC_INTROSPECTION_H */

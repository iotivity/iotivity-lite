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
  @file
*/
#ifndef OC_INTROSPECTION_H
#define OC_INTROSPECTION_H

#include "oc_core_res.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief functions for introspection
 *
 * This provides multiple multiple mechanisms for adding introspection data
 * to a server.
 *
 * The IDD information is served up as encoded CBOR contents (read as is).
 * If the size of the IDD data is to big for the buffer, then an internal error
 * is returned.  Note that some build options can only serve up introspection
 * data for one device and can not be used if multiple devices are implemented.
 *
 * - Add OC_IDD_API (recomended) or OC_IDD_FILE to the compilers preprocessor
 * macro defines
 * - Set the introspection data for each device using oc_set_introspection_data
 * or
 * - Create a file that contains the introspection data specify name of the file
 *   using oc_set_introspection_file.
 *
 * If OC_IDD_API was added to the preprocessor and the server does not call
 * oc_set_introspection_data or oc_set_introspection_file the server will look
 * for the file `IDD_<device_index>` in the location specified by
 * oc_storage_config.
 *
 * If OC_IDD_FILE was added to the preprocessor and the server does not call
 * oc_set_introspection_data or oc_set_introspection_file the server will look
 * for the file `server_introspection.dat` in the same location as the server.
 * This is added for backwards compatability with older privious implementations
 * and is not recomended. Introspection data can only be added for a single
 * device.
 *
 * The final option is to build without OC_IDD_API or OC_IDD_FILE to the
 * compilers preprocessor macro defines. This is **not recomended** but is
 * provided for backwards compatability.  The instrospection data is read from
 * the headerfile `server_introspection.dat.h`. Introspection data can only be
 * added for a single device.
 *
 * When using the final options the `server_introspeciton.dat.h` must
 * contain two items:
 *  1. a macro `introspection_data_size` that specifies the size of the
 * introspection data in bytes
 *  2. an array `uint8_t introspection_data[]` containing the hex data
 * representing the IDD The header file must be placed in a folder that gets
 * included in the build.
 */

#if defined OC_IDD_API || defined OC_IDD_API
/**
  @brief sets the filename of the introspection resource.
  if not set the file is "server_introspection.dat" is read from the location
  where the executable resides

  @param device index of the device to which the resource is to be created
  @param filename filename of the IDD file in cbor.
*/
void oc_set_introspection_file(size_t device, const char *filename);

/**
 * @brief Set the IDD by passing in an array containing the data
 *
 * @param device index of the device to which the IDD describes
 * @param IDD an array of CBOR encoded bytes containing the introspection device
 * data
 * @param IDD_size the size of the IDD array
 */
void oc_set_introspection_data(size_t device, uint8_t *IDD, size_t IDD_size);
#endif /* OC_IDD_API or OC_IDD_FILE */
#ifdef __cplusplus
}
#endif

#endif /* OC_INTROSPECTION_H */

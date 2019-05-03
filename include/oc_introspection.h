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
 * @brief functions for introspection .
 * The introspection mechanism is implemented by 2 different mechanisms
 *
 * The first mechanism is reading the IDD file from the location specified by
 * oc_storage_config.  The IDD information can be provided in two ways. If can
 * be added to the oc_storage before the server starts using the name
 * IDD_<device_index>. Or it can be added at run time by passing in the IDD data
 * as a byte array calling oc_set_introspection_data. The IDD information is
 * served up as encoded CBOR contents (e.g. read as is). If the size of the IDD
 * data is to big for the buffer, then an internal error is given back. note
 * that this option can serve up more than 1 introspection file, if multiple
 * devices are implemented. This feature is enabled when the compile switch
 * OC_IDD_API is used.
 *
 * The second option is to use an include file that contains the IDD
 * information. This is the default mechanism.
 *
 * The include file is called "server_introspection.dat.h" and should contain
 * introspection_data_size : size of the array introspection_data
 * uint8_t introspection_data[] : hex data representing the IDD.
 * one should place this file in a folder that gets included in the build
 * for example the include directory.
 */
void oc_set_introspection_data(size_t device, uint8_t *IDD, size_t IDD_size);

#ifdef __cplusplus
}
#endif

#endif /* OC_INTROSPECTION_H */

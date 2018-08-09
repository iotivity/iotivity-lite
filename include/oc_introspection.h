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

#ifndef OC_INTROSPECTION_H
#define OC_INTROSPECTION_H

#ifdef __cplusplus
extern "C"
{
#endif

/**
 * @brief functions for introspection .
 * The introspection mechanism is implemented by 2 different mechanisms
 * 
 * The first mechanism is reading the IDD file from a location.
 * The file is read with standard c library (fopen, fread, ..) 
 * The IDD information is served up as encoded CBOR contents (e.g. read as is).
 * The file is read and passed to the requesting client on each call.
 * if the file size is to big for the buffer, then an internal error is given back.
 * note that this option can serve up more than 1 introspection file, if multiple devices are implemented.
 * This feature is enabled when the compile switch OC_IDD_FILE is used.
 *
 * The second option is to use an include file that contains the IDD information.
 * This is the default mechanism.
 * The include file is called "server_introspection.dat.h" and should contain
 * introspection_data_size : size of the array introspection_data
 * uint8_t introspection_data[] : hex data representing the IDD.
 * one should place this file in a folder that gets included in the build
 * for example the include directory.
*/


/**
  @brief sets the filename of the introspection resource.
  if not set the file is "server_introspection.dat" is read from the location where the executable resides

  @param device index of the device to which the resource is to be created
  @param filename filename of the IDD file in cbor.
*/
void oc_set_introspection_file(int device, const char* filename);


/**
  @brief Creation of the oic.wk.introspection resource.

  @param device index of the device to which the resource is to be created
*/
void oc_create_introspection_resource(int device);

#ifdef __cplusplus
}
#endif

#endif /* OC_INTROSPECTION_H */

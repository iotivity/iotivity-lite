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

/**
 * @brief functions for introspection .
 * @file
 *
 * the IDD information is served up as encoded CBOR contents (e.g. read as is).
 * the file is read and passed to the requesting client on each call.
 * if the file size is to big for the buffer, then an internal error is given back.
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


#endif /* OC_INTROSPECTION_H */

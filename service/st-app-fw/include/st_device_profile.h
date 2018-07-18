/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

/**
  @brief ST device_profile manager APIs for managing st-app-fw module.
  @file
*/
#ifndef ST_DEVICE_PROFILE_H
#define ST_DEVICE_PROFILE_H

#include <stdbool.h>

/**
  @brief A function set device profile.
  @param device_def Unsigned char array showing CBOR info.
  @param device_def_len Total length of device def
  @return bool Description of result.
  @retval true if successful.
  @retval false if params are invalid.
*/
bool st_set_device_profile(unsigned char *device_def,
                           unsigned int device_def_len);

/**
  @brief A function unset device profile.
*/
void st_unset_device_profile(void);

#endif /* ST_DEVICE_PROFILE_H */
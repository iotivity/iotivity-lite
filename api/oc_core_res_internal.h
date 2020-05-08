/*
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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
 */
#ifndef OC_CORE_RES_INTERNAL_H
#define OC_CORE_RES_INTERNAL_H

#include "oc_core_res.h"
#include <stdint.h>

/**
 * Add new device resource to the stack. This initilizes all the stack related
 * resources that a specified by the OCF specification.
 *
 * If the stack is built with OC_SECURITY this will read the existing security
 * settings for the device. If no settings are found they will be initilized.
 *
 * Unlike oc_core_add_new_device() the network connection is not initilized by
 * calling this function.  This is purposly done since the primary use of this
 * function is to add virtual devices.  Virtual devices should not initilize a
 * the network connection unless the bridge device they belong to is onboarded.
 *
 * @see oc_core_add_new_device
 * @see oc_connectivity_init
 * @see oc_connectivity_shutdown
 */
oc_device_info_t *oc_core_add_new_device_at_index(
  const char *uri, const char *rt, const char *name, const char *spec_version,
  const char *data_model_version, size_t index,
  oc_core_add_device_cb_t add_device_cb, void *data);

/**
 * Only virtual devices are expected to be removed.
 *
 * If the memory is part of an array it is set to all zeros and the memory will
 * still not be freed but will be avalible to be reused.
 */
void oc_core_remove_device_at_index(size_t index);
#endif /* OC_CORE_RES_INTERNAL_H */

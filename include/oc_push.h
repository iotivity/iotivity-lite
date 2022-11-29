/****************************************************************************
 *
 * Copyright 2021 ETRI All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
 * Created on: Aug 23, 2021,
 * 				Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

/**
 * @file
 */

#ifndef OC_PUSH_H
#define OC_PUSH_H

#include <stdio.h>

#include "oc_config.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_endpoint.h"
#include "port/oc_log.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PUSHCONFIG_RESOURCE_PATH "/pushconfig"
#define PUSHCONFIG_RESOURCE_TYPE "oic.r.pushconfiguration"
#define PUSHCONFIG_RESOURCE_NAME "Push Configuration"

#define PUSHRECEIVERS_RESOURCE_PATH "/pushreceivers"
#define PUSHRECEIVERS_RESOURCE_TYPE "oic.r.pushreceiver"
#define PUSHRECEIVERS_RESOURCE_NAME "Push Receiver Configuration"

/**
 * @brief object used to store Resource pushed to
 * "oic.r.pushreceiver:receivers[i].receiveruri"
 */
typedef struct oc_pushd_resource_rep
{
  struct oc_pushd_resource_rep *next;
  oc_resource_t
    *resource;   ///< used to point any pushed Resource managed by iotivity-lite
  oc_rep_t *rep; ///< payload of pushed Resource
} oc_pushd_resource_rep_t;

/**
 * @brief callback function called whenever new push arrives
 */
typedef void (*oc_on_push_arrived_t)(oc_pushd_resource_rep_t *);

/**
 * @brief print payload of Resource in user friendly format
 *
 * @param[in] payload pointer to the payload to be printed
 */
OC_API
void oc_print_pushd_resource(const oc_rep_t *payload);

/**
 * @brief set callback function called whenever new push arrives
 *
 * @param[in] func function name
 */
OC_API
void oc_set_on_push_arrived(oc_on_push_arrived_t func);

/**
 * @brief application should call this function whenever the contents of
 * pushable Resource is updated, or Push Notification will not work.
 *
 * @param[in] uri          path of pushable Resource whose contents is just
 * updated
 * @param[in] uri_len      length of uri
 * @param[in] device_index index of Device that updated pushable Resource
 * belongs to
 */
OC_API
void oc_resource_state_changed(const char *uri, size_t uri_len,
                               size_t device_index);

#ifdef __cplusplus
}
#endif

#endif /*OC_PUSH_H*/

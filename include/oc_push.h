/****************************************************************************
 *
 * Copyright 2021 ETRI All Rights Reserved.
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
 * Created on: Aug 23, 2021,
 * 				Author: Joo-Chul Kevin Lee (rune@etri.re.kr)
 *
 *
 ****************************************************************************/

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


#if defined(OC_PUSHDEBUG) || defined(OC_DEBUG)
#define OC_PUSH_DBG(...) OC_LOG("D", __VA_ARGS__)
#define OC_PUSH_WRN(...) OC_LOG("W", __VA_ARGS__)
#define OC_PUSH_ERR(...) OC_LOG("E", __VA_ARGS__)
#else
#define OC_PUSH_DBG(...)
#define OC_PUSH_WRN(...)
#define OC_PUSH_ERR(...)
#endif


#ifdef __cplusplus
extern "C"
{
#endif


#define PUSHCONF_RSC_PATH "/pushconfig"
#define PUSHCONF_RSC_TYPE "oic.r.pushconfiguration"
#define PUSHCONF_RSC_NAME "Push Configuration"

#define PUSHRECVS_RSC_PATH "/pushreceivers"
#define PUSHRECVS_RSC_TYPE "oic.r.pushreceiver"
#define PUSHRECVS_RSC_NAME "Push Receiver Configuration"



/**
 * @brief object used to store Resource pushed to "oic.r.pshreceiver:receivers[i].receiveruri"
 */
typedef struct oc_pushd_rsc_rep
{
	struct oc_pushd_rsc_rep *next;
	oc_resource_t *resource;        ///< used to point any pushed Resource managed by iotivity-lite
	oc_rep_t *rep;                  ///< payload of pushed Resource
} oc_pushd_rsc_rep_t;


/**
 * @brief string representing response code
 */
extern const char *cli_status_strs[];

/**
 * @brief if this callback function is provided by user, it will called whenever new push notification arrives...
 */
extern void (*oc_push_arrived)(oc_pushd_rsc_rep_t *);

/**
 * @brief return response code string for `i`
 */
#define cli_statusstr(i) (cli_status_strs[(i)])


/**
 * @brief print payload of Resource in user friendly format
 */
void oc_print_pushd_rsc(oc_rep_t *payload);

/**
 * @brief application should call this function whenever the contents of pushable Resource is updated,
 *        or Push Notification will not work.
 *
 * @param[in] uri          path of pushable Resource whose contents is just updated
 * @param[in] device_index index of Device that updated pushable Resource belongs to
 */
void oc_resource_state_changed(const char *uri, size_t device_index);


#ifdef __cplusplus
}
#endif

#endif /*OC_PUSH_H*/

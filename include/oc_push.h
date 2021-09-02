/*
// Copyright (c) 2021 ETRI
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
//
//  Created on: Aug 23, 2021
//      Author: jclee
*/

#ifndef OC_PUSH_H
#define OC_PUSH_H

#include "oc_config.h"
#include "oc_helpers.h"
#include "oc_memb.h"
#include "util/oc_process.h"


#ifdef __cplusplus
extern "C"
{
#endif


typedef enum {
	OC_PP_WFP,
	OC_PP_WFU,
	OC_PP_WFR,
	OC_PP_TOUT,
	OC_PP_ERR
} oc_pp_state_t;

/*
 * Resource creation and request handlers for ["oic.r.notificationselector", "oic.r.pushproxy"] Resource
 */
typedef struct oc_ns
{
	struct oc_ns *next;
	oc_resource_t *resource;
	oc_string_t phref;
	oc_string_array_t prt;
	oc_string_array_t pif;
	oc_string_t pushtarget;
	oc_string_t pushqif;
	oc_string_array_t sourcert;
	oc_string_array_t endpoints;
	oc_pp_state_t state;
} oc_ns_t;


/*
 * structure for member of "oic.r.pushreceiver:receivers" array
 */
typedef struct oc_recv
{
//	oc_recv_t *next;
	oc_string_t uri;
	oc_string_array_t rts;
} oc_recv_t;


/*
 * Object creation and request handler for Push Receiver Resource
 */
typedef struct oc_recvs
{
	struct oc_ns *next;
	oc_resource_t *resource;
	struct oc_mmem *receivers;
//	OC_LIST_STRUCT(receivers);
} oc_recvs_t;


OC_PROCESS_NAME(oc_push_process);


#ifdef __cplusplus
}
#endif

#endif /*OC_PUSH_H*/

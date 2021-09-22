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

#include <stdio.h>

#include "oc_config.h"
#include "oc_helpers.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_endpoint.h"
#include "port/oc_log.h"
#include "util/oc_memb.h"
#include "util/oc_process.h"

/*
 * TODO4ME remove later...
 */
//#define OC_PUSHDEBUG

#if defined(OC_PUSHDEBUG) || defined(OC_DEBUG)
#ifndef OC_DEBUG
#define oc_print(...) printf(__VA_ARGS__)
#define oc_log(level, ...)                                                     \
		do {                                                                         \
			oc_print("%s: %s <%s:%d>: ", level, __FILE__, __func__, __LINE__);            \
			oc_print(__VA_ARGS__);                                                        \
			oc_print("\n");                                                               \
		} while (0)
#define p_dbg(...) oc_log("DEBUG", __VA_ARGS__)
#define p_wrn(...) oc_log("WARNING", __VA_ARGS__)
#define p_err(...) oc_log("ERROR", __VA_ARGS__)
#else
#define p_dbg(...) OC_LOG("DEBUG", __VA_ARGS__)
#define p_wrn(...) OC_LOG("WARNING", __VA_ARGS__)
#define p_err(...) OC_LOG("ERROR", __VA_ARGS__)
#endif
#else
#define p_dbg(...)
#define p_wrn(...)
#define p_err(...)
#endif


#ifdef __cplusplus
extern "C"
{
#endif


#define PUSHCONF_PATH "/pushconfig"
#define PUSHRECVS_PATH "/pushreceivers"


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
	/* notificaiton selector */
	oc_string_t phref;		/* optional */
	oc_string_array_t prt;	/* optional */
	oc_string_array_t pif;	/* optional */
	/* push proxy */
//	oc_string_t pushtarget;
	oc_endpoint_t *pushtarget_ep;	/* full URI (e.g. coaps://[fe80::b1d6]:1122/myLightSwitch), oc_endpoint_t type */
	oc_string_t targetpath; /* path in target server (e.g. /myLightSwitch) */
	oc_string_t pushqif;
	oc_string_array_t sourcert;
//	oc_list_t endpoints;
	oc_pp_state_t state;
} oc_ns_t;


/*
 * structure for member of "oic.r.pushreceiver:receivers" object array
 */
typedef struct oc_recv
{
	struct oc_recv *next;
	oc_string_t receiveruri;
	oc_string_array_t rts;
	oc_endpoint_t ep;
} oc_recv_t;


/*
 * Object creation and request handler for Push Receiver Resource
 */
typedef struct oc_recvs
{
	struct oc_recvs *next;
	oc_resource_t *resource;
	oc_list_t receivers;
//	oc_array_t *receivers;
//	OC_LIST_STRUCT(receivers);
} oc_recvs_t;



/*
 * object used to store Resource pushed to "oic.r.pshreceiver:receivers[i].receiveruri"
 */
typedef struct oc_pushd_rsc_rep
{
	struct oc_pushd_rsc_rep *next;
	oc_resource_t *resource;
	oc_rep_t *rep;
} oc_pushd_rsc_rep_t;


OC_PROCESS_NAME(oc_push_process);

void oc_push_list_init();
void oc_create_pushconf_resource(size_t device_index);
void oc_create_pushreceiver_resource(size_t device_index);
oc_recv_t * _find_recv_obj_by_uri(oc_recvs_t *recvs_instance, const char *uri, int uri_len);

#define _find_recv_obj_by_uri2(recvs_instance, uri_string) \
	(_find_recv_obj_by_uri((recvs_instance), oc_string(uri_string), oc_string_len(uri_string)))




#ifdef __cplusplus
}
#endif

#endif /*OC_PUSH_H*/

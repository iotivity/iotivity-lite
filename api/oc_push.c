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
//   Created on: Aug 23, 2021
//       Author: jclee
*/

#include "oc_push.h"

#if defined(OC_PUSH) && defined(OC_SERVER) && defined(OC_CLIENT)

#include "oc_api.h"
#include "oc_events.h"
#include "oc_rep.h"
#include "oc_endpoint.h"
#include "util/oc_process.h"
#include "util/oc_list.h"

/**
 *
 * @brief	variable for storing new collection member of push config Resource
 *
 */
OC_MEMB(ns_memb, oc_ns_t, 1);

/**
 * @brief	`ns_col_list` keeps real data of all Notification Selector Resources
 * 			(it includes all Resources of all Devices)
 *
 * 			each list member is instance of `oc_ns_t`
 */
OC_LIST(ns_list);


/**
 * @brief	`recvs_list` keeps real data of all Receiver object in Push Receiver Resource
 * 			(it includes all Receiver objects of Resource of all Devices)
 *
 * 			each list member is instance of `oc_recv_t`
 */
OC_LIST(recvs_list);


OC_PROCESS(oc_push_process, "Push Notification handler");

/**
 *
 * @brief get callback for push configuraiton
 *
 */
void get_pushconf(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{

}


/**
 *
 * @brief post callback for push configuraiton
 *
 */
void post_pushconf(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
}


/**
 *
 * @brief callback to be used to set existing `notification selector` with received Resource representation
 *
 * @param resource
 * @param rep			Resource representation structure
 * @param data			internal structure for storing `notification selector` resource
 * 						(oc_memb struct for ["oic.r.notificationselector", "oic.r.pushproxy"] Resource)
 * @return
 */
bool set_ns_properties(oc_resource_t *resource, oc_rep_t *rep, void *data)
{
	(void)resource;
	oc_ns_t *ns_instance = (oc_ns_t *)data;
	while (rep != NULL) {
		switch (rep->type) {
		case OC_REP_STRING:
			if (oc_string_len(rep->name) == 5 && memcmp(oc_string(rep->name), "phref", 5) == 0)
			{
				oc_new_string(&ns_instance->phref, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			else if (oc_string_len(rep->name) == 10 && memcmp(oc_string(rep->name), "pushtarget", 10) == 0)
			{
				oc_new_string(&ns_instance->pushtarget, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			else if (oc_string_len(rep->name) == 7 && memcmp(oc_string(rep->name), "pushqif", 7) == 0)
			{
				oc_new_string(&ns_instance->pushqif, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			break;
		case OC_REP_STRING_ARRAY:
			if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "prt", 3) == 0)
			{
				oc_new_string_array(&ns_instance->prt, rep->value.array.size);
				oc_array_t *array_item = &rep->value.array;
				for (int i=0; i < rep->value.array.size; i++)
				{
					oc_string_array_add_item(ns_instance->prt, array_item->ptr);
					array_item = array_item->next;
				}
			}
			else if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "pif", 3) == 0)
			{
				oc_new_string_array(&ns_instance->pif, rep->value.array.size);
				oc_array_t *array_item = &rep->value.array;
				for (int i=0; i < rep->value.array.size; i++)
				{
					oc_string_array_add_item(ns_instance->pif, array_item->ptr);
					array_item = array_item->next;
				}
			}
			else if (oc_string_len(rep->name) == 8 && memcmp(oc_string(rep->name), "sourcert", 8) == 0)
			{
				oc_new_string_array(&ns_instance->sourcert, rep->value.array.size);
				oc_array_t *array_item = &rep->value.array;
				for (int i=0; i < rep->value.array.size; i++) {
					oc_string_array_add_item(ns_instance->sourcert, array_item->ptr);
					array_item = array_item->next;
				}
				/*
				 * FIXME4ME 만약 config client가 sourcert를 oic.r.pushpayload 이외의 것으로 설정하려 하면 bad request 에러를 리턴해야 함 (shall)
				 */
			}
			break;
		case OC_REP_INT:
			if (oc_string_len(rep->name) == 5 && memcmp(oc_string(rep->name), "state", 5) == 0)
			{
				ns_instance->state = rep->value.integer;
			}
			break;
		default:
			break;
		}
		rep = rep->next;
	}
	return true;
}



/**
 *
 * @brief callback to be used to prepare `notification selector` from existing Resource representation
 *
 * @param resource
 * @param iface_mask		interface to be used to send response
 * @param data				internal structure for storing `notification selector` resource
 * 							(oc_memb struct for ["oic.r.notificationselector", "oic.r.pushproxy"] Resource)
 */
void get_ns_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask, void *data)
{
	oc_ns_t *ns_instance = (oc_ns_t *)data;

	oc_rep_start_root_object();
	switch (iface_mask) {
	case OC_IF_BASELINE:
		oc_process_baseline_interface(resource);
		/* fall through */
	case OC_IF_RW:
		/* phref (optional) */
		if (oc_string_len(ns_instance->phref))
		{
			oc_rep_set_text_string(root, phref, oc_string(ns_instance->phref));
		}

		/* prt (optional) */
		if (oc_string_array_get_allocated_size(ns_instance->prt))
		{
			oc_rep_set_array(root, prt);
			for (char i=0; i < oc_string_array_get_allocated_size(ns_instance->prt); i++)
			{
				oc_rep_add_text_string(prt, oc_string_array_get_item(ns_instance->prt, i));
			}
			oc_rep_close_array(root, prt);
		}

		/* pif (optional) */
		if (oc_string_array_get_allocated_size(ns_instance->pif))
		{
			oc_rep_set_array(root, pif);
			for (char i=0; i < oc_string_array_get_allocated_size(ns_instance->pif); i++)
			{
				oc_rep_add_text_string(pif, oc_string_array_get_item(ns_instance->pif, i));
			}
			oc_rep_close_array(root, pif);
		}

		/* pushtarget */
		oc_rep_set_text_string(root, pushtarget, oc_string(ns_instance->pushtarget));

		/* pushqif */
		oc_rep_set_text_string(root, pushqif, oc_string(ns_instance->pushqif));

		/* sourcert */
		if (oc_string_array_get_allocated_size(ns_instance->sourcert))
		{
			oc_rep_set_array(root, sourcert);
			for (char i=0; i < oc_string_array_get_allocated_size(ns_instance->sourcert); i++)
			{
				oc_rep_add_text_string(sourcert, oc_string_array_get_item(ns_instance->sourcert, i));
			}
			oc_rep_close_array(root, sourcert);
		}

		/* state */
		oc_rep_set_int(root, state, ns_instance->state);

		break;
	default:
		break;
	}
	oc_rep_end_root_object();
}



void get_ns(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	get_ns_properties(request->resource, iface_mask, user_data);
	oc_send_response(request, OC_STATUS_OK);
}


/**
 *
 * @brief callback for getting & creating new `notification selector`
 *
 */
oc_resource_t *get_ns_instance(const char *href, oc_string_array_t *types,
								oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
								size_t device)
{
	oc_ns_t *ns_instance = (oc_ns_t *)oc_memb_alloc(&ns_memb);

	if (ns_instance) {
		ns_instance->resource = oc_new_resource(NULL, href, oc_string_array_get_allocated_size(*types), device);
		if (ns_instance->resource) {
			size_t i;
			for (i = 0; i < oc_string_array_get_allocated_size(*types); i++) {
				const char *rt = oc_string_array_get_item(*types, i);
				oc_resource_bind_resource_type(ns_instance->resource, rt);
			}
			oc_resource_bind_resource_interface(ns_instance->resource, iface_mask);
			ns_instance->resource->properties = bm;
			oc_resource_set_default_interface(ns_instance->resource, OC_IF_RW);
			oc_resource_set_request_handler(ns_instance->resource, OC_GET, get_ns, ns_instance);
			oc_resource_set_properties_cbs(ns_instance->resource, get_ns_properties, ns_instance, set_ns_properties, ns_instance);
			oc_add_resource(ns_instance->resource);

			oc_list_add(ns_list, ns_instance);
			return ns_instance->resource;
		} else {
			oc_memb_free(&ns_memb, ns_instance);
		}
	}

	return NULL;
}


/**
 *
 * @brief callback for freeing existing notification selector
 *
 */
void free_ns_instance(oc_resource_t *resource)
{
	oc_ns_t *ns_instance = (oc_ns_t *)oc_list_head(ns_list);

	while (ns_instance)
	{
		if (ns_instance->resource == resource)
		{
			oc_delete_resource(resource);
			oc_list_remove(ns_list, ns_instance);
			oc_memb_free(&ns_memb, ns_instance);
			return;
		}
		ns_instance = ns_instance->next;
	}
}



/**
 *
 * @brief initialize Push Configuration Resource
 *
 * @details
 * for Origin Server: \n
 * - Push Configuration ("oic.r.pushconfiguration") \n
 * - Notification Selector + Push Proxy ("oic.r.notificationselector" + "oic.r.pushproxy") \n
 *
 * for Target Server \n
 * - Push Receiver ("oic.r.pushreceiver") \n
 *
 * @param device_index	device index
 */
void init_pushconf_resource(size_t device_index)
{
	/* create Push Configuration Resource */
	oc_resource_t *push_conf = oc_new_collection("Push Configuration", "/pushconfig", 2, device_index);
	oc_resource_bind_resource_type(push_conf, "oic.r.pushconfiguration");
	oc_resource_bind_resource_interface(push_conf, OC_IF_LL | OC_IF_RW | OC_IF_CREATE | OC_IF_BASELINE);
	oc_resource_set_default_interface(push_conf, OC_IF_LL);
	oc_resource_set_discoverable(push_conf, true);

//	oc_resource_set_request_handler(push_conf, OC_GET, get_pushconf, NULL);
//	oc_resource_set_request_handler(push_conf, OC_POST, post_pushconf, NULL);

	/* set "rts" Property */
	oc_collection_add_supported_rt(push_conf, "oic.r.notificationselector");
	oc_collection_add_supported_rt(push_conf, "oic.r.pushproxy");

	oc_collections_add_rt_factory("oic.r.notificationselector", get_ns_instance, free_ns_instance);
//	oc_collections_add_rt_factory("oic.r.pushproxy", get_pp_instance, free_pp_instance);

	oc_add_collection(push_conf);
}


/**
 *
 * @brief	GET callback for Push Receiver Resource
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
void get_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	oc_rep_start_root_object();
	switch (iface_mask)
	{
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
	case OC_IF_RW:
		/*
		 * `receivers` object array
		 */
		oc_rep_open_array(root, receivers);
		oc_recv_t *recv_instance = (oc_recv_t *)oc_list_head(recvs_list);
		while (recv_instance)
		{
			if (recv_instance->resource == request->resource)
			{
				/* == open new receiver object == */
				oc_rep_object_array_begin_item(receivers);
				/* receiver:uri */
				oc_rep_set_text_string(receivers, uri, oc_string(recv_instance->uri));

				/* receiver:rts[] */
				oc_rep_open_array(receivers, rts);
				for (char i=0; i < oc_string_array_get_allocated_size(recv_instance->rts); i++)
				{
					oc_rep_add_text_string(rts, oc_string_array_get_item(recv_instance->rts, i));
				}
				oc_rep_close_array(receivers, rts);

				/* == close object == */
				oc_rep_object_array_end_item(receivers);
			}
			recv_instance = recv_instance->next;
		}
		oc_rep_close_array(root, receivers);
		break;
	default:
		break;
	}
	oc_rep_end_root_object();
	oc_send_response(request, OC_STATUS_OK);

	return;
}



/**
 *
 * @brief	POST callback for Push Receiver Resource
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
void post_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{

}



/**
 *
 * @brief initiate Push Receiver Resource
 *
 * @param device_index
 */
void init_pushreceiver_resource(size_t device_index)
{
	/* create Push Receiver Resource */
	oc_resource_t *push_recv = oc_new_resource("Push Configuration", "/pushreceivers", 1, device_index);

	oc_resource_bind_resource_type(push_recv, "oic.r.pushreceiver");
	oc_resource_bind_resource_interface(push_recv, OC_IF_RW | OC_IF_BASELINE);
	oc_resource_set_default_interface(push_recv, OC_IF_RW);
	oc_resource_set_discoverable(push_recv, true);

	oc_resource_set_request_handler(push_recv, OC_GET, get_pushrecv, NULL);
	oc_resource_set_request_handler(push_recv, OC_POST, post_pushrecv, NULL);

	oc_add_resource(push_recv);
}



OC_PROCESS_THREAD(oc_push_process, ev, data)
{
	oc_resource_t *src_rsc;

	OC_PROCESS_BEGIN();

	do {
		int device_count = oc_core_get_num_devices();

		/* create Push Notification Resource per each Device */
		for (int i=0; i<device_count; i++) {
			init_push_resources(i);
		}

		OC_PROCESS_YIELD();

		/* send UPDATE to target server */
		if (ev == oc_events[PUSH_RSC_STATE_CHANGED]) {
			src_rsc = (oc_resource_t *)data;
			/*
			 * client에서 POST 하는 루틴 참조할 것 (client_multithread_linux.c 참고)
			 */
			/* TODO4ME from here.. 2021/8/30  */
			/*
			 * 1. find `notification selector` which monitors `src_rsc` from `ns_col_list`
			 * 2. post UPDATE by using URI, endpoint (use oc_sting_to_endpoint())
			 */

//			if (!is_resource_found())
//				return;
//
//			if (oc_init_post(a_light, &target_ep, NULL, &post_response, LOW_QOS, NULL)) {
//				oc_rep_start_root_object();
//				oc_rep_set_boolean(root, state, false);
//				oc_rep_set_int(root, power, 105);
//				oc_rep_end_root_object();
//				if (oc_do_post())
//					printf("Sent POST request\n");
//				else
//					printf("Could not send POST request\n");
//			} else
//				printf("Could not init POST request\n");

		}

	} while(0);

	OC_PROCESS_END();
}



/**
 *
 * @brief re-schedule push process
 *
 */
void oc_resource_state_changed(const char *uri, size_t device_index)
{
	if (!oc_process_is_running(&oc_push_process)) {
		OC_DBG("oc_push_process is not running!\n");
		return;
	}

	/* Resource which is just updated */
	oc_process_post(&oc_push_process, oc_events[PUSH_RSC_STATE_CHANGED],
					oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index));
//	oc_process_poll(&oc_push_process);

	_oc_signal_event_loop();

	return;
}






#endif /* OC_PUSH && OC_SERVER && OC_CLIENT */

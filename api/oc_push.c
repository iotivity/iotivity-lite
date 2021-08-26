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
#include "util/oc_process.h"
#include "util/oc_list.h"

/**
 *
 * @brief variable for storing new collection member of push config Resource
 *
 */
OC_MEMB(ns_memb, oc_ns_t, 1);
OC_LIST(ns_list);

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
 * @brief
 *
 * @param resource
 * @param rep
 * @param data
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
			else if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "prt", 3) == 0)
			{
				oc_new_string_array(ns_instance->prt, rep->value.array.size);
				oc_array_t *array_item = &rep->value.array;
				for (int i=0; i<rep->value.array.size; i++) {
					oc_string_array_add_item(ns_instance->prt, array_item->ptr);
					array_item = array_item->next;
				}
			}
			/* TODO4ME from here.. 2021/8/27  */
			

			break;

//		case OC_REP_DOUBLE:
//			if (oc_string_len(rep->name) == 5 && memcmp(oc_string(rep->name), "power", 5) == 0) {
//				ec->power = rep->value.double_p;
//			} else if (oc_string_len(rep->name) == 6 && memcmp(oc_string(rep->name), "energy", 6) == 0) {
//				ec->energy = rep->value.double_p;
//			}
//			break;
		default:
			break;
		}
		rep = rep->next;
	}
	return true;
}



/**
 *
 * @brief prepare Resource presentation of ["oic.r.notificationselector", "oic.r.pushproxy"]
 *
 * @param resource
 * @param iface_mask
 * @param data oc_memb struct for ["oic.r.notificationselector", "oic.r.pushproxy"] Resource
 */
void get_ns_properties(oc_resource_t *resource, oc_interface_mask_t iface_mask, void *data)
{
	oc_ns_t *ns = (oc_ns_t *)data;
	oc_rep_start_root_object();
	switch (iface_mask) {
	case OC_IF_BASELINE:
		oc_process_baseline_interface(resource);
		/* fall through */
	case OC_IF_S:
		oc_rep_set_double(root, power, ns->power);
		oc_rep_set_double(root, energy, ns->energy);
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
 * @brief callback for creating new notification selector
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
oc_resource_t *free_ns_instance(oc_resource_t *resource)
{

}



/**
 * @brief initialize Resources for Push Notification
 *
 * @details
 * for Origin Server: \n
 * - Push Configuration ("oic.r.pushconfiguration") \n
 * - Notification Selector + Push Proxy ("oic.r.notificationselector" + "oic.r.pushproxy") \n
 *
 * for Target Server \n
 * - Push Receiver ("oic.r.pushreceiver") \n
 */
void init_push_resources(size_t device_index)
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

	oc_add_collection(push_conf);
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
			/* TODO4ME from here.. 2021/8/25  */

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

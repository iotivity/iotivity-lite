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
#include "oc_ri.h"
#include "oc_core_res.h"
#include "util/oc_process.h"
#include "util/oc_list.h"
#include "util/oc_mmem.h"

/**
 * @brief	memory block for storing new collection member of Push Configuration Resource
 */
OC_MEMB(ns_instance_memb, oc_ns_t, 1);

/**
 * @brief	`ns_col_list` keeps real data of all Notification Selector Resources
 * 			(it includes all Resources of all Devices)
 *
 * 			each list member is instance of `oc_ns_t`
 */
OC_LIST(ns_list);



/**
 * @brief	memory block definition for storing new Receiver object array of Push Receiver Resource
 */
OC_MEMB(recvs_instance_memb, oc_recvs_t, 1);

/**
 * @brief	memory block definition for storing new Receiver object of Receiver object array
 */
OC_MEMB(recv_instance_memb, oc_recv_t, 1);



/**
 * @brief	`recvs_list` keeps real data of all Receiver object in Push Receiver Resource
 * 			(it includes all Receiver objects of Resource of all Devices)
 *
 * 			each list member is instance of `oc_recv_t`
 */
OC_LIST(recvs_list);



/**
 * @brief	memory block definition for storing properties representation of pushed resource
 */
OC_MEMB(rep_instance_memb, oc_rep_t, 1);

/**
 * @brief	memory block definition for storing pushed resource representation list
 */
OC_MEMB(pushd_rsc_rep_instance_memb, oc_pushd_rsc_rep_t, 1);



/**
 * @brief	`pushed_rsc_list` keeps Resource representation of Pushed Resources
 */
OC_LIST(pushd_rsc_rep_list);



/**
 * @brief	process which handles push notification
 */
OC_PROCESS(oc_push_process, "Push Notification handler");



/**
 * @brief				callback to be used to set existing `notification selector` with received Resource representation
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
	/*
	 * `data` is set when new Notification Selector Resource is created
	 * by calling `oc_resource_set_properties_cbs()` in `get_ns_instance()`
	 */
	oc_ns_t *ns_instance = (oc_ns_t *)data;
	while (rep != NULL) {
		switch (rep->type) {
		case OC_REP_STRING:
			/* oic.r.notificationselector:phref */
			if (oc_string_len(rep->name) == 5 && memcmp(oc_string(rep->name), "phref", 5) == 0)
			{
				oc_new_string(&ns_instance->phref, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			/* oic.r.pushproxy:pushtarget */
			else if (oc_string_len(rep->name) == 10 && memcmp(oc_string(rep->name), "pushtarget", 10) == 0)
			{
				oc_new_string(&ns_instance->pushtarget, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			/* oic.r.pushproxy:pushqif */
			else if (oc_string_len(rep->name) == 7 && memcmp(oc_string(rep->name), "pushqif", 7) == 0)
			{
				oc_new_string(&ns_instance->pushqif, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			break;
		case OC_REP_STRING_ARRAY:
			/* oic.r.notificationselector:prt */
			if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "prt", 3) == 0)
			{
				oc_new_string_array(&ns_instance->prt, oc_string_array_get_allocated_size(rep->value.array));

				for (int i=0; i<oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					oc_string_array_add_item(ns_instance->prt, oc_string_array_get_item(rep->value.array, i));
				}
			}
			/* oic.r.notificationselector:pif */
			else if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "pif", 3) == 0)
			{
				oc_new_string_array(&ns_instance->pif, oc_string_array_get_allocated_size(rep->value.array));

				for (int i=0; i<oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					oc_string_array_add_item(ns_instance->pif, oc_string_array_get_item(rep->value.array, i));
				}
			}
			/*  oic.r.pushproxy:sourcert  */
			else if (oc_string_len(rep->name) == 8 && memcmp(oc_string(rep->name), "sourcert", 8) == 0)
			{
				oc_new_string_array(&ns_instance->sourcert, oc_string_array_get_allocated_size(rep->value.array));

				for (int i=0; i<oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					oc_string_array_add_item(ns_instance->sourcert, oc_string_array_get_item(rep->value.array, i));
				}
				/*
				 * TODO4ME 만약 config client가 sourcert를 oic.r.pushpayload 이외의 것으로 설정하려 하면  bad request 에러를 리턴해야 함 (shall)
				 */
			}
			break;
		case OC_REP_INT:
			/* oic.r.pushproxy:state */
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
	/*
	 * `data` is set when new Notification Selector Resource is created
	 * by calling `oc_resource_set_properties_cbs()` in `get_ns_instance()`
	 */
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


/**
 * @brief				function used to RETRIEVE `Notification Selector + Push Proxy` Resource
 * 						which is autogenerated through `oic.if.crete` interface
 * @param request
 * @param iface_mask
 * @param user_data
 */
void get_ns(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	get_ns_properties(request->resource, iface_mask, user_data);
	oc_send_response(request, OC_STATUS_OK);
}



/**
 * @brief				function used to UPDATE `Notification Selector + Push Proxy` Resource
 * 						which is autogenerated through `oic.if.crete` interface
 * @param request
 * @param iface_mask
 * @param user_data
 */
void post_ns(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	set_ns_properties(request->resource, iface_mask, user_data);
	oc_send_response(request, OC_STATUS_CHANGED);
}


/**
 *
 * @brief callback for getting & creating new `Notification Selector + Push Proxy` Resource instance
 *
 */
oc_resource_t *get_ns_instance(const char *href, oc_string_array_t *types,
								oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
								size_t device)
{
	oc_ns_t *ns_instance = (oc_ns_t *)oc_memb_alloc(&ns_instance_memb);

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
			oc_resource_set_request_handler(ns_instance->resource, OC_POST, post_ns, ns_instance);
			oc_resource_set_properties_cbs(ns_instance->resource, get_ns_properties, ns_instance,
														set_ns_properties, ns_instance);
			oc_add_resource(ns_instance->resource);

			/*
			 * add this new Notification Selector Resource to the list
			 * which keeps all Notification Selectors of all Devices
			 */
			oc_list_add(ns_list, ns_instance);
			return ns_instance->resource;
		} else {
			oc_memb_free(&ns_instance_memb, ns_instance);
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
			oc_memb_free(&ns_instance_memb, ns_instance);
			return;
		}
		ns_instance = ns_instance->next;
	}
}



#if 0
/**
 * @brief				RETRIEVE handler for Push Configuration Resource
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
static void get_pushconf(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{

	oc_rep_begin_root_object();

	switch (iface_mask)
	{
	case OC_IF_LL:

	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
		break;
	case OC_IF_B:
		break;
	default:
		break;
	}

	oc_rep_end_root_object();

}


/**
 * @brief				UPDATE handler for Push Configuration Resource
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
static void post_pushconf(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{

}
#endif



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
	oc_resource_bind_resource_interface(push_conf, OC_IF_LL | /*OC_IF_B | */ OC_IF_CREATE | OC_IF_BASELINE);
	oc_resource_set_default_interface(push_conf, OC_IF_LL);
	oc_resource_set_discoverable(push_conf, true);

	/* RETRIEVE, UPDATE handler */
//	oc_resource_set_request_handler(push_conf, OC_GET, get_pushconf, NULL);
//	oc_resource_set_request_handler(push_conf, OC_POST, post_pushconf, NULL);

	/* set "rts" Property */
	oc_collection_add_supported_rt(push_conf, "oic.r.notificationselector");
	oc_collection_add_supported_rt(push_conf, "oic.r.pushproxy");

	oc_collections_add_rt_factory("oic.r.notificationselector", get_ns_instance, free_ns_instance);
//	oc_collections_add_rt_factory("oic.r.pushproxy", get_pp_instance, free_pp_instance);

	oc_add_collection(push_conf);
}





void get_pushd_rsc(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	int result = OC_STATUS_OK;
	oc_pushd_rsc_rep_t *pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(request->resource->uri, request->resource->device);

	if (!pushd_rsc_rep)
	{
		p_err("something wrong, can't find resource representation for pushed resource (%s)...\n",
				oc_string(request->resource->uri));
		return;
	}

	if (pushd_rsc_rep->rep)
	{
		oc_rep_begin_root_object();
		switch (iface_mask)
		{
		case OC_IF_BASELINE:
			oc_process_baseline_interface(request->resource);
		case OC_IF_R:
		case OC_IF_RW:
			break;
		default:
			break;
		}
		oc_rep_end_root_object();

		oc_send_response(request, result);
	}
	else
	{
		p_err("resource representation for pushed resource (%s) is found, but no resource representation for it is built\n",
				oc_string(request->resource->uri));
	}

	return;
}




void post_pushd_rsc(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	oc_rep_set_pool(&rep_instance_memb);

	/*
	 * TODO4ME _create_pushd_rsc_rep(new_rep, org_rep) 이용...
	 */

}




/**
 *
 * @brief				GET callback for Push Receiver Resource
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
void get_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	int result = OC_STATUS_OK;

	oc_rep_begin_root_object();
	switch (iface_mask)
	{
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
	case OC_IF_RW:
		/*
		 * `receivers` object array
		 */
		oc_rep_open_array(root, receivers);
		oc_recvs_t *recvs_instance = (oc_recvs_t *)oc_list_head(recvs_list);
		while (recvs_instance)
		{
			if (recvs_instance->resource == request->resource)
			{
#if 0
				oc_recv_t *recvs = (oc_recv_t *)OC_MMEM_PTR(recvs_instance->receivers);
				int arr_len = recvs_instance->receivers->size/sizeof(oc_recv_t);

				for (int i=0; i<arr_len; i++)
				{
					/* == open new receiver object == */
					oc_rep_object_array_begin_item(receivers);
					/* receiver:uri */
					oc_rep_set_text_string(receivers, uri, oc_string(recvs[i].uri));

					/* receiver:rts[] */
					oc_rep_open_array(receivers, rts);
					for (char j=0; j < oc_string_array_get_allocated_size(recvs[i].rts); j++)
					{
						oc_rep_add_text_string(rts, oc_string_array_get_item(recvs[i].rts, j));
					}
					oc_rep_close_array(receivers, rts);

					/* == close object == */
					oc_rep_object_array_end_item(receivers);
				}
#endif
//				oc_recv_t *recvs = (oc_recv_t *)OC_MMEM_PTR(recvs_instance->receivers);

//				int arr_len = recvs_instance->receivers->size/sizeof(oc_recv_t);

//				for (int i=0; i<arr_len; i++)
				oc_recv_t *recv_obj = (oc_recv_t *)oc_list_head(recvs_instance->receivers);
				while (recv_obj)
				{
					/* == open new receiver object == */
					oc_rep_object_array_begin_item(receivers);
					/* receiver:uri */
//					oc_rep_set_text_string(receivers, uri, oc_string(recvs[i].uri));
					oc_rep_set_text_string(receivers, uri, oc_string(recv_obj->receiveruri));

					/* receiver:rts[] */
					oc_rep_open_array(receivers, rts);
//					for (char j=0; j < oc_string_array_get_allocated_size(recvs[i].rts); j++)
					for (char j=0; j < oc_string_array_get_allocated_size(recv_obj->rts); j++)
					{
//						oc_rep_add_text_string(rts, oc_string_array_get_item(recvs[i].rts, j));
						oc_rep_add_text_string(rts, oc_string_array_get_item(recv_obj->rts, j));
					}
					oc_rep_close_array(receivers, rts);

					/* == close object == */
					oc_rep_object_array_end_item(receivers);
				}
				break;
			}
			else
			{
				recvs_instance = recvs_instance->next;
			}
		}
		oc_rep_close_array(root, receivers);
		break;
	default:
		break;
	}
	oc_rep_end_root_object();

	oc_send_response(request, result);

	return;
}




#if 0
/**
 * @brief		free memory allocated for "receivers[i].rts" array Property
 * @param rcvs	receiver object array
 */
void _free_recvs_obj_array(oc_array_t *rcvs)
{
//	int recv_len = sizeof(oc_recv_t);
//	int arr_len = rcvs->size/recv_len;
//	char *ptr = (char *)rcvs;
//
//	for (int i=0; i<arr_len; i++)
//	{
//		ptr = ptr + i*recv_len;
//		oc_free_string_array((&((oc_recv_t *)ptr)->rts));
//	}

	oc_recv_t *rcvs_array = (oc_recv_t *)(OC_MMEM_PTR(rcvs));
	int arr_len = rcvs->size/sizeof(oc_recv_t);

	for (int i=0; i<arr_len; i++)
	{
		oc_free_string_array(&rcvs_array[i].rts);
		oc_free_string(&rcvs_array[i].receiveruri);
	}

	return;
}
#endif



/**
 * @brief				get length of payload list (oc_rep_t list)
 *
 * @param obj_list	payload list
 * @return				number of payload list member
 */
int _get_obj_array_len(oc_rep_t *obj_list)
{
	int n = 0;
	oc_rep_t *obj = obj_list;

	while (obj)
	{
		n++;
		obj = obj->next;
	}

	return n;
}


/**
 * @brief						try to find `receiver` object which has `uri` as its `uri` Property
 *
 * @param recvs_instance
 * @param uri
 * @param uri_len
 * @return
 * 		NULL: not found,
 * 		not NULL: found
 */
//oc_recv_t * _find_recv_obj_by_uri(oc_list_t recv_obj_list, const char *uri, int uri_len)
oc_recv_t * _find_recv_obj_by_uri(oc_recvs_t *recvs_instance, const char *uri, int uri_len)
{
//	oc_recv_t *recv = (oc_recv_t *)oc_list_head(recv_obj_list);
	oc_recv_t *recv = (oc_recv_t *)oc_list_head(recvs_instance->receivers);

	while (recv)
	{
		if (!strncmp(oc_string(recv->receiveruri), uri, uri_len))
		{
			break;
		}
		else
		{
			recv = recv->next;
		}
	}

	return recv;
}




/**
 * @brief
 *
 * @param uri
 * @param device_index
 * @return
 */
oc_pushd_rsc_rep_t * _find_pushd_rsc_rep_by_uri(oc_string_t uri, size_t device_index)
{
	oc_pushd_rsc_rep_t *pushd_rsc_rep = (oc_pushd_rsc_rep_t *)oc_list_head(pushd_rsc_rep_list);

	while (pushd_rsc_rep)
	{
		if (!strcmp(oc_string(pushd_rsc_rep->resource->uri), oc_string(uri))
				&& (pushd_rsc_rep->resource->device == device_index))
		{
			break;
		}
		else
		{
			pushd_rsc_rep = pushd_rsc_rep->next;
		}
	}

	return pushd_rsc_rep;
}




/**
 * @brief					purge app resource and resource representation container
 * 							accessed through `uri` in device whose index is `device_index`
 *
 * @param uri				URI to app resource to be purged
 * @param device_index	index of device where the target resource resides
 */
void _purge_pushd_rsc(oc_string_t uri, size_t device_index)
{
	oc_resource_t *pushd_rsc = oc_ri_get_app_resource_by_uri(oc_string(uri), oc_string_len(uri), device_index);
	oc_pushd_rsc_rep_t *pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(uri, device_index);

	if (pushd_rsc_rep)
	{
		/* step 1. purge `rep` */
		oc_rep_set_pool(&rep_instance_memb);
		oc_free_rep(pushd_rsc_rep->rep);

		/* step 2. remove pushed resource representation from `pushed_rsc_rep_list` */
		oc_list_remove(pushd_rsc_rep_list, pushd_rsc_rep);
		oc_memb_free(&pushd_rsc_rep_instance_memb, pushd_rsc_rep);
	}
	else
	{
		p_err("can't find resource representation for pushed resource (%s)...\n", oc_string(uri));
		return;
	}

	if (pushd_rsc)
	{
		/* step 3. remove pushed Resource from `app_resources` */
		oc_delete_resource(pushd_rsc);
	}
	else
	{
		p_err("can't find pushed resource (%s)...\n", oc_string(uri));
		return;
	}

	return;
}



/**
 * @brief				oc_rep_set_pool() should be called before calling this func
 *
 * @param new_rep
 * @param org_rep
 */
void * _create_pushd_rsc_rep(oc_rep_t **new_rep, oc_rep_t *org_rep)
{
	if (!org_rep)
		return org_rep;

	*new_rep = oc_alloc_rep();

	(*new_rep)->next = _create_pushd_rsc_rep(&((*new_rep)->next), org_rep->next);

	(*new_rep)->type = org_rep->type;
	oc_new_string((*new_rep)->name, oc_string(org_rep->name), oc_string_len(org_rep->name));


	switch (org_rep->type)
	{
	case OC_REP_NIL:
		break;
	case OC_REP_INT:
		(*new_rep)->value.integer= org_rep->value.integer;
		break;
	case OC_REP_DOUBLE:
		(*new_rep)->value.double_p= org_rep->value.double_p;
		break;
	case OC_REP_BOOL:
		(*new_rep)->value.boolean = org_rep->value.boolean;
		break;
	case OC_REP_BYTE_STRING_ARRAY:
	case OC_REP_STRING_ARRAY:
		oc_new_string_array(&(*new_rep)->value.array, oc_string_array_get_allocated_size(org_rep->value.array));
		for (int i=0; i<oc_string_array_get_allocated_size(org_rep->value.array); i++)
		{
			oc_string_array_add_item((*new_rep)->value.array, oc_string_array_get_item(org_rep->value.array, i));
		}
		break;
	case OC_REP_BOOL_ARRAY:
		oc_new_bool_array(&(*new_rep)->value.array, oc_bool_array_size(org_rep->value.array));
		memcpy((*new_rep)->value.array.ptr, org_rep->value.array.ptr, org_rep->value.array.size*BYTE_POOL);
		break;
	case OC_REP_DOUBLE_ARRAY:
		oc_new_double_array(&(*new_rep)->value.array, oc_double_array_size(org_rep->value.array));
		memcpy((*new_rep)->value.array.ptr, org_rep->value.array.ptr, org_rep->value.array.size*DOUBLE_POOL);
		break;
	case OC_REP_INT_ARRAY:
		oc_new_int_array(&(*new_rep)->value.array, oc_int_array_size(org_rep->value.array));
		memcpy((*new_rep)->value.array.ptr, org_rep->value.array.ptr, org_rep->value.array.size*INT_POOL);
		break;
	case OC_REP_BYTE_STRING:
	case OC_REP_STRING:
		oc_new_string((*new_rep)->value.string, oc_string(org_rep->value.string), oc_string_len(org_rep->value.string));
		break;
	case OC_REP_OBJECT:
		(*new_rep)->value.object = _create_pushd_rsc_rep(&((*new_rep)->value.object), org_rep->value.object);
		break;
	case OC_REP_OBJECT_ARRAY:
		(*new_rep)->value.object_array = _create_pushd_rsc_rep(&((*new_rep)->value.object_array), org_rep->value.object_array);
		break;
	default:
		break;
	}

	return (*new_rep);
}



/**
 * @brief				create app resource and `oc_pushd_rsc_t` corresponding to pushed resource
 *
 * @param recv_obj	receiver object that points pushed resource
 * @param resource	Push Receiver resource
 */
void _create_pushd_rsc(oc_recv_t *recv_obj, oc_resource_t *resource)
{
	/* create Push Receiver Resource */
	oc_resource_t *pushd_rsc = oc_new_resource("Pushed Resource", oc_string(recv_obj->receiveruri), 1, resource->device);

//	oc_resource_bind_resource_type(push_recv, "oic.r.pushreceiver");
//	oc_resource_bind_resource_interface(push_recv, OC_IF_RW | OC_IF_BASELINE);
//	oc_resource_set_default_interface(push_recv, OC_IF_RW);
	oc_resource_set_discoverable(pushd_rsc, true);

	/*
	 * TODO4ME 2021/9/11 resume here...
	 */
	oc_resource_set_request_handler(pushd_rsc, OC_GET, get_pushd_rsc, NULL);
	oc_resource_set_request_handler(pushd_rsc, OC_POST, post_pushd_rsc, NULL);
//	oc_resource_set_request_handler(push_recv, OC_DELETE, delete_pushrecv, NULL);

	oc_add_resource(pushd_rsc);


	/* create resource representation container for this resource */
	oc_pushd_rsc_rep_t *pushd_rsc_rep_instance = (oc_pushd_rsc_rep_t *)oc_memb_alloc(&pushd_rsc_rep_instance_memb);
	if (pushd_rsc_rep_instance) {
		pushd_rsc_rep_instance->resource = pushd_rsc;
		pushd_rsc_rep_instance->rep = NULL;
		oc_list_add(pushd_rsc_rep_list, pushd_rsc_rep_instance);
	}
	else
	{
		p_err("oc_memb_alloc() error!\n");
	}
}




/**
 * @brief						remove receiver object array in `recv_obj_list`,
 * 								and app resource pointed by `receiveruri` of each receivre object in the array
 *
 * @param recv_obj_list		receiver object array
 * @param device_index		index of device where the Push Resource resides
 */
//void _purge_recv_obj_list(oc_list_t recv_obj_list, size_t device_index)
void _purge_recv_obj_list(oc_recvs_t *recvs_instance)
{
	/*
	 * TODO4ME oc_free_rep()를 참고해서 다시 작성해 볼것
	 */
//	oc_recv_t *recv_obj = (oc_recv_t *)oc_list_pop(recv_obj_list);
	oc_recv_t *recv_obj = (oc_recv_t *)oc_list_pop(recvs_instance->receivers);

	while (recv_obj)
	{
		/* delete app resource pointed by `receiveruri` first.. */
//		_purge_pushd_rsc(recv_obj->receiveruri, device_index);
		_purge_pushd_rsc(recv_obj->receiveruri, recvs_instance->resource->device);

		oc_free_string(&recv_obj->receiveruri);
		oc_free_string_array(&recv_obj->rts);
		oc_memb_free(&recv_instance_memb, recv_obj);

//		recv_obj = (oc_recv_t *)oc_list_pop(recv_obj_list);
		recv_obj = (oc_recv_t *)oc_list_pop(recvs_instance->receivers);
	}

	return;
}







/**
 * @brief				update existing receiver object with new payload
 *
 * @param recv_obj	existing receiver object
 * @param resource	app resource pointed by `recv_obj:receiveruri`
 * @param rep			payload representation of new receiver object
 */
//void _update_recv_obj(oc_recv_t *recv_obj, oc_resource_t *resource, oc_rep_t *rep)
void _update_recv_obj(oc_recv_t *recv_obj, oc_recvs_t *recvs_instance, oc_rep_t *rep)
{
	while (rep)
	{
		switch (rep->type)
		{
		case OC_REP_STRING:
			if (!strcmp(oc_string(rep->name), "receiveruri"))
			{
				/* if `receiveruri' is different from existing `receiveruri`,
				 * update URI of Resource pointed by previous `receiveruri` */
				if (strcmp(oc_string(recv_obj->receiveruri), oc_string(rep->value.string)))
				{
//					oc_free_string(&resource->uri);
					oc_free_string(&recvs_instance->resource->uri);
//					oc_store_uri(oc_string(rep->value.string), &resource->uri);
					oc_store_uri(oc_string(rep->value.string), &recvs_instance->resource->uri);
				}

				oc_free_string(&recv_obj->receiveruri);
				oc_new_string(&recv_obj->receiveruri, oc_string(rep->value.string),
									oc_string_len(rep->value.string));
			}
			break;
		case OC_REP_STRING_ARRAY:
			if (!strcmp(oc_string(rep->name), "rts"))
			{
				oc_free_string_array(&recv_obj->rts);
				int len = oc_string_array_get_allocated_size(rep->value.array);
				oc_new_string_array(&recv_obj->rts, len);

				for (int i=0; i < len; i++)
				{
					oc_string_array_add_item(recv_obj->rts, oc_string_array_get_item(rep->value.array, i));
				}
			}
			break;
		default:
			p_err("something wrong, unexpected Property type: %d\n", rep->type);
			return;
		}
		rep = rep->next;
	}

	return;
}



/**
 * @brief				create new receiver object
 *
 * @param recv_obj	pointer for new receiver object
 * @param rep			received new receiver object object
 */
//void _create_recv_obj(oc_list_t recv_obj_list, oc_rep_t *rep)
void _create_recv_obj(oc_recvs_t *recvs_instance, oc_rep_t *rep)
{
	oc_recv_t *recv_obj = (oc_recv_t *)oc_memb_alloc(&recv_instance_memb);
	if (!recv_obj)
	{
		p_err("oc_memb_alloc() error!\n");
		return;
	}

	while (rep)
	{
		switch (rep->type)
		{
		case OC_REP_STRING:
			if (!strcmp(oc_string(rep->name), "receiveruri"))
			{
				oc_new_string(&recv_obj->receiveruri, oc_string(rep->value.string),
									oc_string_len(rep->value.string));
			}
			break;
		case OC_REP_STRING_ARRAY:
			if (!strcmp(oc_string(rep->name), "rts"))
			{
				int len = oc_string_array_get_allocated_size(rep->value.array);
				oc_new_string_array(&recv_obj->rts, len);

				for (int i=0; i < len; i++)
				{
					oc_string_array_add_item(recv_obj->rts, oc_string_array_get_item(rep->value.array, i));
				}
			}
			break;
		default:
			p_err("something wrong, unexpected Property type: %d\n", rep->type);
//			return;
		}
		rep = rep->next;
	}

//	oc_list_add(recv_obj_list, recv_obj);
	oc_list_add(recvs_instance->receivers, recv_obj);

	/* create app resource corresponding to receiver object */
//	_create_pushd_rsc(recv_obj, recv_obj_list);
	_create_pushd_rsc(recv_obj, recvs_instance->resource);

	return;
}




/**
 * @brief					replace existing receiver object array with new one
 *
 * @param recv_obj_list	receiver object array
 * @param resource		Push Receiver resource
 * @param rep				payload representation of new receiver object array
 */
//void _replace_recv_obj_array(oc_list_t recv_obj_list, oc_resource_t *resource, oc_rep_t *rep)
void _replace_recv_obj_array(oc_recvs_t *recvs_instance, oc_rep_t *rep)
{
	int obj_arr_len;
	oc_rep_t *rep_obj;
	oc_rep_t *rep_obj_value;
	oc_recv_t *recv_obj_instance;

	/* remove existing receivers object array */
//	_purge_recv_obj_list(recv_obj_list, resource->device);
	_purge_recv_obj_list(recvs_instance);

	/* add new receivers object array */
	while (rep)
	{
		switch (rep->type)
		{
		case OC_REP_OBJECT_ARRAY:
			obj_arr_len = _get_obj_array_len(rep->value.object_array);
			rep_obj = rep->value.object_array;

			/* replace `receivers` obj array with new one */
			for (int i=0; i<obj_arr_len; i++, rep_obj=rep_obj->next)
			{
//				_create_recv_obj(recv_obj_list, rep_obj->value.object);
				_create_recv_obj(recvs_instance, rep_obj->value.object);
			} /* for */
			break;
		default:
			p_err("something wrong, unexpected Property type: %d\n", rep->type);
//			return;
		}
		rep = rep->next;
	} /* while */

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
	char *uri_param;
	int uri_param_len = -1;
	oc_recv_t *recv_obj;
	oc_recvs_t *recvs_instance;
	oc_rep_t *rep = request->request_payload;
	int result = OC_STATUS_CHANGED;

	/* try to get "receiveruri" parameter */
	if (request->query)
	{
		uri_param_len = oc_ri_get_query_value(request->query, request->query_len, "receiveruri", &uri_param);
		p_dbg("received query string: %s\n", request->query);
	}
	else
	{
		p_dbg("request->query is NULL\n");
	}

	/* look up target receivers of target Push Receiver Resource */
	recvs_instance = (oc_recvs_t *)oc_list_head(recvs_list);
	while (recvs_instance)
	{
		if (recvs_instance->resource == request->resource)
		{
			p_dbg("receivers obj array instance for target resource (%s) is found!\n", oc_sting(request->resource->uri));

			if (uri_param_len != -1)
			{
//				recv_obj = _find_recv_obj_by_uri(recvs_instance->receivers, uri_param, uri_param_len);
				recv_obj = _find_recv_obj_by_uri(recvs_instance, uri_param, uri_param_len);
				if (recv_obj)
				{
					/* if the given `receiveruri` parameter is in existing receivers array,
					 * just update existing receiver object */
//					_update_recv_obj(recv_obj, recvs_instance->resource, rep);
					_update_recv_obj(recv_obj, recvs_instance, rep);
				}
				else
				{
					/* if the given `receiveruri` parameter is not in existing receivers array,
					 * add new receiver object to the receivers array */
#ifdef PUSH_DEBUG
					oc_string_t uri;
					oc_new_string(&uri, uri_param, uri_param_len);
					p_err("can't find receiver object which has uri(%s)\n creating new receiver obj...", oc_string(uri));
					oc_free_string(&uri);
#endif

					/* create corresponding receiver object */
//					_create_recv_obj(recvs_instance->receivers, rep);
					_create_recv_obj(recvs_instance, rep);

					/* create app resource corresponding to receiver object */
//					_create_pushd_rsc(recv_obj, recvs_instance->resource);

//					result = OC_STATUS_NOT_FOUND;
				}
			}
			else
			{
				/* if `receiveruri` param is not provided..
				 * replace whole existing `receivers` object array with new one.. */
//				_replace_recv_obj_array(recvs_instance->receivers, recvs_instance->resource, rep);
				_replace_recv_obj_array(recvs_instance, rep);
			}
			break;
		}
		else
		{
			recvs_instance = recvs_instance->next;
		}
	}

#if 0
	while (rep)
	{
		switch (rep->type)
		{
		case OC_REP_OBJECT_ARRAY:
			/* update "oic.r.pushreceiver:receivers" with new receiver object array */
			if (!recvs_instance)
			{
				/* if `receivers` object array for the Resource has not been configured yet... */
				recvs_instance = (oc_recvs_t *)oc_memb_alloc(&recvs_instance_memb);

				if (recvs_instance) {
					recvs_instance->resource = request->resource;
					oc_list_add(recvs_list, recvs_instance);
				}
				else
				{
					p_err("oc_memb_alloc() error!");
					return;
				}
			}

			/* (re)allocate memory for `rts` property */
//			int obj_arr_len = oc_list_length(&rep->value.object_array);


			int obj_arr_len = _get_obj_array_len(rep->value.object_array);
			oc_mmem_alloc(recvs_instance->receivers, sizeof(oc_recv_t)*obj_arr_len, BYTE_POOL);
			if (OC_MMEM_PTR(recvs_instance->receivers) == NULL)
			{
				p_err("oc_mmem_alloc() error!");
				return;
			}

			oc_recv_t *recv_array = (oc_recv_t *)recvs_instance->receivers;
			oc_rep_t *rep_obj = rep->value.object_array;
			oc_rep_t *rep_obj_value;

			/* replace `receivers` obj array with new one */
			for (int i=0; i<obj_arr_len; i++, rep_obj=rep_obj->next)
			{
				rep_obj_value = rep_obj->value.object;

				while (rep_obj_value)
				{
					switch (rep_obj_value->type)
					{
					case OC_REP_STRING:
						if (!strcmp("uri", oc_string(rep_obj_value->name)))
						{
							oc_new_string(&recv_array[i].receiveruri, oc_string(rep_obj_value->value.string),
												oc_string_len(rep_obj_value->value.string));
						}
						break;
					case OC_REP_STRING_ARRAY:
						if (!strcmp("rts", oc_string(rep_obj_value->name)))
						{
							oc_new_string_array(&recv_array[i].rts,
														oc_string_array_get_allocated_size(rep_obj_value->value.array));
							for (int j=0; j<oc_string_array_get_allocated_size(rep_obj_value->value.array); j++)
							{
								oc_string_array_add_item(recv_array[i].rts,
																oc_string_array_get_item(rep_obj_value->value.array, j));
							}
						}
						break;
					default:
						break;
					}
					rep_obj_value = rep_obj_value->next;
				}
			} /* for */
			break;
		default:
			break;
		}
		rep = rep->next;
	} /* while (rep) */
#endif

	oc_send_response(request, result);

	return;
}




/**
 * @briefe
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
void delete_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{

}




/**
 *
 * @brief	initiate Push Receiver Resource
 *
 * @param device_index
 */
void init_pushreceiver_resource(size_t device_index)
{
	/* create Push Receiver Resource */
	oc_resource_t *push_recv = oc_new_resource("Push Receiver", "/pushreceivers", 1, device_index);

	oc_resource_bind_resource_type(push_recv, "oic.r.pushreceiver");
	oc_resource_bind_resource_interface(push_recv, OC_IF_RW | OC_IF_BASELINE);
	oc_resource_set_default_interface(push_recv, OC_IF_RW);
	oc_resource_set_discoverable(push_recv, true);

	oc_resource_set_request_handler(push_recv, OC_GET, get_pushrecv, NULL);
	oc_resource_set_request_handler(push_recv, OC_POST, post_pushrecv, NULL);
	oc_resource_set_request_handler(push_recv, OC_DELETE, delete_pushrecv, NULL);

	oc_add_resource(push_recv);

	/*
	 * add struct for `receivers` object list for this Resource to the list
	 */
	oc_recvs_t *recvs_instance = (oc_recvs_t *)oc_memb_alloc(&recvs_instance_memb);
	if (recvs_instance) {
		recvs_instance->resource = push_recv;
		oc_list_init(recvs_instance->receivers);
		oc_list_add(recvs_list, recvs_instance);
	}
	else
	{
		p_err("oc_memb_alloc() error!\n");
	}
}


void oc_push_list_init()
{
	oc_list_init(ns_list);
	oc_list_init(recvs_list);
	oc_list_init(pushd_rsc_rep_list);
}


OC_PROCESS_THREAD(oc_push_process, ev, data)
{
	oc_resource_t *src_rsc;

	OC_PROCESS_BEGIN();

	do {
		int device_count = oc_core_get_num_devices();

		/* create Push Notification Resource per each Device */
		for (int i=0; i<device_count; i++) {
			/*
			 * TODO4ME push 관련 리소스 초기화를 oc_core_add_new_device()에서 수행하도록 바꿀것
			 */
			init_pushconf_resource(i);
			init_pushreceiver_resource(i);
		}

		OC_PROCESS_YIELD();

		/* send UPDATE to target server */
		if (ev == oc_events[PUSH_RSC_STATE_CHANGED]) {
			src_rsc = (oc_resource_t *)data;
			/*
			 * client에서 POST 하는 루틴 참조할 것 (client_multithread_linux.c 참고)
			 */
			/* TODO4ME 2021/8/30 resume here.. */
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
	/*
	 * TODO4ME 여기서 변동이 생긴 resource가 부합되는 notification selector가 있는지 확인해야 한다
	 */

	if (!oc_process_is_running(&oc_push_process)) {
		p_dbg("oc_push_process is not running!\n");
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

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
 * 				Author: jclee
 *
 *
 ****************************************************************************/


#include "oc_push.h"

#if defined(OC_PUSH) && defined(OC_SERVER) && defined(OC_CLIENT) && defined(OC_DYNAMIC_ALLOCATION) && defined(OC_COLLECTIONS_IF_CREATE)

#include "oc_api.h"
#include "oc_events.h"
#include "oc_rep.h"
#include "oc_endpoint.h"
#include "oc_ri.h"
#include "oc_core_res.h"
#include "oc_signal_event_loop.h"
#include "util/oc_process.h"
#include "util/oc_list.h"
#include "util/oc_mmem.h"
#include <arpa/inet.h>

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
 * 			each list member is instance of `oc_recvs_t`
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



char *pp_state_strs[] =
{
		"waitingforprovisioning",			/*OC_PP_WFP*/
		"waitingforupdate",					/*OC_PP_WFU*/
		"waitingforresponse",				/*OC_PP_WFR*/
		"waitingforupdatemitigation",		/*OC_PP_WFUM*/
		"waitingforresponsemitigation",	/*OC_PP_WFRM*/
		"error",									/*OC_PP_ERR*/
		"timeout"								/*OC_PP_TOUT*/
};



char *cli_status_strs[] =
{
		"OC_STATUS_OK",                        /* 0 */
		"OC_STATUS_CREATED",                   /* 1 */
		"OC_STATUS_CHANGED",                   /* 2 */
		"OC_STATUS_DELETED",                   /* 3 */
		"OC_STATUS_NOT_MODIFIED",              /* 4 */
		"OC_STATUS_BAD_REQUEST",               /* 5 */
		"OC_STATUS_UNAUTHORIZED",              /* 6 */
		"OC_STATUS_BAD_OPTION",                /* 7 */
		"OC_STATUS_FORBIDDEN",                 /* 8 */
		"OC_STATUS_NOT_FOUND",                 /* 9 */
		"OC_STATUS_METHOD_NOT_ALLOWED",        /* 10 */
		"OC_STATUS_NOT_ACCEPTABLE",            /* 11 */
		"OC_STATUS_REQUEST_ENTITY_TOO_LARGE",  /* 12 */
		"OC_STATUS_UNSUPPORTED_MEDIA_TYPE",    /* 13 */
		"OC_STATUS_INTERNAL_SERVER_ERROR",     /* 14 */
		"OC_STATUS_NOT_IMPLEMENTED",           /* 15 */
		"OC_STATUS_BAD_GATEWAY",               /* 16 */
		"OC_STATUS_SERVICE_UNAVAILABLE",       /* 17 */
		"OC_STATUS_GATEWAY_TIMEOUT",           /* 18 */
		"OC_STATUS_PROXYING_NOT_SUPPORTED"     /* 19 */
};


/*
 * mandatory property of oic.r.pushporxy, oic.r.pushreceivers
 */
enum {
	PP_PUSHTARGET = 0x01,
	PP_SOURCERT = 0x02,
	PR_RECEIVERS = 0x01,
	PR_RECEIVERURI = 0x02,
	PR_RTS = 0x04
};


/*
 * if this callback function is provided by user, it will called whenever new push is arrived...
 */
void (*oc_push_arrived)(oc_pushd_rsc_rep_t *) = NULL;



/*
 * FIXME4ME use `oc_ri_get_interface_mask()` instead of this...
 */
oc_interface_mask_t _get_ifmask_from_ifstr(char *ifstr)
{
	oc_interface_mask_t iface = 0;

	if (!strcmp(ifstr, "oic.if.baseline"))
	{
		iface = OC_IF_BASELINE;
	}
	else if (!strcmp(ifstr, "oic.if.ll"))
	{
		iface = OC_IF_LL;
	}
	else if (!strcmp(ifstr, "oic.if.b"))
	{
		iface = OC_IF_B;
	}
	else if (!strcmp(ifstr, "oic.if.r"))
	{
		iface = OC_IF_R;
	}
	else if (!strcmp(ifstr, "oic.if.rw"))
	{
		iface = OC_IF_RW;
	}
	else if (!strcmp(ifstr, "oic.if.a"))
	{
		iface = OC_IF_A;
	}
	else if (!strcmp(ifstr, "oic.if.s"))
	{
		iface = OC_IF_S;
	}
	else if (!strcmp(ifstr, "oic.if.create"))
	{
		iface = OC_IF_CREATE;
	}

	return iface;
}


bool _is_null_pushtarget(oc_ns_t *ns_instance)
{
	char ipv6addrstr[50], ipv4addrstr[50];

	inet_ntop(AF_INET6, ns_instance->pushtarget_ep.addr.ipv6.address, ipv6addrstr, 50);
	inet_ntop(AF_INET, ns_instance->pushtarget_ep.addr.ipv4.address, ipv4addrstr, 50);

	if (!strcmp(ipv6addrstr, "::") && !strcmp(ipv4addrstr, "0.0.0.0"))
		return true;

	return false;
}


/**
 * @brief				callback to be called to set existing (or just created by `get_ns_instance()`)
 * 						user-defined data structure for `notification selector` with received Resource representation
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
	bool result = false;
//	bool is_null_pushtarget = false;
//	char mandatory_properties_check = 0;

	/*
	 * `data` is set when new Notification Selector Resource is created
	 * by calling `oc_resource_set_properties_cbs()` in `get_ns_instance()`
	 */
	oc_ns_t *ns_instance = (oc_ns_t *)data;
	while (rep != NULL) {
		switch (rep->type) {
		case OC_REP_STRING:
			/*
			 * oic.r.notificationselector:phref (optional)
			 */
			if (oc_string_len(rep->name) == 5 && memcmp(oc_string(rep->name), "phref", 5) == 0)
			{
				oc_free_string(&ns_instance->phref);
				oc_new_string(&ns_instance->phref, oc_string(rep->value.string), oc_string_len(rep->value.string));
				p_dbg("oic.r.pushproxy:phref (%s)\n", oc_string(rep->value.string));
			}
			/*
			 * oic.r.pushproxy:pushtarget (mandatory)
			 */
			else if (oc_string_len(rep->name) == 10 && memcmp(oc_string(rep->name), "pushtarget", 10) == 0)
			{
				if (!strcmp(oc_string(rep->value.string), ""))
				{
					/* NULL pushtarget ("") is still acceptable... */
					p_dbg("NULL \"pushtarget\" is received, still stay in \"waitforprovisioning\" state...\n");

					/* clear endpoint */
					memset((void *)(&ns_instance->pushtarget_ep), 0, sizeof(ns_instance->pushtarget_ep));

					/* clear target path */
					oc_free_string(&ns_instance->targetpath);
					oc_new_string(&ns_instance->targetpath, "", strlen(""));

//					is_null_pushtarget = true;
//					mandatory_properties_check |= PP_PUSHTARGET;
				}
				else
				{
					/* if non-NULL pushtarget.. */
					oc_endpoint_t *new_ep;
					oc_string_t new_targetpath;

					new_ep = oc_new_endpoint();
					oc_init_string(new_targetpath);

					p_dbg("oic.r.pushproxy:pushtarget (%s)\n", oc_string(rep->value.string));

//					if (oc_string_to_endpoint(&rep->value.string, &ns_instance->pushtarget_ep, &ns_instance->targetpath) < 0)
					if (oc_string_to_endpoint(&rep->value.string, new_ep, &new_targetpath) < 0)
					{
						p_err("oic.r.pushproxy:pushtarget (%s) parsing failed!\n", oc_string(rep->value.string));

						oc_free_endpoint(new_ep);
						oc_free_string(&new_targetpath);

						goto exit;
					}
					else
					{
						oc_free_string(&ns_instance->targetpath);

						/* update with new values... */
						oc_endpoint_copy(&ns_instance->pushtarget_ep, new_ep);
						oc_new_string(&ns_instance->targetpath, oc_string(new_targetpath), oc_string_len(new_targetpath));

						p_dbg("oic.r.pushproxy:pushtarget (%s)\n", oc_string(rep->value.string));

						/* return memory */
						oc_free_endpoint(new_ep);
						oc_free_string(&new_targetpath);

						if (oc_string_len(ns_instance->targetpath))
						{
							p_dbg("oic.r.pushproxy:pushtarget parsing is successful! targetpath (\"%s\")\n", oc_string(ns_instance->targetpath));
//							mandatory_properties_check |= PP_PUSHTARGET;
						}
						else
						{
							p_err("path part of \"pushtarget\" should not be NULL!!\n");
							goto exit;
						}
					}
				}
			}
			/*
			 * TODO4ME <2022/04/17> deprecated property, remove later...
			 * oic.r.pushproxy:pushqif (optional)
			 */
			else if (oc_string_len(rep->name) == 7 && memcmp(oc_string(rep->name), "pushqif", 7) == 0)
			{
				oc_free_string(&ns_instance->pushqif);
				oc_new_string(&ns_instance->pushqif, oc_string(rep->value.string), oc_string_len(rep->value.string));
			}
			break;

		case OC_REP_STRING_ARRAY:
			/*
			 * oic.r.notificationselector:prt (optional)
			 */
			if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "prt", 3) == 0)
			{
				/*
				 * fixme4me <2022/4/18> ""를 넘겨줬을때 prt 내용 삭제하도록 수정
				 */
//				if (oc_string_array_get_allocated_size(ns_instance->prt))
					oc_free_string_array(&ns_instance->prt);

				oc_new_string_array(&ns_instance->prt, oc_string_array_get_allocated_size(rep->value.array));

				for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					p_dbg("oic.r.pushproxy:prt (%s)\n", oc_string_array_get_item(rep->value.array, i));
					oc_string_array_add_item(ns_instance->prt, oc_string_array_get_item(rep->value.array, i));
				}
			}
			/*
			 * oic.r.notificationselector:pif (optional)
			 */
			else if (oc_string_len(rep->name) == 3 && memcmp(oc_string(rep->name), "pif", 3) == 0)
			{
//				if (oc_string_array_get_allocated_size(ns_instance->pif))
					oc_free_string_array(&ns_instance->pif);

				oc_new_string_array(&ns_instance->pif, oc_string_array_get_allocated_size(rep->value.array));

				for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					p_dbg("oic.r.pushproxy:pif (%s)\n", oc_string_array_get_item(rep->value.array, i));
					oc_string_array_add_item(ns_instance->pif, oc_string_array_get_item(rep->value.array, i));
				}
			}
			/*
			 * oic.r.pushproxy:sourcert (mandatory)
			 */
			else if (oc_string_len(rep->name) == 8 && memcmp(oc_string(rep->name), "sourcert", 8) == 0)
			{
//				if (oc_string_array_get_allocated_size(ns_instance->sourcert))
//					oc_free_string_array(&ns_instance->sourcert);

//				oc_new_string_array(&ns_instance->sourcert, oc_string_array_get_allocated_size(rep->value.array));

				/*
				 * FIXME4ME<done> 만약 config client가 sourcert를 oic.r.pushpayload 이외의 것으로 설정하려 하면  bad request 에러를 리턴해야 함 (shall)
				 */
				for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					if (strcmp(oc_string_array_get_item(rep->value.array, i), "oic.r.pushpayload"))
					{
//						oc_free_string_array(&ns_instance->sourcert);
						p_err("illegal oic.r.pushproxy:sourcert value (%s)!\n", oc_string_array_get_item(rep->value.array, i));
						goto exit;
					}
				}

				oc_free_string_array(&ns_instance->sourcert);
				oc_new_string_array(&ns_instance->sourcert, oc_string_array_get_allocated_size(rep->value.array));
				for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
				{
					p_dbg("oic.r.pushproxy:sourcert (%s)\n", oc_string_array_get_item(rep->value.array, i));
					oc_string_array_add_item(ns_instance->sourcert, oc_string_array_get_item(rep->value.array, i));
				}

//				mandatory_properties_check |= PP_SOURCERT;
			}
			break;

		case OC_REP_INT:
			/*
			 * oic.r.pushproxy:state (RETRIEVE:mandatory, UPDATE:optional)
			 */
			if (oc_string_len(rep->name) == 5 && memcmp(oc_string(rep->name), "state", 5) == 0)
			{
				p_dbg("state of Push Proxy (\"%s\") is changed (%s => %s)\n", oc_string(ns_instance->resource->uri),
						oc_string(ns_instance->state), oc_string(rep->value.string));
//						pp_statestr(ns_instance->state), pp_statestr(rep->value.integer));
				pp_update_state(ns_instance->state, oc_string(rep->value.string));
//				ns_instance->state = rep->value.integer;
			}
			break;

		default:
			break;
		}
		rep = rep->next;
	}

#if 0
	if ((mandatory_properties_check & (PP_PUSHTARGET | PP_SOURCERT)) != (PP_PUSHTARGET | PP_SOURCERT))
	{
		p_err("mandatory properties of Push Proxy Resources are not provided!\n");
		goto exit;
	}
#endif

//	if (!is_null_pushtarget)
	if (!_is_null_pushtarget(ns_instance))
	{
		p_dbg("state of Push Proxy (\"%s\") is changed (%s => %s)\n", oc_string(ns_instance->resource->uri),
				oc_string(ns_instance->state), pp_statestr(OC_PP_WFU));
//		pp_statestr(ns_instance->state), pp_statestr(OC_PP_WFU));
		pp_update_state(ns_instance->state, pp_statestr(OC_PP_WFU));
//		ns_instance->state = OC_PP_WFU;
	}
	else
	{
		p_dbg("pushtarget of Push Proxy (\"%s\") is still NULL, Push Proxy is in (\"%s\")\n",
				oc_string(ns_instance->resource->uri), oc_string(ns_instance->state));
	}

	result = true;

exit:
	return result;
}



/**
 *
 * @brief 					callback to be called to fill the contents of `notification selector` from existing user-defined data structure (`oc_ns_t`)
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

	oc_rep_begin_root_object();
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

		/*
		 * prt (optional)
		 */
		if (oc_string_array_get_allocated_size(ns_instance->prt))
		{
			oc_rep_open_array(root, prt);
			for (int i=0; i < (int)oc_string_array_get_allocated_size(ns_instance->prt); i++)
			{
				oc_rep_add_text_string(prt, oc_string_array_get_item(ns_instance->prt, i));
			}
			oc_rep_close_array(root, prt);
		}

		/*
		 * pif (optional)
		 */
		if (oc_string_array_get_allocated_size(ns_instance->pif))
		{
			oc_rep_open_array(root, pif);
			for (int i=0; i < (int)oc_string_array_get_allocated_size(ns_instance->pif); i++)
			{
				oc_rep_add_text_string(pif, oc_string_array_get_item(ns_instance->pif, i));
			}
			oc_rep_close_array(root, pif);
		}

		/*
		 * pushtarget
		 */
//		oc_process_post(&oc_push_process, oc_events[PUSH_RSC_STATE_CHANGED], ns_instance);

		oc_string_t ep, full_uri;
		/*
		 * FIXME4ME<done> <2022/4/17> handle the case when "pushtarget" is NULL string...
		 */
		/*
		 * testcode
		 */
//		if (!inet_ntop(AF_INET6, ns_instance->pushtarget_ep.addr.ipv6.address, address, 1000))
//			p_dbg("inet_ntop failed\n");
//		else
//			p_dbg("inet_ntop success: %s\n", address);

		if (oc_endpoint_to_string(&ns_instance->pushtarget_ep, &ep) < 0)
		{
			/* handle NULL pushtarget... */
#if 0
			char ipv6addrstr[50], ipv4addrstr[50];
			inet_ntop(AF_INET6, ns_instance->pushtarget_ep.addr.ipv6.address, ipv6addrstr, 50);
			inet_ntop(AF_INET, ns_instance->pushtarget_ep.addr.ipv4.address, ipv4addrstr, 50);

			if (!strcmp(ipv6addrstr, "::") && !strcmp(ipv4addrstr, "0.0.0.0"))
			{
				oc_new_string(&full_uri, "", strlen(""));
			}
#endif
			if (_is_null_pushtarget(ns_instance))
			{
				oc_new_string(&full_uri, "", strlen(""));
			}
		}
		else
		{
			if (oc_string_len(ns_instance->targetpath))
				oc_concat_strings(&full_uri, oc_string(ep), oc_string(ns_instance->targetpath));
			else
				oc_new_string(&full_uri, oc_string(ep), oc_string_len(ep));

			oc_free_string(&ep);
		}

		oc_rep_set_text_string(root, pushtarget, oc_string(full_uri));
		oc_free_string(&full_uri);

		/*
		 * pushqif
		 */
		oc_rep_set_text_string(root, pushqif, oc_string(ns_instance->pushqif));

		/*
		 * sourcert
		 */
		if (oc_string_array_get_allocated_size(ns_instance->sourcert))
		{
			oc_rep_open_array(root, sourcert);
			for (int i=0; i < (int)oc_string_array_get_allocated_size(ns_instance->sourcert); i++)
			{
				oc_rep_add_text_string(sourcert, oc_string_array_get_item(ns_instance->sourcert, i));
			}
			oc_rep_close_array(root, sourcert);
		}

		/*
		 * state
		 */
//		oc_rep_set_int(root, state, ns_instance->state);
		oc_rep_set_text_string(root, state, oc_string(ns_instance->state));

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
	(void)iface_mask;

	p_dbg("trying to update notification selector (\"%s\")... \n", oc_string(request->resource->uri));

	if (set_ns_properties(request->resource, request->request_payload, user_data))
		oc_send_response(request, OC_STATUS_CHANGED);
	else
		oc_send_response(request, OC_STATUS_BAD_REQUEST);

}



void delete_ns(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	(void)iface_mask;
	(void)user_data;

	p_dbg("trying to delete notification selector (\"%s\")... \n", oc_string(request->resource->uri));

	if (oc_delete_resource(request->resource))
		oc_send_response(request, OC_STATUS_DELETED);
	else
		oc_send_response(request, OC_STATUS_BAD_REQUEST);
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
			for (int i = 0; i < (int)oc_string_array_get_allocated_size(*types); i++) {
				const char *rt = oc_string_array_get_item(*types, i);
				oc_resource_bind_resource_type(ns_instance->resource, rt);
			}
			oc_resource_bind_resource_interface(ns_instance->resource, iface_mask);
			ns_instance->resource->properties = bm;
			oc_resource_set_default_interface(ns_instance->resource, OC_IF_RW);
			oc_resource_set_request_handler(ns_instance->resource, OC_GET, get_ns, ns_instance);
			oc_resource_set_request_handler(ns_instance->resource, OC_POST, post_ns, ns_instance);
			oc_resource_set_request_handler(ns_instance->resource, OC_DELETE, delete_ns, ns_instance);
			oc_resource_set_properties_cbs(ns_instance->resource, get_ns_properties, ns_instance, set_ns_properties, ns_instance);
			oc_add_resource(ns_instance->resource);

			p_dbg("new link (\"%s\") and corresponding resource for \"%s\" collection is created\n", oc_string(ns_instance->resource->uri), PUSHCONF_RSC_PATH);

//			ns_instance->state = OC_PP_WFP;
			oc_new_string(&ns_instance->state, pp_statestr(OC_PP_WFP), strlen(pp_statestr(OC_PP_WFP)));

			p_dbg("state of Push Proxy (\"%s\") is initialized (%s)\n", oc_string(ns_instance->resource->uri), pp_statestr(OC_PP_WFP));

#if 0
			p_dbg("rt: { ");
			for (int i=0; i<(int)oc_string_array_get_allocated_size(ns_instance->resource->types); i++)
			{
				p_dbg("\t%s ", oc_string_array_get_item(ns_instance->resource->types, i));
			}
			p_dbg("}\n");
#endif

			/*
			 * add this new Notification Selector Resource to the list
			 * which keeps all Notification Selectors of all Devices
			 */
			oc_list_add(ns_list, ns_instance);
			return ns_instance->resource;
		} else {
			p_err("oc_new_resource() error!\n");
			oc_memb_free(&ns_instance_memb, ns_instance);
		}
	}
	else
	{
		p_err("oc_memb_alloc() error!\n");
	}

	return NULL;
}


/**
 *
 * @brief callback for freeing existing notification selector
 * 		(this callback is called when target resource pointed by `link` is deleted by calling `oc_delete_resource()`)
 *
 */
void free_ns_instance(oc_resource_t *resource)
{
	oc_ns_t *ns_instance = (oc_ns_t *)oc_list_head(ns_list);
	oc_endpoint_t *ep;

	p_dbg("delete ns_instance for resource (\"%s\")...\n", oc_string(resource->uri));

	while (ns_instance)
	{
		if (ns_instance->resource == resource)
		{
//			oc_delete_resource(resource);

			oc_list_remove(ns_list, ns_instance);

			/* free each field of ns_instance */
			oc_free_string(&ns_instance->phref);
			oc_free_string_array(&ns_instance->prt);
			oc_free_string_array(&ns_instance->pif);

			ep = ns_instance->pushtarget_ep.next;
			while (ep)
			{
				oc_free_endpoint(ep);
				ep = ep->next;
			}

			oc_free_string(&ns_instance->targetpath);
			oc_free_string(&ns_instance->pushqif);
			oc_free_string_array(&ns_instance->sourcert);

			oc_free_string(&ns_instance->state);

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
void oc_create_pushconf_resource(size_t device_index)
{
	/* create Push Configuration Resource */
	oc_resource_t *push_conf = oc_new_collection("Push Configuration", PUSHCONF_RSC_PATH, 1, device_index);

	if (push_conf)
	{
		oc_resource_bind_resource_type(push_conf, "oic.r.pushconfiguration");
		oc_resource_bind_resource_interface(push_conf, OC_IF_LL |  OC_IF_CREATE | OC_IF_BASELINE); /* XXX4ME OC_IF_DELETE is not defined yet.. */
		oc_resource_set_default_interface(push_conf, OC_IF_LL);
		oc_resource_set_discoverable(push_conf, true);

		/* set "rts" Property */
		oc_collection_add_supported_rt(push_conf, "oic.r.notificationselector");
		oc_collection_add_supported_rt(push_conf, "oic.r.pushproxy");

		/* LINK creation, deletion handler */
		oc_collections_add_rt_factory("oic.r.notificationselector", get_ns_instance, free_ns_instance);
		//	oc_collections_add_rt_factory("oic.r.pushproxy", get_pp_instance, free_pp_instance);

		oc_add_collection(push_conf);
	}
	else
	{
		p_err("oc_new_collection() error!\n");
	}
}




void _build_rep_payload(CborEncoder *parent, oc_rep_t *rep)
{
	CborEncoder child;
	oc_rep_t *obj;

	if (!rep)
		return;

	/*
	 * FIXME4ME should I check if rep->name is NULL?
	 */
	switch (rep->type)
	{
	case OC_REP_NIL:
		break;

	case OC_REP_INT:
		/* oc_rep_set_int(object, key, value) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
		g_err |= cbor_encode_int(parent, rep->value.integer);
		break;

	case OC_REP_DOUBLE:
		/* oc_rep_set_double(object, key, value) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
		g_err |= cbor_encode_double(parent, rep->value.double_p);
		break;

	case OC_REP_BOOL:
		/* oc_rep_set_boolean(object, key, value) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
		g_err |= cbor_encode_boolean(parent, rep->value.boolean);
		break;

	case OC_REP_BYTE_STRING_ARRAY:
		/* oc_rep_open_array(root, xxxx) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
	   g_err |= cbor_encoder_create_array(parent, &child, CborIndefiniteLength);

	   /* oc_rep_add_byte_string(xxxx, str); */
	   for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
	   {
	   	g_err |= cbor_encode_byte_string(&child, (const uint8_t *)oc_string_array_get_item(rep->value.array, i),
	   												strlen(oc_string_array_get_item(rep->value.array, i)));
	   }

	   /* oc_rep_close_array(root, xxxx); */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	case OC_REP_STRING_ARRAY:
//		oc_rep_start_root_object();
//		oc_rep_open_array(root, quotes);
//		oc_rep_add_text_string(quotes, str0);
//		oc_rep_add_text_string(quotes, str1);
//		oc_rep_add_text_string(quotes, str2);
//		oc_rep_add_text_string(quotes, str3);
//		oc_rep_close_array(root, quotes);
//		oc_rep_end_root_object();

		/* oc_rep_open_array(root, xxxx) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
	   g_err |= cbor_encoder_create_array(parent, &child, CborIndefiniteLength);

	   /* oc_rep_add_text_string(xxxx, str); */
	   for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
	   {
	      if ((const char *)oc_string_array_get_item(rep->value.array, i) != NULL) {
	        g_err |= cbor_encode_text_string(&child, oc_string_array_get_item(rep->value.array, i),
	      		  	  	  	  	  	  	  	  	  	  strlen(oc_string_array_get_item(rep->value.array, i)));
	      } else {
	        g_err |= cbor_encode_text_string(&child, "", 0);
	      }
	   }

	   /* oc_rep_close_array(root, xxxx); */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	case OC_REP_BOOL_ARRAY:
		/* oc_rep_open_array(root, xxxx) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
	   g_err |= cbor_encoder_create_array(parent, &child, CborIndefiniteLength);

	   /* oc_rep_add_boolean(xxxx, value); */
	   for (int i=0; i<(int)rep->value.array.size; i++)
	   {
	   	g_err |= cbor_encode_boolean(&child, ((char *)(rep->value.array.ptr))[i]);
	   }

	   /* oc_rep_close_array(root, xxxx); */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	case OC_REP_DOUBLE_ARRAY:
		/* oc_rep_open_array(root, xxxx) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
	   g_err |= cbor_encoder_create_array(parent, &child, CborIndefiniteLength);

	   /* oc_rep_add_double(xxxx, value); */
	   for (int i=0; i<(int)rep->value.array.size; i++)
	   {
	   	g_err |= cbor_encode_double(&child, ((double *)(rep->value.array.ptr))[i]);
	   }

	   /* oc_rep_close_array(root, xxxx); */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	case OC_REP_INT_ARRAY:
		/* oc_rep_open_array(root, xxxx) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
	   g_err |= cbor_encoder_create_array(parent, &child, CborIndefiniteLength);

	   /* oc_rep_add_int(xxxx, value); */
	   for (int i=0; i<(int)rep->value.array.size; i++)
	   {
	   	g_err |= cbor_encode_int(&child, ((int64_t *)(rep->value.array.ptr))[i]);
	   }

	   /* oc_rep_close_array(root, xxxx); */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	case OC_REP_BYTE_STRING:
		/* oc_rep_set_byte_string(object, key, value, length) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
		g_err |= cbor_encode_byte_string(parent, (const uint8_t *)oc_string(rep->value.string), oc_string_len(rep->value.string));
		break;

	case OC_REP_STRING:
		/* oc_rep_set_text_string(object, key, value) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
		if ((const char *)oc_string(rep->value.string) != NULL) {
			g_err |= cbor_encode_text_string(parent, oc_string(rep->value.string), oc_string_len(rep->value.string));
		} else {
			g_err |= cbor_encode_text_string(parent, "", 0);
		}
		break;

	case OC_REP_OBJECT:
//		oc_rep_start_root_object();
//		oc_rep_set_object(root, my_object);
//		oc_rep_set_int(my_object, a, 1);
//		oc_rep_set_boolean(my_object, b, false);
//		oc_rep_set_text_string(my_object, c, "three");
//		oc_rep_close_object(root, my_object);
//		oc_rep_end_root_object();

		/* oc_rep_open_object(parent, key) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
		g_err |= cbor_encoder_create_map(parent, &child, CborIndefiniteLength);

		_build_rep_payload(&child, rep->value.object);

	   /* oc_rep_close_object(parent, key) */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	case OC_REP_OBJECT_ARRAY:
		/*
		 * TODO4ME test this...!
		 */
//		 oc_rep_start_root_object();
//		 oc_rep_set_array(root, space2001);
//
//		 oc_rep_object_array_begin_item(space2001);
//		 oc_rep_set_text_string(space2001, name, "Dave Bowman");
//		 oc_rep_set_text_string(space2001, job, "astronaut");
//		 oc_rep_object_array_end_item(space2001);
//
//		 oc_rep_object_array_begin_item(space2001);
//		 oc_rep_set_text_string(space2001, name, "Frank Poole");
//		 oc_rep_set_text_string(space2001, job, "astronaut");
//		 oc_rep_object_array_end_item(space2001);
//
//		 oc_rep_object_array_begin_item(space2001);
//		 oc_rep_set_text_string(space2001, name, "Hal 9000");
//		 oc_rep_set_text_string(space2001, job, "AI computer");
//		 oc_rep_object_array_end_item(space2001);
//
//		 oc_rep_close_array(root, space2001);
//		 oc_rep_end_root_object();

		/* oc_rep_open_array(root, xxxx) */
		g_err |= cbor_encode_text_string(parent, oc_string(rep->name), oc_string_len(rep->name));
	   g_err |= cbor_encoder_create_array(parent, &child, CborIndefiniteLength);

	   /* recurse remaining objects... */
	   /*
	    * oc_rep_object_array_begin_item(xxxx)
	    * ...
	    * oc_rep_object_array_end_item(xxxx)
	    */
	   obj = rep->value.object_array;
	   while (obj)
	   {
			do
			{
				/* oc_rep_object_array_begin_item(key) */
				CborEncoder obj_map;
				g_err |= cbor_encoder_create_map(&child, &obj_map, CborIndefiniteLength);

				_build_rep_payload(&obj_map, obj->value.object);

				/* oc_rep_object_array_end_item(key) */
				g_err |= cbor_encoder_close_container(&child, &obj_map);
			} while (0);
			obj = obj->next;
	   }

	   /* oc_rep_close_array(root, xxxx); */
	   g_err |= cbor_encoder_close_container(parent, &child);
		break;

	default:
		break;
	}

	_build_rep_payload(parent, rep->next);

	return;
}




/**
 * @brief
 *
 * @param uri
 * @param device_index
 * @return
 */
oc_pushd_rsc_rep_t * _find_pushd_rsc_rep_by_uri(oc_string_t *uri, size_t device_index)
{
	oc_pushd_rsc_rep_t *pushd_rsc_rep = (oc_pushd_rsc_rep_t *)(oc_list_head(pushd_rsc_rep_list));

	while (pushd_rsc_rep)
	{
		if (!strcmp(oc_string(pushd_rsc_rep->resource->uri), oc_string(*uri))
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



void get_pushd_rsc(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	(void)user_data;

	int result = OC_STATUS_OK;
	oc_pushd_rsc_rep_t *pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(&request->resource->uri, request->resource->device);

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
			/* fall through */
		case OC_IF_R:
		case OC_IF_RW:
			_build_rep_payload(&root_map, pushd_rsc_rep->rep);
			break;
		default:
			break;
		}
		oc_rep_end_root_object();

		oc_send_response(request, result);
	}
	else
	{
		p_err("resource representation for pushed resource (%s) is found, but no resource representation for it is built yet!\n",
				oc_string(request->resource->uri));
		/*
		 * FIXME4ME<done> send response here too!!!
		 */
		oc_send_response(request, OC_STATUS_NOT_FOUND);
	}

	return;
}



/**
 * @brief				check if "rt" of pushed resource is part of "rts" (all value of "rt" should be part of "rts")
 *
 * @param recv_obj
 * @param rep
 * @return	not 0: found
 * 			0: not found
 */
char _check_pushd_rsc_rt(oc_recv_t *recv_obj, oc_rep_t *rep)
{
	char result = 0;
	int rt_len, rts_len;
	int i, j;

	if (!recv_obj || !rep)
		return result;

	rts_len = oc_string_array_get_allocated_size(recv_obj->rts);

	/* if "rts" is not configured (""), any pushed resource can be accepted... */
	if ((rts_len == 1) && !strcmp(oc_string_array_get_item(recv_obj->rts, 0), ""))
		return 1;

	while (rep)
	{
		if ((rep->type == OC_REP_STRING_ARRAY) && !strcmp(oc_string(rep->name), "rt"))
		{
			rt_len = oc_string_array_get_allocated_size(rep->value.array);
			for (i=0; i<rt_len; i++)
			{
				for (j=0; j<rts_len; j++)
				{
					if (!strcmp(oc_string_array_get_item(rep->value.array, i), oc_string_array_get_item(recv_obj->rts, j)))
						break;
				}
				if (j == rts_len)
				{
					break;
				}
			}
			if (i == rt_len)
				result = 1;

			break;
		}
		rep = rep->next;
	}

	return result;
}





oc_recvs_t * _find_recvs_by_device(size_t device_index)
{
	oc_recvs_t *recvs_instance = (oc_recvs_t *)oc_list_head(recvs_list);

	while (recvs_instance)
	{
		if (recvs_instance->resource->device == device_index)
		{
			break;
		}
		else
		{
			recvs_instance = recvs_instance->next;
		}
	}

	return recvs_instance;
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
	oc_new_string(&((*new_rep)->name), oc_string(org_rep->name), oc_string_len(org_rep->name));

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
		for (int i=0; i<(int)oc_string_array_get_allocated_size(org_rep->value.array); i++)
		{
			oc_string_array_add_item((*new_rep)->value.array, oc_string_array_get_item(org_rep->value.array, i));
		}
		break;
	case OC_REP_BOOL_ARRAY:
		oc_new_bool_array(&(*new_rep)->value.array, oc_bool_array_size(org_rep->value.array));
		memcpy((*new_rep)->value.array.ptr, org_rep->value.array.ptr, org_rep->value.array.size*sizeof(uint8_t));
		break;
	case OC_REP_DOUBLE_ARRAY:
		oc_new_double_array(&(*new_rep)->value.array, oc_double_array_size(org_rep->value.array));
		memcpy((*new_rep)->value.array.ptr, org_rep->value.array.ptr, org_rep->value.array.size*sizeof(double));
		break;
	case OC_REP_INT_ARRAY:
		oc_new_int_array(&(*new_rep)->value.array, oc_int_array_size(org_rep->value.array));
		memcpy((*new_rep)->value.array.ptr, org_rep->value.array.ptr, org_rep->value.array.size*sizeof(int64_t));
		break;
	case OC_REP_BYTE_STRING:
	case OC_REP_STRING:
		oc_new_string(&((*new_rep)->value.string), oc_string(org_rep->value.string), oc_string_len(org_rep->value.string));
		break;
	case OC_REP_OBJECT:
		(*new_rep)->value.object = _create_pushd_rsc_rep(&((*new_rep)->value.object), org_rep->value.object);
		break;
	case OC_REP_OBJECT_ARRAY:
		/*
		 * TODO4ME, test this!
		 */
		(*new_rep)->value.object_array = _create_pushd_rsc_rep(&((*new_rep)->value.object_array), org_rep->value.object_array);
		break;
	default:
		break;
	}

	return (*new_rep);
}




void oc_print_pushd_rsc(oc_rep_t *payload)
{
	static int depth = 0;
	char prefix_width = 3;
	char *prefix_str = "   ";
	char depth_prefix[1024];
	oc_rep_t *rep = payload;
	oc_rep_t *obj;
	int i;

	depth++;
	for (i=0; i<depth; i++)
	{
//		depth_prefix[i] = '\t';
		strcpy(depth_prefix+(i*prefix_width), prefix_str);
	}
//	depth_prefix[i] = '\0';
	depth_prefix[i*prefix_width] = '\0';

	if (!rep) {
		p_dbg("no data!\n");
		depth--;
		return;
	}

	if (depth == 1)
		PRINT("\n\n");

	while (rep != NULL)
	{
		switch (rep->type)
		{
		case OC_REP_BOOL:
			PRINT("%s%s: %d\n", depth_prefix, oc_string(rep->name), rep->value.boolean);
			break;

		case OC_REP_BOOL_ARRAY:
			PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name), depth_prefix);
			for (i = 0; i < (int) oc_bool_array_size(rep->value.array); i++)
			{
				PRINT("%s%s\"%d\"\n", depth_prefix, prefix_str, oc_bool_array(rep->value.array)[i]);
			}
			PRINT("%s]\n", depth_prefix);
			break;

		case OC_REP_INT:
			PRINT("%s%s: %lld\n", depth_prefix, oc_string(rep->name), rep->value.integer);
			break;

		case OC_REP_INT_ARRAY:
			PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name), depth_prefix);
			for (i = 0; i < (int) oc_int_array_size(rep->value.array); i++)
			{
				PRINT("%s%s\"%d\"\n", depth_prefix, prefix_str, oc_int_array(rep->value.array)[i]);
			}
			PRINT("%s]\n", depth_prefix);
			break;

		case OC_REP_DOUBLE:
			PRINT("%s%s: %f\n", depth_prefix, oc_string(rep->name), rep->value.double_p);
			break;

		case OC_REP_DOUBLE_ARRAY:
			PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name), depth_prefix);
			for (i = 0; i < (int) oc_double_array_size(rep->value.array); i++)
			{
				PRINT("%s%s\"%f\"\n", depth_prefix, prefix_str, oc_double_array(rep->value.array)[i]);
			}
			PRINT("%s]\n", depth_prefix);
			break;

		case OC_REP_STRING:
			PRINT("%s%s: \"%s\"\n", depth_prefix, oc_string(rep->name), oc_string(rep->value.string));
			break;

		case OC_REP_STRING_ARRAY:
			PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name), depth_prefix);
			for (i = 0; i < (int) oc_string_array_get_allocated_size(rep->value.array); i++)
			{
				PRINT("%s%s\"%s\"\n", depth_prefix, prefix_str, oc_string_array_get_item(rep->value.array, i));
			}
			PRINT("%s]\n", depth_prefix);
			break;

		case OC_REP_OBJECT:
			PRINT("%s%s: \n%s{ \n", depth_prefix, oc_string(rep->name), depth_prefix);
			oc_print_pushd_rsc(rep->value.object);
			PRINT("%s}\n", depth_prefix);
			break;

		case OC_REP_OBJECT_ARRAY:
		case OC_REP_NIL:
			PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name), depth_prefix);
			depth++;
			obj = rep->value.object_array;
			while (obj)
			{
				PRINT("%s%s{\n", depth_prefix, prefix_str);
				oc_print_pushd_rsc(obj->value.object);
				obj = obj->next;
				PRINT("%s%s}", depth_prefix, prefix_str);
				if (obj)
					PRINT(",\n");
				else
					PRINT("\n");
			}
			depth--;
			PRINT("%s]\n", depth_prefix);
			break;

#if 0
		{
			PRINT("\t\tkey: %s value: { \n", oc_string(rep->name));
			oc_rep_t *obj_rep = rep->value.object;
			while (obj_rep != NULL)
			{
				switch (obj_rep->type)
				{
				case OC_REP_BOOL:
					PRINT("\t\t\t %s : %d \n", oc_string(obj_rep->name), obj_rep->value.boolean);
					break;
				case OC_REP_INT:
					PRINT("\t\t\t %s : %lld \n", oc_string(obj_rep->name), obj_rep->value.integer);
					break;
				case OC_REP_STRING:
					PRINT("\t\t\t %s : %s \n", oc_string(obj_rep->name), oc_string(obj_rep->value.string));
					break;
				case OC_REP_STRING_ARRAY:
				{
					PRINT("\t\t\t %s [ \n", oc_string(obj_rep->name));
					int i;
					for (i = 0; i < (int) oc_string_array_get_allocated_size(obj_rep->value.array); i++)
					{
						PRINT("\t\t\t\t %s \n", oc_string_array_get_item(obj_rep->value.array, i));
					}
					PRINT("\t\t\t ]\n");
				}
				break;
				default:
					PRINT("\t\t\t %s : \n", oc_string(obj_rep->name));
					break;
				}
				obj_rep = obj_rep->next;
			}
			PRINT("\t\t }\n\n");
		}
#endif


#if 0
		case OC_REP_STRING_ARRAY:
		{
			PRINT("\t\t %s [ \n", oc_string(rep->name));
			int i;
			for (i = 0; i < (int) oc_string_array_get_allocated_size(rep->value.array); i++)
			{
				PRINT("\t\t\t %s \n", oc_string_array_get_item(rep->value.array, i));
			}
			PRINT("\t\t ]\n");
		}
		break;
#endif

		default:
			PRINT("%s%s: unknown type: %d ???\n", depth_prefix, oc_string(rep->name), rep->type);
			break;
		}
		rep = rep->next;
	}
	depth--;
}




oc_rep_t * _rep_list_remove(oc_rep_t **rep_list, oc_rep_t **item)
{
	oc_rep_t **l, *removed_item;

	for (l = (oc_rep_t**) rep_list; *l != NULL; l = &(*l)->next)
	{
		if (*l == *item)
		{
			*l = (*l)->next;

			removed_item = *item;
			*item = (*item)->next;
			removed_item->next = NULL;
			return removed_item;
		}
	}

	return NULL;
}




void post_pushd_rsc(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	(void)iface_mask;
	(void)user_data;

	int result = OC_STATUS_CHANGED;
	oc_rep_t *rep = request->request_payload;
	oc_rep_t *common_property;
	oc_pushd_rsc_rep_t *pushd_rsc_rep;
	oc_recvs_t *recvs_instance;
	oc_recv_t *recv_obj;

	recvs_instance = _find_recvs_by_device(request->resource->device);
	if (recvs_instance)
	{
//		recv_obj = _find_recv_obj_by_uri(recvs_instance, oc_string(request->resource->uri), oc_string_len(request->resource->uri));
		recv_obj = _find_recv_obj_by_uri2(recvs_instance, request->resource->uri);
		if (!recv_obj)
		{
			p_err("can't find receiver object for (%s)\n", oc_string(request->resource->uri));
			return;
		}
	}
	else
	{
		p_err("can't find push receiver properties for (%s) in device (%d), the target resource may not be a \"push receiver resource\"\n", oc_string(request->resource->uri), request->resource->device);
		return;
	}

	/* check if rt of pushed resource is part of configured rts */
	if (!_check_pushd_rsc_rt(recv_obj, rep))
	{
		p_err("pushed resource type(s) is not in \"rts\" of push recerver object\n");
		result = OC_STATUS_FORBIDDEN;
	}
	else
	{
		while (rep)
		{
			/*
			 * FIXME4ME<done> <2022/4/20> skip "rt" (array), "if" (array), "n" (optional), "id" (optional) common property in the payload ("oic.r.pushpayload")
			 * because "rt" and "if" are already processed here...
			 */
			switch (rep->type)
			{
			case OC_REP_STRING_ARRAY:
				if (!strcmp(oc_string(rep->name), "rt"))
				{
					/* update rt */
					oc_free_string_array(&request->resource->types);
					oc_new_string_array(&request->resource->types, oc_string_array_get_allocated_size(rep->value.array));
					for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
					{
						oc_string_array_add_item(request->resource->types, oc_string_array_get_item(rep->value.array, i));
					}

					/*
					 * remove rep from list..
					 * - remove rep from list and move pointer to the next rep...
					 * - removed rep is handed over as return value
					 */
					common_property = _rep_list_remove(&request->request_payload, &rep);
					oc_free_rep(common_property);
					continue;

				}
				else if (!strcmp(oc_string(rep->name), "if"))
				{
					/* update if */
					request->resource->interfaces = 0;
					for (int i=0; i<(int)oc_string_array_get_allocated_size(rep->value.array); i++)
					{
						request->resource->interfaces |=
								oc_ri_get_interface_mask(oc_string_array_get_item(rep->value.array, i),
																strlen(oc_string_array_get_item(rep->value.array, i)));
					}

					common_property = _rep_list_remove(&request->request_payload, &rep);
					oc_free_rep(common_property);
					continue;
				}
				break;
			case OC_REP_STRING:
				if (!strcmp(oc_string(rep->name), "n"))
				{
					/* update name */
					oc_free_string(&request->resource->name);
					oc_new_string(&request->resource->name, oc_string(rep->value.string), oc_string_len(rep->value.string));

					common_property = _rep_list_remove(&request->request_payload, &rep);
					oc_free_rep(common_property);
					continue;
				}
				break;
#if 0
			case OC_REP_OBJECT:
				if (!strcmp(oc_string(rep->name), "rep"))
				{
					pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(&request->resource->uri, request->resource->device);
					if (pushd_rsc_rep)
					{
						oc_rep_set_pool(&rep_instance_memb);
						oc_free_rep(pushd_rsc_rep->rep);
						if (!_create_pushd_rsc_rep(&pushd_rsc_rep->rep, rep->value.object))
						{
							p_err("something wrong!, creating corresponding pushed resource representation faild (%s) ! \n",
									oc_string(request->resource->uri));
							result = OC_STATUS_INTERNAL_SERVER_ERROR;
						}
					}
					else
					{
						p_err("something wrong!, can't find corresponding pushed resource representation instance for (%s) \n",
								oc_string(request->resource->uri));
						result = OC_STATUS_NOT_FOUND;
					}
				}
				break;
#endif
			default:
				break;
			}
			rep = rep->next;
		}

		/* reset rep pointer */
//		rep = request->request_payload;

		/*
		 *
		 * store received "oic.r.pushpayload" resource contents
		 *
		 */
		pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(&request->resource->uri, request->resource->device);
		if (pushd_rsc_rep)
		{
			oc_rep_set_pool(&rep_instance_memb);
			oc_free_rep(pushd_rsc_rep->rep);


			if (!_create_pushd_rsc_rep(&pushd_rsc_rep->rep, request->request_payload))
			{
				p_err("something wrong!, creating corresponding pushed resource representation faild (%s) ! \n",
						oc_string(request->resource->uri));
				result = OC_STATUS_INTERNAL_SERVER_ERROR;
			}
			else
			{
#ifdef OC_PUSHDEBUG
//				PRINT("\npushed target resource: %s\n", oc_string(pushd_rsc_rep->resource->uri));
//				oc_print_pushd_rsc(pushd_rsc_rep->rep);
#endif

				if (oc_push_arrived)
					/*
					 * TODO4ME<done> <2022/4/20>, protect this call with thread lock...
					 * don't need this.. because 네트워크 이벤트가 발생했을때 그 처리를 보호하는 mutex가 network layer에서 동작하고 있음
					 */
					oc_push_arrived(pushd_rsc_rep);
			}
		}
		else
		{
			p_err("something wrong!, can't find corresponding pushed resource representation instance for (%s) \n",
					oc_string(request->resource->uri));
			result = OC_STATUS_NOT_FOUND;
		}
	}


	oc_send_response(request, result);
	return;
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
	(void)user_data;

	int result = OC_STATUS_OK;

	oc_rep_begin_root_object();
	switch (iface_mask)
	{
	case OC_IF_BASELINE:
		oc_process_baseline_interface(request->resource);
		/* fall through */
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

				oc_recv_t *recv_obj = (oc_recv_t *)oc_list_head(recvs_instance->receivers);
				while (recv_obj)
				{
					/* == open new receiver object == */
					oc_rep_object_array_begin_item(receivers);
					/* receiver:receiveruri */
					oc_rep_set_text_string(receivers, receiveruri, oc_string(recv_obj->receiveruri));

					/* receiver:rts[] */
					oc_rep_open_array(receivers, rts);
					for (int j=0; j < (int)oc_string_array_get_allocated_size(recv_obj->rts); j++)
					{
						oc_rep_add_text_string(rts, oc_string_array_get_item(recv_obj->rts, j));
					}
					oc_rep_close_array(receivers, rts);

					/* == close object == */
					oc_rep_object_array_end_item(receivers);

					recv_obj = recv_obj->next;
				}

				break;
			}

			recvs_instance = recvs_instance->next;
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
 * @brief					purge app resource and resource representation container
 * 							accessed through `uri` in device whose index is `device_index`
 *
 * @param uri				URI to app resource to be purged
 * @param device_index	index of device where the target resource resides
 */
void _purge_pushd_rsc(oc_string_t *uri, size_t device_index)
{
	oc_resource_t *pushd_rsc = oc_ri_get_app_resource_by_uri(oc_string(*uri), oc_string_len(*uri), device_index);
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
		p_err("can't find resource representation for pushed resource (%s)...\n", oc_string(*uri));
		return;
	}

	if (pushd_rsc)
	{
		/* step 3. remove pushed Resource from `app_resources` */
		p_dbg("purge pushed resource (%s)...\n", oc_string(*uri));
		oc_delete_resource(pushd_rsc);
	}
	else
	{
		p_err("can't find pushed resource (%s)...\n", oc_string(*uri));
		return;
	}

	return;
}







/**
 * @brief				update app resource correspon
 *
 * @param resource
 * @param rep
 */
//void _update_pushd_rsc(oc_resource_t *resource, oc_rep_t *rep)
//{
//
//
//	while (rep)
//	{
//		switch (rep->type)
//		{
//
//		}
//	}
//
//}




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

	if (pushd_rsc)
	{
		/*
		 * XXX, if a resource binds empty resource type (""), when a client retrieve this it may receive weird value...
		 */
		oc_resource_bind_resource_type(pushd_rsc, " ");
		oc_resource_bind_resource_interface(pushd_rsc, OC_IF_RW | OC_IF_BASELINE);
		oc_resource_set_default_interface(pushd_rsc, OC_IF_RW);
		oc_resource_set_discoverable(pushd_rsc, true);

		oc_resource_set_request_handler(pushd_rsc, OC_GET, get_pushd_rsc, NULL);
		oc_resource_set_request_handler(pushd_rsc, OC_POST, post_pushd_rsc, NULL);
		/*
		 * when this pushed resource is deleted.. delete corresponding "receiver" object from receivers array of push receiver resource
		 * => this is done in delete_pushrecv() (delete handler of pushreceiver resource)
		 */

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
	else
	{
		p_err("oc_new_resource() error!\n");
	}
}




/**
 * @brief						remove receiver object array in `recv_obj_list`,
 * 								and app resource pointed by `receiveruri` of each receivre object in the array
 *
 * @param recv_obj_list		receiver object array
 * @param device_index		index of device where the Push Resource resides
 */
void _purge_recv_obj_list(oc_recvs_t *recvs_instance)
{
	/*
	 * TODO4ME rewrite this func (refer to oc_free_rep())
	 */
//	oc_recv_t *recv_obj = (oc_recv_t *)oc_list_pop(recv_obj_list);
	oc_recv_t *recv_obj = (oc_recv_t *)oc_list_pop(recvs_instance->receivers);

	while (recv_obj)
	{
		p_dbg("purge receiver obj for ( %s (device: %d) )... \n", oc_string(recv_obj->receiveruri), recvs_instance->resource->device);

		/* delete app resource pointed by `receiveruri` first.. */
//		_purge_pushd_rsc(recv_obj->receiveruri, device_index);
		_purge_pushd_rsc(&recv_obj->receiveruri, recvs_instance->resource->device);

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
void _update_recv_obj(oc_recv_t *recv_obj, oc_recvs_t *recvs_instance, oc_rep_t *rep)
{
	oc_pushd_rsc_rep_t *pushd_rsc_rep;

	while (rep)
	{
		switch (rep->type)
		{
		case OC_REP_STRING:
			if (!strcmp(oc_string(rep->name), "receiveruri"))
			{
				p_dbg("target receiveruri: \"%s\", new receiveruri: \"%s\"\n", oc_string(recv_obj->receiveruri), oc_string(rep->value.string));
				/* if `receiveruri' is different from existing `receiveruri`,
				 * update URI of Resource pointed by previous `receiveruri` */
				if (strcmp(oc_string(recv_obj->receiveruri), oc_string(rep->value.string)))
				{
					pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(&recv_obj->receiveruri, recvs_instance->resource->device);

					if (pushd_rsc_rep)
					{
						p_dbg("pushed resource representation (\"%s\") is found\n", oc_string(pushd_rsc_rep->resource->uri));

						oc_free_string(&pushd_rsc_rep->resource->uri);
						oc_store_uri(oc_string(rep->value.string), &pushd_rsc_rep->resource->uri);
					}

#if 0
					oc_free_string(&recvs_instance->resource->uri);
					oc_store_uri(oc_string(rep->value.string), &recvs_instance->resource->uri);
#endif
				}

				oc_free_string(&recv_obj->receiveruri);
				oc_new_string(&recv_obj->receiveruri, oc_string(rep->value.string), oc_string_len(rep->value.string));
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
				oc_new_string(&recv_obj->receiveruri, oc_string(rep->value.string), oc_string_len(rep->value.string));
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
			break;
		}
		rep = rep->next;
	}

	oc_list_add(recvs_instance->receivers, recv_obj);

	/* create app resource corresponding to receiver object */
//	_create_pushd_rsc(recv_obj, recv_obj_list);
	p_dbg("new app resource for new receiver obj (\"%s\") is created...\n", oc_string(recv_obj->receiveruri));
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
//	oc_rep_t *rep_obj_value;
//	oc_recv_t *recv_obj_instance;

	/* remove existing receivers object array */
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
			break;
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
	(void)iface_mask;
	(void)user_data;

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
		if (uri_param_len != -1)
			p_dbg("received query string: \"%.*s\", found \"receiveruri\": \"%.*s\" \n", request->query_len, request->query, uri_param_len, uri_param);
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
			p_dbg("receivers obj array instance \"%s\"@Device(%d) is found!\n", oc_string(request->resource->uri), request->resource->device);

			if (uri_param_len != -1)
			{
//				recv_obj = _find_recv_obj_by_uri(recvs_instance->receivers, uri_param, uri_param_len);
				recv_obj = _find_recv_obj_by_uri(recvs_instance, uri_param, uri_param_len);
				if (recv_obj)
				{

					/* if the given `receiveruri` parameter is in existing receivers array,
					 * just update existing receiver object */
					p_dbg("existing receiver obj (\"%.*s\") is found, update it...\n", uri_param_len, uri_param);
//					_update_recv_obj(recv_obj, recvs_instance->resource, rep);
					_update_recv_obj(recv_obj, recvs_instance, rep);
				}
				else
				{
					/* if the given `receiveruri` parameter is not in existing receivers array,
					 * add new receiver object to the receivers array */
					p_dbg("can't find receiver obj which has uri \"%.*s\", creating new receiver obj...", uri_param_len, uri_param);

					/*
					 * if there is already NORMAL resource whose path is same as requested target uri,
					 * just ignore this request and return error!
					 */
					if (oc_ri_get_app_resource_by_uri(uri_param, uri_param_len, recvs_instance->resource->device))
					{
						p_dbg("can't create receiver obj whose receiveruri is same as existing app resource (\"%.*s\")...", uri_param_len, uri_param);
						result = OC_STATUS_FORBIDDEN;
						goto exit;
					}

					/* create corresponding receiver object */
//					_create_recv_obj(recvs_instance->receivers, rep);
					_create_recv_obj(recvs_instance, rep);
				}
			}
			else
			{
				/* if `receiveruri` param is not provided..
				 * replace whole existing `receivers` object array with new one.. */
//				_replace_recv_obj_array(recvs_instance->receivers, recvs_instance->resource, rep);
				p_dbg("replace existing receiver obj array with new ones...");
				_replace_recv_obj_array(recvs_instance, rep);
			}

			break;
		}

		recvs_instance = recvs_instance->next;
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

exit:
	oc_send_response(request, result);

	return;
}




/**
 * @brief DELETE callback for Push Receiver Resource
 *
 * @param request
 * @param iface_mask
 * @param user_data
 */
void delete_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
	(void)iface_mask;
	(void)user_data;

	char *uri_param;
	int uri_param_len = -1;
	oc_recv_t *recv_obj;
	oc_recvs_t *recvs_instance;
	int result = OC_STATUS_DELETED;

	/* try to get "receiveruri" parameter */
	if (request->query)
	{
		uri_param_len = oc_ri_get_query_value(request->query, request->query_len, "receiveruri", &uri_param);
		if (uri_param_len != -1)
			p_dbg("received query string: \"%.*s\", found \"receiveruri\": \"%.*s\" \n", request->query_len, request->query, uri_param_len, uri_param);
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
			p_dbg("receivers obj array instance of push receiver resource (\"%s\") is found!\n", oc_string(request->resource->uri));

			if (uri_param_len != -1)
			{
				recv_obj = _find_recv_obj_by_uri(recvs_instance, uri_param, uri_param_len);
				if (recv_obj)
				{
					/* remove receiver obj from array */
					oc_list_remove(recvs_instance->receivers, recv_obj);
					p_dbg("receiver obj is removed from array\n");

					/* delete associated resource... */
					_purge_pushd_rsc(&recv_obj->receiveruri, recvs_instance->resource->device);
					p_dbg("app resource corresponding to the receiver obj is removed\n");

					/* free memory */
					oc_free_string(&recv_obj->receiveruri);
					oc_free_string_array(&recv_obj->rts);
					oc_memb_free(&recv_instance_memb, recv_obj);
				}
				else
				{
					/* if the given `receiveruri` parameter is not in existing receivers array,
					 * add new receiver object to the receivers array */
#ifdef OC_PUSHDEBUG
//					oc_string_t uri;
//					oc_new_string(&uri, uri_param, uri_param_len);
					p_dbg("can't find receiver object which has uri(\"%.*s\"), ignore it...", uri_param_len, uri_param);
//					oc_free_string(&uri);
#endif
					result = OC_STATUS_NOT_FOUND;
				}
			}
			else
			{
				/* if `receiveruri` param is not provided..
				 * remove whole existing `receivers` object array */
				_purge_recv_obj_list(recvs_instance);
			}

			break;
		}

		recvs_instance = recvs_instance->next;
	}

	oc_send_response(request, result);

	return;
}







/**
 *
 * @brief	initiate Push Receiver Resource
 *
 * @param device_index
 */
void oc_create_pushreceiver_resource(size_t device_index)
{
	/* create Push Receiver Resource */
	oc_resource_t *push_recv = oc_new_resource("Push Receiver", PUSHRECVS_RSC_PATH, 1, device_index);

	if (push_recv)
	{
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
			OC_LIST_STRUCT_INIT(recvs_instance, receivers);
			oc_list_add(recvs_list, recvs_instance);
		}
		else
		{
			p_err("oc_memb_alloc() error!\n");
		}
	}
	else
	{
		p_err("oc_new_resource() error!\n");
	}

}


void oc_push_list_init()
{
	oc_list_init(ns_list);
	oc_list_init(recvs_list);
	oc_list_init(pushd_rsc_rep_list);
}


/*
 * clean up push related data structure
 * - for push configuration Resource: they are cleaned when all app Resources are removed (see oc_main_shutdown())
 * - for push receivers Resource: free in this function
 */
void oc_push_free()
{
	oc_recvs_t *recvs_instance;

	p_dbg("begin to free push receiver list!!!\n");

	for (recvs_instance = (oc_recvs_t *)oc_list_head(recvs_list); recvs_instance; recvs_instance = recvs_instance->next)
	{
		_purge_recv_obj_list(recvs_instance);
	}
}


void response_to_push_rsc(oc_client_response_t *data)
{
	oc_ns_t *ns_instance = (oc_ns_t *)data->user_data;

	p_dbg("\n   => return status code: [ %s ] \n\n", cli_statusstr(data->code));

	if (data->code == OC_STATUS_SERVICE_UNAVAILABLE)
	{
		/*
		 * TODO4ME <2022/4/17> if update request fails... retry to resolve endpoint of target device ID...
		 */
		p_dbg("state of Push Proxy (\"%s\") is changed (%s => %s)\n", oc_string(ns_instance->resource->uri),
				oc_string(ns_instance->state), pp_statestr(OC_PP_TOUT));
//				pp_statestr(ns_instance->state), pp_statestr(OC_PP_TOUT));
			pp_update_state(ns_instance->state, pp_statestr(OC_PP_TOUT));
//			ns_instance->state = OC_PP_TOUT;
	}
	else if (data->code == OC_STATUS_CHANGED)
	{
		p_dbg("state of Push Proxy (\"%s\") is changed (%s => %s)\n", oc_string(ns_instance->resource->uri),
				oc_string(ns_instance->state), pp_statestr(OC_PP_WFU));
		pp_update_state(ns_instance->state, pp_statestr(OC_PP_WFU));
	}
	else
	{
		/*
		 * FIXME4ME<done> <2022/4/17> check condition to enter ERR
		 */
		p_dbg("state of Push Proxy (\"%s\") is changed (%s => %s)\n", oc_string(ns_instance->resource->uri),
				oc_string(ns_instance->state), pp_statestr(OC_PP_ERR));
			pp_update_state(ns_instance->state, pp_statestr(OC_PP_ERR));
	}



#if 0
	p_dbg("\n UPDATE pushed receiver \n");
	if (data->code == OC_STATUS_CHANGED)
		p_dbg("POST response OK\n");
	else
		p_err("POST response code %d\n", data->code);
#endif
}



/*
 * XXX alternative implementation (not using proto-thread)
 */
void push_update(oc_ns_t *ns_instance)
{
	oc_resource_t *src_rsc;
	char di[OC_UUID_LEN];

	src_rsc = (oc_resource_t *)ns_instance->user_data;

	if (!ns_instance || !src_rsc) {
		p_err("something wrong! corresponding notification selector source resource is NULL, or updated resource is NULL!\n");
		return;
	}

	if (!src_rsc->payload_builder)
	{
		p_err("payload_builder() of source resource is NULL!\n");
		return;
	}

	/*
	 * client에서 POST 하는 루틴 참조할 것 (client_multithread_linux.c 참고)
	 */
	/*
	 * 1. find `notification selector` which monitors `src_rsc` from `ns_col_list`
	 * 2. post UPDATE by using URI, endpoint (use oc_sting_to_endpoint())
	 */
	if (oc_init_post(oc_string(ns_instance->targetpath), &ns_instance->pushtarget_ep,
							"if=oic.if.rw", &response_to_push_rsc, HIGH_QOS, ns_instance))
	{
		/*
		 * add other properties than "rep" object of "oic.r.pushpayload" Resource here.
		 * payload_builder() only "rep" object.
		 *
		 * payload_builder() doesn't need to have "oc_rep_start_root_object()" and "oc_rep_end_root_object()"
		 * they should be added here...
		 */
		oc_rep_begin_root_object();

		/* anchor */
		oc_uuid_to_str(oc_core_get_device_id(ns_instance->resource->device), di, OC_UUID_LEN);
		oc_rep_set_text_string(root, anchor, di);

		/* href (option) */
		if (oc_string(ns_instance->phref) && strcmp(oc_string(ns_instance->phref), ""))
		{
			oc_rep_set_text_string(root, href, oc_string(ns_instance->phref));
		}

		/* rt (array) */
		oc_rep_open_array(root, rt);
		for (size_t i=0; i<oc_string_array_get_allocated_size(src_rsc->types); i++)
		{
			oc_rep_add_text_string(rt, oc_string_array_get_item(src_rsc->types, i));
		}
		oc_rep_close_array(root, rt);

		/* if (array) */
		oc_core_encode_interfaces_mask(oc_rep_object(root), src_rsc->interfaces);

		/* build rep object */
		src_rsc->payload_builder();

		oc_rep_end_root_object();

		if (oc_do_post())
		{

#if OC_PUSHDEBUG
			oc_string_t ep, full_uri;

			oc_endpoint_to_string(&ns_instance->pushtarget_ep, &ep);
			if (oc_string_len(ns_instance->targetpath))
				oc_concat_strings(&full_uri, oc_string(ep), oc_string(ns_instance->targetpath));
			else
				oc_new_string(&full_uri, oc_string(ep), oc_string_len(ep));

			p_dbg("push \"%s\" ====> \"%s\"\n", oc_string(src_rsc->uri), oc_string(full_uri));
			oc_free_string(&ep);
			oc_free_string(&full_uri);
#endif
			p_dbg("state of Push Proxy (\"%s\") is changed (%s => %s)\n", oc_string(ns_instance->resource->uri),
					oc_string(ns_instance->state), pp_statestr(OC_PP_WFR));
//					pp_statestr(ns_instance->state), pp_statestr(OC_PP_WFR));
			pp_update_state(ns_instance->state, pp_statestr(OC_PP_WFR));
//			ns_instance->state = OC_PP_WFR;
		}
		else
		{
			p_err("Could not send POST\n");
		}
	}
	else
	{
		p_err("Could not init POST\n\n");
	}

}





OC_PROCESS_THREAD(oc_push_process, ev, data)
{
	oc_resource_t *src_rsc;
	oc_ns_t *ns_instance;
	char di[OC_UUID_LEN];

	OC_PROCESS_BEGIN();

	while (1) {

#if 0
		int device_count = oc_core_get_num_devices();
		/* create Push Notification Resource per each Device */
		for (int i=0; i<device_count; i++) {
			init_pushconf_resource(i);
			init_pushreceiver_resource(i);
		}
#endif

		OC_PROCESS_YIELD();

		/* send UPDATE to target server */
		if (ev == oc_events[PUSH_RSC_STATE_CHANGED]) {
			ns_instance = (oc_ns_t *)data;
			src_rsc = (oc_resource_t *)ns_instance->user_data;

			if (!ns_instance || !src_rsc /*|| !ns_instance->user_data*/) {
				p_err("something wrong! corresponding notification selector source resource is NULL, or updated resource is NULL!\n");
				break;
			}

			/*
			 * client에서 POST 하는 루틴 참조할 것 (client_multithread_linux.c 참고)
			 */
			/*
			 * 1. find `notification selector` which monitors `src_rsc` from `ns_col_list`
			 * 2. post UPDATE by using URI, endpoint (use oc_sting_to_endpoint())
			 */
			if (oc_init_post(oc_string(ns_instance->targetpath), &ns_instance->pushtarget_ep,
									"if=oic.if.rw", &response_to_push_rsc, LOW_QOS, NULL))
			{
				/*
				 * add other properties than "rep" object of "oic.r.pushpayload" Resource here.
				 * payload_builder() only adds "rep" object.
				 *
				 * payload_builder() doesn't need to have "oc_rep_start_root_object()" and "oc_rep_end_root_object()"
				 * they should be added here...
				 */
//				oc_resource_t *org_rsc;

				oc_rep_begin_root_object();

				/* anchor */
				oc_uuid_to_str(oc_core_get_device_id(ns_instance->resource->device), di, OC_UUID_LEN);
				oc_rep_set_text_string(root, anchor, di);

				/* href (option) */
				if (oc_string(ns_instance->phref) && strcmp(oc_string(ns_instance->phref), ""))
				{
					oc_rep_set_text_string(root, href, oc_string(ns_instance->phref));
				}

				/* rt (array) */
				oc_rep_open_array(root, rt);
				for (size_t i=0; i<oc_string_array_get_allocated_size(src_rsc->types); i++)
				{
					oc_rep_add_text_string(rt, oc_string_array_get_item(src_rsc->types, i));
				}
				oc_rep_close_array(root, rt);

				/* if (array) */
				oc_core_encode_interfaces_mask(oc_rep_object(root), src_rsc->interfaces);

//				oc_rep_open_object(root, rep);
				src_rsc->payload_builder();
//				oc_rep_close_object(root, rep);

				oc_rep_end_root_object();

				if (oc_do_post())
					p_dbg("Sent POST request\n\n");
				else
					p_err("Could not send POST\n\n");
			}
			else
			{
				p_err("Could not init POST\n\n");
			}


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

	}

	OC_PROCESS_END();
}




/**
 * @brief			check if any of source array is part of target array
 * @param target
 * @param source
 * @return
 * 			0: any of source is not part of target
 * 			1: any of source is part of target
 */
char _check_string_array_inclusion(oc_string_array_t *target, oc_string_array_t *source)
{
	int i, j;
	int src_len, tgt_len;
	int result = 0;

	tgt_len = oc_string_array_get_allocated_size(*target);
	src_len = oc_string_array_get_allocated_size(*source);

	if (!tgt_len || !src_len)
	{
		p_dbg("source or target string array is empty!\n");
		return result;
	}

	for (i=0; i<src_len; i++)
	{
		for (j=0; j<tgt_len; j++)
		{
			if (!strcmp(oc_string_array_get_item(*source, i), oc_string_array_get_item(*target, j)))
			{
				result = 1;
				break;
			}
		}
		if (result)
			break;
//		if (j == tgt_len)
//			break;
	}
//	if (i == src_len)
//		result = 1;

	return result;
}



/**
 *
 * @brief re-schedule push process
 *
 */
void oc_resource_state_changed(const char *uri, size_t device_index)
{
	oc_resource_t *resource = oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index);
	oc_ns_t *ns_instance = (oc_ns_t *)oc_list_head(ns_list);
	char all_matched = 1;

	p_dbg("resource \"%s\"@device(%d) is updated!\n", uri, device_index);

	if (!resource)
	{
		p_err("there is no resource for \"%s\"@device(%d)\n", uri, device_index);
		return;
	}
	if (!(resource->properties & OC_PUSHABLE))
	{
		p_err("resource \"%s\"@device (%d) is not pushable!\n", uri, device_index);
		return;
	}

	for ( ; ns_instance; ns_instance = ns_instance->next)
	{
		if (ns_instance->resource->device != device_index)
			continue;

		/* if push proxy is not in "wait for update" state, just skip it... */
		if (strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_WFU)))
			continue;

		if (oc_string(ns_instance->phref))
		{
			if (strcmp(oc_string(ns_instance->phref), "") && strcmp(oc_string(ns_instance->phref), uri))
				all_matched = 0;
		}
		if (oc_string_array_get_allocated_size(ns_instance->prt)>0)
		{
			if (!_check_string_array_inclusion(&ns_instance->prt, &resource->types))
				all_matched = 0;
		}
		if (oc_string_array_get_allocated_size(ns_instance->pif)>0)
		{
			oc_interface_mask_t pif = 0;
			for (int i=0; i<(int)oc_string_array_get_allocated_size(ns_instance->pif); i++)
			{
				pif |= _get_ifmask_from_ifstr(oc_string_array_get_item(ns_instance->pif, i));
			}

			if (!(pif & resource->interfaces))
//			if ((pif & resource->interfaces) != resource->interfaces)
//				all_matched = (all_matched)? 1:0;
//			else
				all_matched = 0;
		}

		if (all_matched)
		{
			if (!oc_process_is_running(&oc_push_process)) {
				p_dbg("oc_push_process is not running!\n");
				return;
			}

			p_dbg("resource \"%s\" matches notification selector \"%s\"!\n", oc_string(resource->uri), oc_string(ns_instance->resource->uri));

			/* resource is necessary to identify which resource is being pushed..,
			 * before sending update to target server */
			ns_instance->user_data = resource;

			/* post "event" for Resource which has just been updated */
			push_update(ns_instance);
//			oc_process_post(&oc_push_process, oc_events[PUSH_RSC_STATE_CHANGED], ns_instance);

		}
		else
		{
			all_matched = 1;
		}

#if 0
		/* if phref is configured... */
		if (oc_string(ns_instance->phref))
		{
			if (!strcmp(oc_string(ns_instance->phref), uri))
			{
				/* if phref is matched, check prt... */
				if (oc_string_array_get_allocated_size(ns_instance->prt)>0)
				{
					if (_check_string_array_inclusion(&ns_instance->prt, &resource->types))
					{
						/* if phref, prt are matched, check pif... */
						if (oc_string_array_get_allocated_size(ns_instance->pif)>0)
						{
							all_matched = 1;
						}

					}
				}
				{
//					all_matched = 0;
					continue;
				}
				else
				{
					/* if phref, prt are matched, check pif... */
//					if (!_check_string_array_inclusion(&ns_instance->pif, &resource->in))
					{

					}
				}
			}
		}
		/* if prt is configure... */
		else if (oc_string_array_get_allocated_size(ns_instance->prt)>0)
		{

		}
		/* if pif is configured... */
		else if (oc_string_array_get_allocated_size(ns_instance->pif)>0)
		{
		}
#endif

	}

	/* if there is no notification selector matching this resource, no action happens... */
//	if (!ns_instance)
//	{
//		p_err("there is no notification selector for resource (%s) @device (%d)\n", uri, device_index);
//		return;
//	}


//	_oc_signal_event_loop();


#if 0
	if (!oc_process_is_running(&oc_push_process)) {
		p_dbg("oc_push_process is not running!\n");
		return;
	}

	/* Resource which is just updated */
	oc_process_post(&oc_push_process, oc_events[PUSH_RSC_STATE_CHANGED],
					oc_ri_get_app_resource_by_uri(uri, strlen(uri), device_index));
//	oc_process_poll(&oc_push_process);

	_oc_signal_event_loop();
#endif

	return;
}






#endif /* OC_PUSH && OC_SERVER && OC_CLIENT && OC_DYNAMIC_ALLOCATION && OC_COLLECTIONS_IF_CREATE */

/****************************************************************************
 *
 * Copyright 2021 ETRI All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

#include "util/oc_features.h"

#ifdef OC_HAS_FEATURE_PUSH

#include "oc_push.h"

#include "api/oc_helpers_internal.h"
#include "api/oc_rep_internal.h"
#include "api/oc_endpoint_internal.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_core_res_internal.h"
#include "oc_endpoint.h"
#include "oc_events_internal.h"
#include "oc_push_internal.h"
#include "oc_rep_internal.h"
#include "oc_ri.h"
#include "oc_signal_event_loop.h"
#include "port/oc_log_internal.h"
#include "util/oc_compiler.h"
#include "util/oc_list.h"
#include "util/oc_macros_internal.h"
#include "util/oc_mmem.h"
#include "util/oc_mmem_internal.h"
#include "util/oc_process.h"

#include <inttypes.h>

// TODO: add push component to logs and use standard logging functions
#if defined(OC_PUSHDEBUG) || defined(OC_DEBUG)
#define OC_PUSH_DBG(...) OC_LOG(OC_LOG_LEVEL_DEBUG, __VA_ARGS__)
#define OC_PUSH_WRN(...) OC_LOG(OC_LOG_LEVEL_WARNING, __VA_ARGS__)
#define OC_PUSH_ERR(...) OC_LOG(OC_LOG_LEVEL_ERROR, __VA_ARGS__)
#else
#define OC_PUSH_DBG(...)
#define OC_PUSH_WRN(...)
#define OC_PUSH_ERR(...)
#endif

#ifdef __ANDROID__
#include "android/oc_log_android.h"
#define OC_TAG "OC-JNI"
#define OC_PUSH_PRINT(...)                                                     \
  __android_log_print(ANDROID_LOG_INFO, OC_TAG, __VA_ARGS__)
#else /* !__ANDROID__ */
#define OC_PUSH_PRINT(...) printf(__VA_ARGS__)
#endif /* __ANDROID__ */

/**
 * @brief Push Proxy state
 */
typedef enum {
  OC_PP_WFP,  ///< Wait For Provisioning
  OC_PP_WFU,  ///< Wait For Update
  OC_PP_WFR,  ///< Wait For Response
  OC_PP_WFUM, ///< Wait For Update Mitigation
  OC_PP_WFRM, ///< Wait For Response Mitigation
  OC_PP_ERR,  ///< Error
  OC_PP_TOUT  ///< Timeout
} oc_pp_state_t;

/**
 * @brief structure for handling "rt": ["oic.r.notificationselector",
 * "oic.r.pushproxy"] Resource
 */
typedef struct oc_ns
{
  struct oc_ns *next;
  oc_resource_t
    *resource; ///< used to point ["oic.r.notificationselector",
               ///< "oic.r.pushproxy"] Resource managed by iotivity-lite
  /* notificaiton selector */
  oc_string_t phref;     ///< oic.r.notificationselector:phref (optional)
  oc_string_array_t prt; ///< oic.r.notificationselector:prt (optional)
  oc_string_array_t pif; ///< oic.r.notificationselector:pif (optional)
  /* push proxy */
  oc_string_t pushtarget_di; ///< device id of target (e.g.
                             ///< ocf://17087f8c-13e3-4849-4258-65af2a47df63)
  oc_endpoint_t
    pushtarget_ep; ///< endpoint of pushtarget (e.g. coaps://[fe80::b1d6]:1122)
  oc_string_t targetpath;     ///< path in pushtarget (e.g. /pushedLightSwitch)
  oc_string_t pushqif;        ///< oic.r.pushproxy:pushqif (deprecated)
  oc_string_array_t sourcert; ///< oic.r.pushproxy:sourcert
  oc_string_t state;          ///< oic.r.pushproxy:state
  void *user_data;            ///< used to point updated pushable Resource
} oc_ns_t;

/**
 * @brief structure for member of "oic.r.pushreceiver:receivers" object array
 */
typedef struct oc_recv
{
  struct oc_recv *next;
  oc_string_t receiveruri; ///< oic.r.pushreceiver:receivers:receiveruri
  oc_string_array_t rts;   ///< oic.r.pushreceiver:receivers:rts
} oc_recv_t;

/**
 * @brief structure for handling for Push Receiver Resource
 */
typedef struct oc_recvs
{
  struct oc_recvs *next;
  oc_resource_t *resource;   ///< used to point ["oic.r.pushreceiver"] Resource
                             ///< managed by iotivity-lite
  OC_LIST_STRUCT(receivers); ///< oic.r.pushreceiver:receivers object array
} oc_recvs_t;

/**
 * @brief	memory block for storing new collection member of Push Configuration
 * Resource
 */
OC_MEMB(g_ns_instance_memb, oc_ns_t, 1);

/**
 * @brief	`ns_col_list` keeps real data of all Notification Selector Resources
 * 			(it includes all Resources of all Devices)
 *
 * 			each list member is instance of `oc_ns_t`
 */
OC_LIST(g_ns_list);

/**
 * @brief	memory block definition for storing new Receiver object array of Push
 * Receiver Resource
 */
OC_MEMB(g_recvs_instance_memb, oc_recvs_t, 1);

/**
 * @brief	memory block definition for storing new Receiver object of Receiver
 * object array
 */
OC_MEMB(g_recv_instance_memb, oc_recv_t, 1);

/**
 * @brief	`g_recvs_list` keeps real data of all Receiver object in Push Receiver
 * Resource (it includes all Receiver objects of Resource of all Devices)
 *
 * 			each list member is instance of `oc_recvs_t`
 */
OC_LIST(g_recvs_list);

/**
 * @brief	memory block definition for storing properties representation of
 * pushed resource
 */
OC_MEMB(g_rep_instance_memb, oc_rep_t, 1);

/**
 * @brief	memory block definition for storing pushed resource representation
 * list
 */
OC_MEMB(g_pushd_rsc_rep_instance_memb, oc_pushd_resource_rep_t, 1);

/**
 * @brief	`pushed_rsc_list` keeps Resource representation of Pushed Resources
 */
OC_LIST(g_pushd_rsc_rep_list);

/**
 * @brief	process which handles push notification
 */
OC_PROCESS(oc_push_process, "Push Notification handler");

const char *pp_state_strs[] = {
  "waitingforprovisioning",       /*OC_PP_WFP*/
  "waitingforupdate",             /*OC_PP_WFU*/
  "waitingforresponse",           /*OC_PP_WFR*/
  "waitingforupdatemitigation",   /*OC_PP_WFUM*/
  "waitingforresponsemitigation", /*OC_PP_WFRM*/
  "error",                        /*OC_PP_ERR*/
  "timeout"                       /*OC_PP_TOUT*/
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
 * if this callback function is provided by user, it will called whenever new
 * push is arrived...
 */
static void (*oc_push_arrived)(oc_pushd_resource_rep_t *) = NULL;

#define pp_statestr(i) (pp_state_strs[(i)])

/**
 * @brief update Push Proxy state from state to new_state
 *
 * @param state		oc_string_t
 * @param new_state	char *
 */
#define pp_update_state(state, new_state)                                      \
  (oc_set_string(&(state), (new_state), strlen((new_state))))

#define OC_PUSH_PROP_PHREF "phref"
#define OC_PUSH_PROP_PUSHTARGET "pushtarget"
#define OC_PUSH_PROP_PUSHQIF "pushqif"
#define OC_PUSH_PROP_STATE "state"
#define OC_PUSH_PROP_PRT "prt"
#define OC_PUSH_PROP_PIF "pif"
#define OC_PUSH_PROP_SOURCERT "sourcert"
#define OC_PUSH_PROP_RECEIVEURI "receiveruri"
#define OC_PUSH_PROP_RTS "rts"

#define OC_PUSH_QUERY_RECEIVERURI "receiveruri"

void
oc_set_on_push_arrived(oc_on_push_arrived_t func)
{
  oc_push_arrived = func;
}

/**
 * @brief callback to be called to set existing (or just created by
 * `get_ns_instance()`) data structure for `notification selector`
 * with received Resource representation
 *
 * @param resource not used
 * @param rep Resource representation structure
 * @param data internal structure for storing `notification selector`
 * resource (oc_memb struct for ["oic.r.notificationselector",
 * "oic.r.pushproxy"] Resource)
 *
 * @return true:success, false:fail
 */
static bool
set_ns_properties(const oc_resource_t *resource, const oc_rep_t *rep,
                  void *data)
{
  (void)resource;
  bool pushtarget_is_updated = false;

  /*
   * `data` is set when new Notification Selector Resource is created
   * by calling `oc_resource_set_properties_cbs()` in `get_ns_instance()`
   */
  oc_ns_t *ns_instance = (oc_ns_t *)data;
  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_STRING:
      /*
       * oic.r.notificationselector:phref
       *  - optional
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_PHREF,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_PHREF))) {
        if (oc_string_is_cstr_equal(&rep->value.string, "", 0)) {
          oc_free_string(&ns_instance->phref);
        } else {
          oc_set_string(&ns_instance->phref, oc_string(rep->value.string),
                        oc_string_len(rep->value.string));
        }
        OC_PUSH_DBG("oic.r.pushproxy:phref (%s)", oc_string(rep->value.string));
        break;
      }
      /*
       * oic.r.pushproxy:pushtarget
       *  - mandatory
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_PUSHTARGET,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_PUSHTARGET))) {
        if (oc_string_is_cstr_equal(&rep->value.string, "", 0)) {
          /* NULL pushtarget ("") is still acceptable... */
          OC_PUSH_DBG("NULL \"pushtarget\" is received, still stay in "
                      "\"waitforprovisioning\" state...");

          /* clear endpoint */
          memset(&ns_instance->pushtarget_ep, 0,
                 sizeof(ns_instance->pushtarget_ep));

          /* clear target path */
          oc_set_string(&ns_instance->targetpath, "", 0);

        } else {
          /* if non-NULL pushtarget.. */
          oc_endpoint_t *new_ep = oc_new_endpoint();
          oc_string_t new_targetpath = OC_MMEM_NULL();

          OC_PUSH_DBG("oic.r.pushproxy:pushtarget (%s)",
                      oc_string(rep->value.string));

          if (oc_string_to_endpoint(&rep->value.string, new_ep,
                                    &new_targetpath) < 0) {
            OC_PUSH_ERR("oic.r.pushproxy:pushtarget (%s) parsing failed!",
                        oc_string(rep->value.string));

            oc_free_endpoint(new_ep);
            oc_free_string(&new_targetpath);

            return false;
          } else {
            oc_free_string(&ns_instance->targetpath);

            /* update with new values... */
            oc_endpoint_copy(&ns_instance->pushtarget_ep, new_ep);
            oc_new_string(&ns_instance->targetpath, oc_string(new_targetpath),
                          oc_string_len(new_targetpath));

            OC_PUSH_DBG("oic.r.pushproxy:pushtarget (%s)",
                        oc_string(rep->value.string));

            /* return memory */
            oc_free_endpoint(new_ep);
            oc_free_string(&new_targetpath);

            if (oc_string_len(ns_instance->targetpath)) {
              OC_PUSH_DBG("oic.r.pushproxy:pushtarget parsing is successful! "
                          "targetpath (\"%s\")",
                          oc_string(ns_instance->targetpath));
              pushtarget_is_updated = true;
            } else {
              OC_PUSH_ERR("path part of \"pushtarget\" should not be NULL!!");
              return false;
            }
          }
        }
        break;
      }
      /*
       * TODO4ME <2022/04/17> deprecated property, remove later...
       * oic.r.pushproxy:pushqif
       *  - optional
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_PUSHQIF,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_PUSHQIF))) {
        oc_set_string(&ns_instance->pushqif, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
        break;
      }
      /*
       * oic.r.pushproxy:state
       *  - RETRIEVE: mandatory
       *  - UPDATE: optional
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_STATE,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_STATE))) {
        /* state can be modified only if Push Proxy is in "tout" or "err" state
         */
        if (strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_ERR)) !=
              0 &&
            strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_TOUT)) !=
              0) {
          OC_PUSH_ERR("state can be modified only if Push Proxy is in \"tout\" "
                      "or \"err\" state");
          return false;
        }

        /* "waitingforupdate" is only acceptable value */
        if (strcmp(oc_string(rep->value.string), pp_statestr(OC_PP_WFU)) != 0) {
          OC_PUSH_ERR(
            "only \"waitingforupdate\" is allowed to reset \"state\"");
          return false;
        }

        OC_PUSH_DBG("state of Push Proxy (\"%s\") is reset (%s => %s)",
                    oc_string(ns_instance->resource->uri),
                    oc_string(ns_instance->state),
                    oc_string(rep->value.string));
        pp_update_state(ns_instance->state, oc_string(rep->value.string));
        break;
      }
      break;

    case OC_REP_STRING_ARRAY:
      /*
       * oic.r.notificationselector:prt
       *  - optional
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_PRT,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_PRT))) {
        oc_free_string_array(&ns_instance->prt);

        oc_new_string_array(
          &ns_instance->prt,
          oc_string_array_get_allocated_size(rep->value.array));

        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); i++) {
          OC_PUSH_DBG("oic.r.pushproxy:prt (%s)",
                      oc_string_array_get_item(rep->value.array, i));
          oc_string_array_add_item(
            ns_instance->prt, oc_string_array_get_item(rep->value.array, i));
        }
        break;
      }
      /*
       * oic.r.notificationselector:pif
       *  - optional
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_PIF,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_PIF))) {
        oc_free_string_array(&ns_instance->pif);

        oc_new_string_array(
          &ns_instance->pif,
          oc_string_array_get_allocated_size(rep->value.array));

        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); i++) {
          OC_PUSH_DBG("oic.r.pushproxy:pif (%s)",
                      oc_string_array_get_item(rep->value.array, i));
          oc_string_array_add_item(
            ns_instance->pif, oc_string_array_get_item(rep->value.array, i));
        }
        break;
      }
      /*
       * oic.r.pushproxy:sourcert
       *  - mandatory
       */
      if (oc_rep_is_property(rep, OC_PUSH_PROP_SOURCERT,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_SOURCERT))) {
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); i++) {
          if (strcmp(oc_string_array_get_item(rep->value.array, i),
                     "oic.r.pushpayload") != 0) {
            OC_PUSH_ERR("illegal oic.r.pushproxy:sourcert value (%s)!",
                        oc_string_array_get_item(rep->value.array, i));
            return false;
          }
        }

        oc_free_string_array(&ns_instance->sourcert);
        oc_new_string_array(
          &ns_instance->sourcert,
          oc_string_array_get_allocated_size(rep->value.array));
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(rep->value.array); i++) {
          OC_PUSH_DBG("oic.r.pushproxy:sourcert (%s)",
                      oc_string_array_get_item(rep->value.array, i));
          oc_string_array_add_item(
            ns_instance->sourcert,
            oc_string_array_get_item(rep->value.array, i));
        }
        break;
      }
      break;

    default:
      OC_PUSH_ERR("not supported Property (\"%s\")", oc_string(rep->name));
      break;
    }
    rep = rep->next;
  }

  /*
   * re-check condition which lets state move from "err"/"tout" to "wfu"
   * - only configurator can change "state" when it is in "err"/"tout" state
   */
  if (pushtarget_is_updated &&
      strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_ERR)) != 0 &&
      strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_TOUT)) != 0 &&
      strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_WFU)) != 0) {
    OC_PUSH_DBG("state of Push Proxy (\"%s\") is changed (%s => %s)",
                oc_string(ns_instance->resource->uri),
                oc_string(ns_instance->state), pp_statestr(OC_PP_WFU));
    pp_update_state(ns_instance->state, pp_statestr(OC_PP_WFU));
  } else {
    OC_PUSH_DBG("pushtarget of Push Proxy (\"%s\") is still NULL, or Push "
                "Proxy is already in (\"%s\")",
                oc_string(ns_instance->resource->uri),
                oc_string(ns_instance->state));
  }

  return true;
}

/**
 * @brief callback to be called to fill the contents of `notification
 * selector` from existing data structure (`oc_ns_t`)
 *
 * @param resource not used
 * @param iface_mask interface to be used to send response
 * @param data internal structure for storing `notification selector`
 * resource (oc_memb struct for ["oic.r.notificationselector",
 * "oic.r.pushproxy"] Resource)
 */
static void
get_ns_properties(const oc_resource_t *resource, oc_interface_mask_t iface_mask,
                  void *data)
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
    OC_FALLTHROUGH;
  case OC_IF_RW:
    /*
     * phref optional
     *  - optional
     */
    if (oc_string(ns_instance->phref)) {
      oc_rep_set_text_string(root, phref, oc_string(ns_instance->phref));
    }

    /*
     * prt
     *  - optional
     */
    if (oc_string_array_get_allocated_size(ns_instance->prt)) {
      oc_rep_open_array(root, prt);
      for (int i = 0;
           i < (int)oc_string_array_get_allocated_size(ns_instance->prt); i++) {
        oc_rep_add_text_string(prt,
                               oc_string_array_get_item(ns_instance->prt, i));
      }
      oc_rep_close_array(root, prt);
    }

    /*
     * pif
     *  - optional
     */
    if (oc_string_array_get_allocated_size(ns_instance->pif)) {
      oc_rep_open_array(root, pif);
      for (int i = 0;
           i < (int)oc_string_array_get_allocated_size(ns_instance->pif); i++) {
        oc_rep_add_text_string(pif,
                               oc_string_array_get_item(ns_instance->pif, i));
      }
      oc_rep_close_array(root, pif);
    }

    /*
     * pushtarget
     */
    oc_string64_t ep;
    oc_string_t full_uri;
    if (!oc_endpoint_to_string64(&ns_instance->pushtarget_ep, &ep)) {
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
      /* if pushtarget endpoint is NULL or illegal value.. just return NULL */
      oc_new_string(&full_uri, "", strlen(""));
    } else {
      if (oc_string_len(ns_instance->targetpath))
        oc_concat_strings(&full_uri, oc_string(ep),
                          oc_string(ns_instance->targetpath));
      else
        oc_new_string(&full_uri, oc_string(ep), oc_string_len(ep));
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
    if (oc_string_array_get_allocated_size(ns_instance->sourcert)) {
      oc_rep_open_array(root, sourcert);
      for (int i = 0;
           i < (int)oc_string_array_get_allocated_size(ns_instance->sourcert);
           i++) {
        oc_rep_add_text_string(
          sourcert, oc_string_array_get_item(ns_instance->sourcert, i));
      }
      oc_rep_close_array(root, sourcert);
    }

    /*
     * state
     */
    oc_rep_set_text_string(root, state, oc_string(ns_instance->state));

    break;
  default:
    break;
  }
  oc_rep_end_root_object();
}

/**
 * @brief callback function used to RETRIEVE `Notification Selector + Push Proxy
 * Resource which is autogenerated through `oic.if.crete` interface
 *
 * @param request request delivered from stack
 * @param iface_mask OCF interface delivered from stack
 * @param user_data oc_ns_t object
 */
static void
get_ns(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  get_ns_properties(request->resource, iface_mask, user_data);
  oc_send_response_with_callback(request, OC_STATUS_OK, true);
}

/**
 * @brief callback function used to UPDATE `Notification Selector + Push Proxy
 * Resource which is autogenerated through `oic.if.crete` interface
 *
 * @param request request delivered from stack
 * @param iface_mask OCF interface delivered from stack
 * @param user_data oc_ns_t object
 */
static void
post_ns(oc_request_t *request, oc_interface_mask_t iface_mask, void *user_data)
{
  (void)iface_mask;

  OC_PUSH_DBG("trying to update notification selector (\"%s\")... ",
              oc_string(request->resource->uri));

  if (set_ns_properties(request->resource, request->request_payload,
                        user_data)) {
    oc_send_response_with_callback(request, OC_STATUS_CHANGED, true);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
  }
}

/**
 * @brief callback function used to DELETE `Notification Selector + Push Proxy
 * Resource which is autogenerated through `oic.if.crete` interface
 *
 * @param request request delivered from stack
 * @param iface_mask OCF interface delivered from stack
 * @param user_data oc_ns_t object
 */
static void
delete_ns(oc_request_t *request, oc_interface_mask_t iface_mask,
          void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  OC_PUSH_DBG("trying to delete notification selector (\"%s\")... ",
              oc_string(request->resource->uri));

  if (oc_delete_resource(request->resource)) {
    oc_send_response_with_callback(request, OC_STATUS_DELETED, true);
  } else {
    oc_send_response_with_callback(request, OC_STATUS_BAD_REQUEST, true);
  }
}

/**
 * @brief callback callback for getting & creating new `Notification Selector
 * + Push Proxy` Resource instance
 *
 * @param href href delivered from stack
 * @param types Resource types delivered from stack
 * @param bm operation bitmask deliverd from stack
 * @param iface_mask OCF interface delivered froms stack
 * @param device device index
 * @return oc_resource_t for new `Notification Selector + Push Proxy`
 */
static oc_resource_t *
get_ns_instance(const char *href, const oc_string_array_t *types,
                oc_resource_properties_t bm, oc_interface_mask_t iface_mask,
                size_t device)
{
  oc_ns_t *ns_instance = (oc_ns_t *)oc_memb_alloc(&g_ns_instance_memb);
  if (ns_instance == NULL) {
    OC_PUSH_ERR("oc_memb_alloc() error!");
    return NULL;
  }

  ns_instance->resource = oc_new_resource(
    NULL, href, (uint8_t)oc_string_array_get_allocated_size(*types), device);
  if (ns_instance->resource == NULL) {
    OC_PUSH_ERR("oc_new_resource() error!");
    oc_memb_free(&g_ns_instance_memb, ns_instance);
    return NULL;
  }

  for (int i = 0; i < (int)oc_string_array_get_allocated_size(*types); i++) {
    const char *rt = oc_string_array_get_item(*types, i);
    oc_resource_bind_resource_type(ns_instance->resource, rt);
  }
  oc_resource_bind_resource_interface(ns_instance->resource, iface_mask);
  ns_instance->resource->properties = bm;
  oc_resource_set_default_interface(ns_instance->resource, OC_IF_RW);
  oc_resource_set_request_handler(ns_instance->resource, OC_GET, get_ns,
                                  ns_instance);
  oc_resource_set_request_handler(ns_instance->resource, OC_POST, post_ns,
                                  ns_instance);
  oc_resource_set_request_handler(ns_instance->resource, OC_DELETE, delete_ns,
                                  ns_instance);
  oc_resource_set_properties_cbs(ns_instance->resource, get_ns_properties,
                                 ns_instance, set_ns_properties, ns_instance);
  oc_add_resource(ns_instance->resource);

  OC_PUSH_DBG("new link (\"%s\") and corresponding resource for \"%s\" "
              "collection is created",
              oc_string(ns_instance->resource->uri), PUSHCONFIG_RESOURCE_PATH);

  /* initialize properties */
  ns_instance->phref = OC_MMEM_NULL();
  ns_instance->prt = OC_MMEM_NULL();
  ns_instance->pif = OC_MMEM_NULL();
  ns_instance->pushtarget_di = OC_MMEM_NULL();
  ns_instance->targetpath = OC_MMEM_NULL();
  ns_instance->sourcert = OC_MMEM_NULL();
  oc_new_string(&ns_instance->state, pp_statestr(OC_PP_WFP),
                strlen(pp_statestr(OC_PP_WFP)));
  ns_instance->user_data = NULL;

  OC_PUSH_DBG("state of Push Proxy (\"%s\") is initialized (%s)",
              oc_string(ns_instance->resource->uri), pp_statestr(OC_PP_WFP));

  /*
   * add this new Notification Selector Resource to the list
   * which keeps all Notification Selectors of all Devices
   */
  oc_list_add(g_ns_list, ns_instance);
  return ns_instance->resource;
}

/**
 * @brief callback for freeing existing notification selector
 * 		(this callback is called when target resource pointed by `link` is deleted
 * by calling `oc_delete_resource()`)
 *
 */
static void
free_ns_instance(oc_resource_t *resource)
{
  OC_PUSH_DBG("delete ns_instance for resource (\"%s\")...",
              oc_string(resource->uri));

  oc_ns_t *ns_instance = (oc_ns_t *)oc_list_head(g_ns_list);
  while (ns_instance) {
    if (ns_instance->resource == resource) {
      /* remove link target resource itself here... */
      oc_delete_resource(resource);

      /* remove oc_ns_t instance from list */
      oc_list_remove(g_ns_list, ns_instance);

      /* free each field of ns_instance */
      oc_free_string(&ns_instance->phref);
      oc_free_string_array(&ns_instance->prt);
      oc_free_string_array(&ns_instance->pif);

      oc_endpoint_t *ep = ns_instance->pushtarget_ep.next;
      oc_endpoint_t *next;
      while (ep) {
        next = ep->next;
        oc_free_endpoint(ep);
        ep = next;
      }

      oc_free_string(&ns_instance->targetpath);
      oc_free_string(&ns_instance->pushqif);
      oc_free_string_array(&ns_instance->sourcert);

      oc_free_string(&ns_instance->state);

      oc_memb_free(&g_ns_instance_memb, ns_instance);
      return;
    }
    ns_instance = ns_instance->next;
  }
}

/**
 * @brief initialize Push Configuration Resource
 *
 * @details
 * for Origin Server: \n
 * - Push Configuration ("oic.r.pushconfiguration") \n
 * - Notification Selector + Push Proxy ("oic.r.notificationselector" +
 * "oic.r.pushproxy") \n
 *
 * @param device_index	device index
 */
void
oc_create_pushconf_resource(size_t device_index)
{
  /* create Push Configuration Resource */
  oc_resource_t *push_conf = oc_new_collection(
    "Push Configuration", PUSHCONFIG_RESOURCE_PATH, 1, device_index);

  if (push_conf == NULL) {
    OC_PUSH_ERR("oc_new_collection() error!");
    return;
  }
  oc_resource_bind_resource_type(push_conf, "oic.r.pushconfiguration");
  oc_resource_bind_resource_interface(push_conf,
                                      OC_IF_LL | OC_IF_CREATE | OC_IF_BASELINE);
  oc_resource_set_default_interface(push_conf, OC_IF_LL);
  oc_resource_set_discoverable(push_conf, true);

  /* set "rts" Property */
  oc_collection_add_supported_rt(push_conf, "oic.r.notificationselector");
  oc_collection_add_supported_rt(push_conf, "oic.r.pushproxy");

  /* LINK creation, deletion handler */
  oc_collections_add_rt_factory("oic.r.notificationselector", get_ns_instance,
                                free_ns_instance);

  if (!oc_add_collection_v1(push_conf)) {
    OC_PUSH_ERR("oc_add_collection_v1() error!");
  }
}

/**
 * @brief build response payload of pushed Resource
 */
static void
_build_rep_payload(CborEncoder *parent, oc_rep_t *rep)
{
  CborEncoder child;
  oc_rep_t *obj;

  if (!rep)
    return;

  switch (rep->type) {
  case OC_REP_NIL:
    break;

  case OC_REP_INT:
    /* oc_rep_set_int(object, key, value) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    g_err |= oc_rep_encode_int(parent, rep->value.integer);

    break;

  case OC_REP_DOUBLE:
    /* oc_rep_set_double(object, key, value) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    g_err |= oc_rep_encode_double(parent, rep->value.double_p);

    break;

  case OC_REP_BOOL:
    /* oc_rep_set_boolean(object, key, value) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    g_err |= oc_rep_encode_boolean(parent, rep->value.boolean);

    break;

  case OC_REP_BYTE_STRING_ARRAY:
    /* oc_rep_open_array(root, xxxx) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

    /* oc_rep_add_byte_string(xxxx, str) */
    for (int i = 0;
         i < (int)oc_string_array_get_allocated_size(rep->value.array); i++) {
      g_err |= oc_rep_encode_byte_string(
        &child, (const uint8_t *)oc_string_array_get_item(rep->value.array, i),
        oc_string_array_get_item_size(rep->value.array, i));
    }

    /* oc_rep_close_array(root, xxxx) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  case OC_REP_STRING_ARRAY:
    /* oc_rep_open_array(root, xxxx) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

    /* oc_rep_add_text_string(xxxx, str) */
    for (int i = 0;
         i < (int)oc_string_array_get_allocated_size(rep->value.array); i++) {
      g_err |= oc_rep_encode_text_string(
        &child, oc_string_array_get_item(rep->value.array, i),
        oc_string_array_get_item_size(rep->value.array, i));
    }

    /* oc_rep_close_array(root, xxxx) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  case OC_REP_BOOL_ARRAY:
    /* oc_rep_open_array(root, xxxx) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

    /* oc_rep_add_boolean(xxxx, value) */
    for (int i = 0; i < (int)rep->value.array.size; i++) {
      g_err |=
        oc_rep_encode_boolean(&child, ((char *)(rep->value.array.ptr))[i]);
    }

    /* oc_rep_close_array(root, xxxx) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  case OC_REP_DOUBLE_ARRAY:
    /* oc_rep_open_array(root, xxxx) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

    /* oc_rep_add_double(xxxx, value) */
    for (int i = 0; i < (int)rep->value.array.size; i++) {
      g_err |=
        oc_rep_encode_double(&child, ((double *)(rep->value.array.ptr))[i]);
    }

    /* oc_rep_close_array(root, xxxx) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  case OC_REP_INT_ARRAY:
    /* oc_rep_open_array(root, xxxx) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

    /* oc_rep_add_int(xxxx, value) */
    for (int i = 0; i < (int)rep->value.array.size; i++) {
      g_err |=
        oc_rep_encode_int(&child, ((int64_t *)(rep->value.array.ptr))[i]);
    }

    /* oc_rep_close_array(root, xxxx) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  case OC_REP_BYTE_STRING:
    /* oc_rep_set_byte_string(object, key, value, length) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    g_err |= oc_rep_encode_byte_string(
      parent, (const uint8_t *)oc_string(rep->value.string),
      oc_string_len(rep->value.string));
    break;

  case OC_REP_STRING:
    /* oc_rep_set_text_string(object, key, value) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));

    if ((const char *)oc_string(rep->value.string) != NULL) {
      g_err |= oc_rep_encode_text_string(parent, oc_string(rep->value.string),
                                         oc_string_len(rep->value.string));
    } else {
      g_err |= oc_rep_encode_text_string(parent, "", 0);
    }
    break;

  case OC_REP_OBJECT:

    /* oc_rep_open_object(parent, key) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_map(parent, &child, CborIndefiniteLength);

    _build_rep_payload(&child, rep->value.object);

    /* oc_rep_close_object(parent, key) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  case OC_REP_OBJECT_ARRAY:

    /* oc_rep_open_array(root, xxxx) */
    g_err |= oc_rep_encode_text_string(parent, oc_string(rep->name),
                                       oc_string_len(rep->name));
    memset(&child, 0, sizeof(child));
    g_err |= oc_rep_encoder_create_array(parent, &child, CborIndefiniteLength);

    /* recurse remaining objects... */
    obj = rep->value.object_array;
    while (obj) {
      /* oc_rep_object_array_begin_item(key) */
      CborEncoder obj_map;
      memset(&obj_map, 0, sizeof(obj_map));
      g_err |=
        oc_rep_encoder_create_map(&child, &obj_map, CborIndefiniteLength);

      _build_rep_payload(&obj_map, obj->value.object);

      /* oc_rep_object_array_end_item(key) */
      g_err |= oc_rep_encoder_close_container(&child, &obj_map);
      obj = obj->next;
    }

    /* oc_rep_close_array(root, xxxx) */
    g_err |= oc_rep_encoder_close_container(parent, &child);
    break;

  default:
    break;
  }

  _build_rep_payload(parent, rep->next);
}

/**
 * @brief find Resource representation for pushed Resource
 *
 * @param uri uri for pushed Resource
 * @param device_index device index which pushed Resource belongs to
 * @return `oc_pushd_resource_rep_t` instance
 */
static oc_pushd_resource_rep_t *
_find_pushd_rsc_rep_by_uri(oc_string_t *uri, size_t device_index)
{
  oc_pushd_resource_rep_t *pushd_rsc_rep =
    (oc_pushd_resource_rep_t *)(oc_list_head(g_pushd_rsc_rep_list));

  while (pushd_rsc_rep) {
    if (strcmp(oc_string(pushd_rsc_rep->resource->uri), oc_string(*uri)) == 0 &&
        (pushd_rsc_rep->resource->device == device_index)) {
      break;
    } else {
      pushd_rsc_rep = pushd_rsc_rep->next;
    }
  }

  return pushd_rsc_rep;
}

/**
 * @brief callback for RETRIEVE of pushed Resource
 *
 * @param request request delivered from stack
 * @param iface_mask OCF interface delivered from stack
 * @param user_data not used
 */
static void
get_pushd_rsc(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *user_data)
{
  (void)user_data;

  int result = OC_STATUS_OK;
  oc_pushd_resource_rep_t *pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(
    &request->resource->uri, request->resource->device);

  if (!pushd_rsc_rep) {
    OC_PUSH_ERR("something wrong, can't find resource representation for "
                "pushed resource (%s)...",
                oc_string(request->resource->uri));
    return;
  }

  if (pushd_rsc_rep->rep) {
    oc_rep_begin_root_object();
    switch (iface_mask) {
    case OC_IF_BASELINE:
      oc_process_baseline_interface(request->resource);
      OC_FALLTHROUGH;
    case OC_IF_R:
    case OC_IF_RW:
      _build_rep_payload(&root_map, pushd_rsc_rep->rep);
      break;
    default:
      break;
    }
    oc_rep_end_root_object();

    oc_send_response_with_callback(request, result, true);
  } else {
    OC_PUSH_ERR("resource representation for pushed resource (%s) is found, "
                "but no resource representation for it is built yet!",
                oc_string(request->resource->uri));

    oc_send_response_with_callback(request, OC_STATUS_NOT_FOUND, true);
  }
}

/**
 * @brief check if "rt" of pushed resource is part of "rts" (all value of
 * "rt" should be part of "rts")
 *
 * @param recv_obj receiver object
 * @param rep payload representation of pushed Resource
 * @return	not 0: found, 0: not found
 */
static bool
_check_pushd_rsc_rt(oc_recv_t *recv_obj, oc_rep_t *rep)
{
  bool result = 0;
  size_t rt_len;
  size_t rts_len;
  size_t i;
  size_t j;

  if (!recv_obj || !rep)
    return result;

  rts_len = oc_string_array_get_allocated_size(recv_obj->rts);

  /* if "rts" is not configured (""), any pushed resource can be accepted... */
  if ((rts_len == 1) &&
      strcmp(oc_string_array_get_item(recv_obj->rts, 0), "") == 0)
    return 1;

  while (rep) {
    if ((rep->type == OC_REP_STRING_ARRAY) &&
        strcmp(oc_string(rep->name), "rt") == 0) {
      rt_len = oc_string_array_get_allocated_size(rep->value.array);
      for (i = 0; i < rt_len; i++) {
        for (j = 0; j < rts_len; j++) {
          if (strcmp(oc_string_array_get_item(rep->value.array, i),
                     oc_string_array_get_item(recv_obj->rts, j)) == 0)
            break;
        }
        if (j == rts_len) {
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

/**
 * @brief find Resource representation of Push Receiver Resource
 * which belongs to `device_index`
 *
 * @param device_index device index
 * @return `oc_recvs_t` instance
 */
static oc_recvs_t *
_find_recvs_by_device(size_t device_index)
{
  oc_recvs_t *recvs_instance = (oc_recvs_t *)oc_list_head(g_recvs_list);

  while (recvs_instance) {
    if (recvs_instance->resource->device == device_index) {
      break;
    } else {
      recvs_instance = recvs_instance->next;
    }
  }

  return recvs_instance;
}

/**
 * @brief build Resource representation for pushed Resource
 *
 * @details `oc_rep_set_pool()` should be called before calling this func
 *
 * @param org_rep Resource representation delivered from stack
 * @return duplication of `org_rep`
 */
static oc_rep_t *
_create_pushd_rsc_rep(oc_rep_t *org_rep)
{
  if (!org_rep)
    return org_rep;

  oc_rep_t *new_rep;

  new_rep = oc_alloc_rep();

  new_rep->next = _create_pushd_rsc_rep(org_rep->next);

  new_rep->type = org_rep->type;
  oc_new_string(&((new_rep)->name), oc_string(org_rep->name),
                oc_string_len(org_rep->name));

  switch (org_rep->type) {
  case OC_REP_NIL:
    break;
  case OC_REP_INT:
    new_rep->value.integer = org_rep->value.integer;
    break;
  case OC_REP_DOUBLE:
    new_rep->value.double_p = org_rep->value.double_p;
    break;
  case OC_REP_BOOL:
    new_rep->value.boolean = org_rep->value.boolean;
    break;
  case OC_REP_BYTE_STRING_ARRAY:
  case OC_REP_STRING_ARRAY:
    oc_new_string_array(
      &(new_rep->value.array),
      oc_string_array_get_allocated_size(org_rep->value.array));
    for (int i = 0;
         i < (int)oc_string_array_get_allocated_size(org_rep->value.array);
         i++) {
      oc_string_array_add_item(
        new_rep->value.array,
        oc_string_array_get_item(org_rep->value.array, i));
    }
    break;
  case OC_REP_BOOL_ARRAY:
    oc_new_bool_array(&(new_rep->value.array),
                      oc_bool_array_size(org_rep->value.array));
    memcpy(new_rep->value.array.ptr, org_rep->value.array.ptr,
           org_rep->value.array.size * sizeof(uint8_t));
    break;
  case OC_REP_DOUBLE_ARRAY:
    oc_new_double_array(&(new_rep->value.array),
                        oc_double_array_size(org_rep->value.array));
    memcpy(new_rep->value.array.ptr, org_rep->value.array.ptr,
           org_rep->value.array.size * sizeof(double));
    break;
  case OC_REP_INT_ARRAY:
    oc_new_int_array(&(new_rep->value.array),
                     oc_int_array_size(org_rep->value.array));
    memcpy(new_rep->value.array.ptr, org_rep->value.array.ptr,
           org_rep->value.array.size * sizeof(int64_t));
    break;
  case OC_REP_BYTE_STRING:
  case OC_REP_STRING:
    oc_new_string(&(new_rep->value.string), oc_string(org_rep->value.string),
                  oc_string_len(org_rep->value.string));
    break;
  case OC_REP_OBJECT:
    new_rep->value.object = _create_pushd_rsc_rep(org_rep->value.object);
    break;
  case OC_REP_OBJECT_ARRAY:
    new_rep->value.object_array =
      _create_pushd_rsc_rep(org_rep->value.object_array);
    break;
  default:
    break;
  }

  return new_rep;
}

/**
 * @brief print Resource representation
 */
void
oc_print_pushd_resource(const oc_rep_t *payload)
{
  static unsigned depth = 0;
  char prefix_width = 3;
  const char *prefix_str = "   ";
  char depth_prefix[1024] = { 0 };
  const oc_rep_t *rep = payload;

  /* check buffer overflow */
  if ((prefix_width * (depth + 1) + 1) > sizeof(depth_prefix)) {
    return;
  }

  size_t i;
#if 0
  depth_prefix[sizeof(depth_prefix) - 1] = '\0';
  depth++;
  for (i = 0; i < depth; i++) {
    strncpy(depth_prefix + (i * prefix_width), prefix_str, sizeof(depth_prefix)-(i * prefix_width));
  }
  if (depth_prefix[sizeof(depth_prefix) - 1] != '\0') {
    return;
  }
#endif
  depth++;
  for (i = 0; i < depth; i++) {
    strcpy(depth_prefix + (i * prefix_width), prefix_str);
  }
  depth_prefix[i * prefix_width] = '\0';

  if (!rep) {
    OC_PUSH_DBG("no data!");
    depth--;
    return;
  }

  if (depth == 1)
    OC_PUSH_PRINT("\n\n");

  while (rep != NULL) {
    switch (rep->type) {
    case OC_REP_BOOL:
      OC_PUSH_PRINT("%s%s: %d\n", depth_prefix, oc_string(rep->name),
                    (int)rep->value.boolean);
      break;

    case OC_REP_BOOL_ARRAY:
      OC_PUSH_PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name),
                    depth_prefix);
      for (i = 0; i < oc_bool_array_size(rep->value.array); i++) {
        OC_PUSH_PRINT("%s%s\"%d\"\n", depth_prefix, prefix_str,
                      oc_bool_array(rep->value.array)[i]);
      }
      OC_PUSH_PRINT("%s]\n", depth_prefix);
      break;

    case OC_REP_INT:
      OC_PUSH_PRINT("%s%s: %" PRId64 "\n", depth_prefix, oc_string(rep->name),
                    rep->value.integer);
      break;

    case OC_REP_INT_ARRAY:
      OC_PUSH_PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name),
                    depth_prefix);
      for (i = 0; i < oc_int_array_size(rep->value.array); i++) {
        OC_PUSH_PRINT("%s%s\"%" PRId64 "\"\n", depth_prefix, prefix_str,
                      oc_int_array(rep->value.array)[i]);
      }
      OC_PUSH_PRINT("%s]\n", depth_prefix);
      break;

    case OC_REP_DOUBLE:
      OC_PUSH_PRINT("%s%s: %f\n", depth_prefix, oc_string(rep->name),
                    rep->value.double_p);
      break;

    case OC_REP_DOUBLE_ARRAY:
      OC_PUSH_PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name),
                    depth_prefix);
      for (i = 0; i < oc_double_array_size(rep->value.array); i++) {
        OC_PUSH_PRINT("%s%s\"%f\"\n", depth_prefix, prefix_str,
                      oc_double_array(rep->value.array)[i]);
      }
      OC_PUSH_PRINT("%s]\n", depth_prefix);
      break;

    case OC_REP_STRING:
      OC_PUSH_PRINT("%s%s: \"%s\"\n", depth_prefix, oc_string(rep->name),
                    oc_string(rep->value.string));
      break;

    case OC_REP_STRING_ARRAY:
      OC_PUSH_PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name),
                    depth_prefix);
      for (i = 0; i < oc_string_array_get_allocated_size(rep->value.array);
           i++) {
        OC_PUSH_PRINT("%s%s\"%s\"\n", depth_prefix, prefix_str,
                      oc_string_array_get_item(rep->value.array, i));
      }
      OC_PUSH_PRINT("%s]\n", depth_prefix);
      break;

    case OC_REP_OBJECT:
      OC_PUSH_PRINT("%s%s: \n%s{ \n", depth_prefix, oc_string(rep->name),
                    depth_prefix);
      oc_print_pushd_resource(rep->value.object);
      OC_PUSH_PRINT("%s}\n", depth_prefix);
      break;

    case OC_REP_OBJECT_ARRAY:
    case OC_REP_NIL:
      OC_PUSH_PRINT("%s%s: \n%s[\n", depth_prefix, oc_string(rep->name),
                    depth_prefix);
      depth++;
      const oc_rep_t *obj = rep->value.object_array;
      while (obj) {
        OC_PUSH_PRINT("%s%s{\n", depth_prefix, prefix_str);
        oc_print_pushd_resource(obj->value.object);
        obj = obj->next;
        OC_PUSH_PRINT("%s%s}", depth_prefix, prefix_str);
        if (obj)
          OC_PUSH_PRINT(",\n");
        else
          OC_PUSH_PRINT("\n");
      }
      depth--;
      OC_PUSH_PRINT("%s]\n", depth_prefix);
      break;

    default:
      OC_PUSH_PRINT("%s%s: unknown type: %d ???\n", depth_prefix,
                    oc_string(rep->name), rep->type);
      break;
    }
    rep = rep->next;
  }
  depth--;
}

/**
 * @brief try to find `receiver` object which has `uri` as its `uri`
 * Property
 *
 * @param recvs_instance Resource representation of Push Receiver Resource
 * @param uri uri string
 * @param uri_len length of uri string
 * @return NULL: not found, not NULL: found `receiver` object
 */
static oc_recv_t *
_find_recv_obj_by_uri(oc_recvs_t *recvs_instance, const char *uri, int uri_len)
{
  oc_recv_t *recv = (oc_recv_t *)oc_list_head(recvs_instance->receivers);

  while (recv) {
    if (!strncmp(oc_string(recv->receiveruri), uri, uri_len)) {
      break;
    } else {
      recv = recv->next;
    }
  }

  return recv;
}

/**
 * @brief try to find `receiver` object which has `uri_string` as its `uri`
 * Property
 */
#define _find_recv_obj_by_uri2(recvs_instance, uri_string)                     \
  (_find_recv_obj_by_uri((recvs_instance), oc_string(uri_string),              \
                         oc_string_len(uri_string)))

static oc_rep_t *
_rep_list_remove(oc_rep_t **rep_list, oc_rep_t **item)
{
  oc_rep_t *removed_item;

  for (oc_rep_t **l = rep_list; *l != NULL; l = &(*l)->next) {
    if (*l == *item) {
      *l = (*l)->next;

      removed_item = *item;
      *item = (*item)->next;
      removed_item->next = NULL;
      return removed_item;
    }
  }

  return NULL;
}

/**
 * @brief callback for UPDATE of pushed Resource
 *
 * @param request request delivered from stack
 * @param iface_mask OCF interface delivered from stack
 * @param user_data not used
 */
static void
post_pushd_rsc(oc_request_t *request, oc_interface_mask_t iface_mask,
               void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  int result = OC_STATUS_CHANGED;
  oc_rep_t *rep = request->request_payload;
  oc_rep_t *common_property;
  oc_pushd_resource_rep_t *pushd_rsc_rep;
  oc_recvs_t *recvs_instance;
  oc_recv_t *recv_obj;

  recvs_instance = _find_recvs_by_device(request->resource->device);
  if (recvs_instance) {
    recv_obj = _find_recv_obj_by_uri2(recvs_instance, request->resource->uri);
    if (!recv_obj) {
      OC_PUSH_ERR("can't find receiver object for (%s)",
                  oc_string(request->resource->uri));
      return;
    }
  } else {
    OC_PUSH_ERR("can't find push receiver properties for (%s) in device (%zu), "
                "the target resource may not be a \"push receiver resource\"",
                oc_string(request->resource->uri), request->resource->device);
    return;
  }

  /* check if rt of pushed resource is part of configured rts */
  if (!_check_pushd_rsc_rt(recv_obj, rep)) {
    OC_PUSH_ERR(
      "pushed resource type(s) is not in \"rts\" of push recerver object");
    result = OC_STATUS_FORBIDDEN;
  } else {
    while (rep) {
      /*
       * <2022/4/20> skip "rt" (array), "if" (array), "n" (optional), "id"
       * (optional) common property in the payload ("oic.r.pushpayload") because
       * "rt" and "if" are already processed here...
       */
      switch (rep->type) {
      case OC_REP_STRING_ARRAY:
        if (strcmp(oc_string(rep->name), "rt") == 0) {
          /* update rt */
          oc_free_string_array(&request->resource->types);
          oc_new_string_array(
            &request->resource->types,
            oc_string_array_get_allocated_size(rep->value.array));
          for (int i = 0;
               i < (int)oc_string_array_get_allocated_size(rep->value.array);
               i++) {
            oc_string_array_add_item(
              request->resource->types,
              oc_string_array_get_item(rep->value.array, i));
          }

          /*
           * remove rep from list..
           * - remove rep from list and move pointer to the next rep...
           * - removed rep is handed over as return value
           */
          common_property = _rep_list_remove(&request->request_payload, &rep);
          oc_free_rep(common_property);
          continue;

        } else if (strcmp(oc_string(rep->name), "if") == 0) {
          /* update if */
          request->resource->interfaces = 0;
          for (int i = 0;
               i < (int)oc_string_array_get_allocated_size(rep->value.array);
               i++) {
            request->resource->interfaces |= oc_ri_get_interface_mask(
              oc_string_array_get_item(rep->value.array, i),
              oc_string_array_get_item_size(rep->value.array, i));
          }

          common_property = _rep_list_remove(&request->request_payload, &rep);
          oc_free_rep(common_property);
          continue;
        }
        break;
      case OC_REP_STRING:
        if (strcmp(oc_string(rep->name), "n") == 0) {
          /* update name */
          oc_set_string(&request->resource->name, oc_string(rep->value.string),
                        oc_string_len(rep->value.string));

          common_property = _rep_list_remove(&request->request_payload, &rep);
          oc_free_rep(common_property);
          continue;
        }
        break;

      default:
        break;
      }
      rep = rep->next;
    }

    /*
     *
     * store received "oic.r.pushpayload" resource contents
     *
     */
    pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(&request->resource->uri,
                                               request->resource->device);
    if (pushd_rsc_rep) {
      oc_rep_set_pool(&g_rep_instance_memb);
      oc_free_rep(pushd_rsc_rep->rep);

      pushd_rsc_rep->rep = _create_pushd_rsc_rep(request->request_payload);
      if (pushd_rsc_rep->rep == NULL) {
        OC_PUSH_ERR("something wrong!, creating corresponding pushed resource "
                    "representation faild (%s) ! ",
                    oc_string(request->resource->uri));
        result = OC_STATUS_INTERNAL_SERVER_ERROR;
      } else {
#ifdef OC_PUSHDEBUG
//				OC_PUSH_PRINT("\npushed target resource: %s\n",
// oc_string(pushd_rsc_rep->resource->uri));
//				oc_print_pushd_resource(pushd_rsc_rep->rep);
#endif
        if (oc_push_arrived)
          oc_push_arrived(pushd_rsc_rep);
      }
    } else {
      OC_PUSH_ERR("something wrong!, can't find corresponding pushed resource "
                  "representation instance for (%s) ",
                  oc_string(request->resource->uri));
      result = OC_STATUS_NOT_FOUND;
    }
  }

  if (result == OC_STATUS_CHANGED &&
      !(pushd_rsc_rep->resource->properties & OC_DISCOVERABLE)) {
    /*
     * if this is the first push to this target Resource... make it discoverable
     */
    OC_PUSH_DBG("this is the first push to (%s), from now on it will be "
                "discoverable...",
                oc_string(pushd_rsc_rep->resource->uri));
    oc_resource_set_discoverable(pushd_rsc_rep->resource, true);
  }

  oc_send_response_with_callback(request, result, true);
}

/**
 * @brief callback for GET of Push Receiver Resource
 */
static void
get_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask,
             void *user_data)
{
  (void)user_data;

  int result = OC_STATUS_OK;

  oc_rep_begin_root_object();
  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
    /* fall through */
    OC_FALLTHROUGH;
  case OC_IF_RW:
    /*
     * `receivers` object array
     */
    oc_rep_open_array(root, receivers);
    oc_recvs_t *recvs_instance = (oc_recvs_t *)oc_list_head(g_recvs_list);
    while (recvs_instance) {
      if (recvs_instance->resource == request->resource) {
        oc_recv_t *recv_obj =
          (oc_recv_t *)oc_list_head(recvs_instance->receivers);
        while (recv_obj) {
          /* == open new receiver object == */
          oc_rep_object_array_begin_item(receivers);
          /* receiver:receiveruri */
          oc_rep_set_text_string(receivers, receiveruri,
                                 oc_string(recv_obj->receiveruri));

          /* receiver:rts[] */
          oc_rep_open_array(receivers, rts);
          for (int j = 0;
               j < (int)oc_string_array_get_allocated_size(recv_obj->rts);
               j++) {
            oc_rep_add_text_string(rts,
                                   oc_string_array_get_item(recv_obj->rts, j));
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

  oc_send_response_with_callback(request, result, true);
}

/**
 * @brief purge app resource (`oc_resource_t`) and resource representation
 * instance (`oc_pushd_resource_rep_t`) accessed through `uri` in device whose
 * index is `device_index`
 *
 * @param uri URI of app resource to be purged
 * @param device_index index of device where the target resource resides
 */
static void
_purge_pushd_rsc(oc_string_t *uri, size_t device_index)
{
  oc_resource_t *pushd_rsc = oc_ri_get_app_resource_by_uri(
    oc_string(*uri), oc_string_len(*uri), device_index);
  oc_pushd_resource_rep_t *pushd_rsc_rep =
    _find_pushd_rsc_rep_by_uri(uri, device_index);

  if (pushd_rsc_rep) {
    /* step 1. purge `rep` */
    oc_rep_set_pool(&g_rep_instance_memb);
    oc_free_rep(pushd_rsc_rep->rep);

    /* step 2. remove pushed resource representation from `pushed_rsc_rep_list`
     */
    oc_list_remove(g_pushd_rsc_rep_list, pushd_rsc_rep);
    oc_memb_free(&g_pushd_rsc_rep_instance_memb, pushd_rsc_rep);
  } else {
    OC_PUSH_ERR(
      "can't find resource representation for pushed resource (%s)...",
      oc_string(*uri));
    return;
  }

  if (pushd_rsc) {
    /* step 3. remove pushed Resource from `app_resources` */
    OC_PUSH_DBG("purge pushed resource (%s)...", oc_string(*uri));
    oc_delete_resource(pushd_rsc);
    return;
  }
  OC_PUSH_ERR("can't find pushed resource (%s)...", oc_string(*uri));
}

/**
 * @brief create app Resource (`oc_resource_t`) and Resource representation
 * (`oc_pushd_resource_rep_t`) instance for the pushed Resource
 *
 * @param recv_obj receiver object that points pushed resource
 * @param resource Push Receiver resource
 * @return true:success, false:fail
 */
static bool
_create_pushd_rsc(oc_recv_t *recv_obj, const oc_resource_t *resource)
{
  bool result = true;

  /* create Push Receiver Resource */
  oc_resource_t *pushd_rsc = oc_new_resource(
    "Pushed Resource", oc_string(recv_obj->receiveruri), 1, resource->device);

  if (pushd_rsc) {
    /*
     * XXX, if a resource binds empty resource type (""), when a client retrieve
     * this it may receive weird value...
     */
    oc_resource_bind_resource_type(pushd_rsc, " ");
    oc_resource_bind_resource_interface(pushd_rsc, OC_IF_RW | OC_IF_BASELINE);
    oc_resource_set_default_interface(pushd_rsc, OC_IF_RW);
    /*
     * initially this resource should not be discoverable...
     * once any resource is pushed to this resource, it will be discoverable...
     */
    oc_resource_set_discoverable(pushd_rsc, false);

    oc_resource_set_request_handler(pushd_rsc, OC_GET, get_pushd_rsc, NULL);
    oc_resource_set_request_handler(pushd_rsc, OC_POST, post_pushd_rsc, NULL);
    /*
     * when this pushed resource is deleted.. delete corresponding "receiver"
     * object from receivers array of push receiver resource
     * => this is done in delete_pushrecv() (delete handler of pushreceiver
     * resource)
     */

    if (!oc_add_resource(pushd_rsc))
      result = false;

    /* create resource representation container for this resource */
    oc_pushd_resource_rep_t *pushd_rsc_rep_instance =
      (oc_pushd_resource_rep_t *)oc_memb_alloc(&g_pushd_rsc_rep_instance_memb);
    if (pushd_rsc_rep_instance) {
      pushd_rsc_rep_instance->resource = pushd_rsc;
      pushd_rsc_rep_instance->rep = NULL;
      oc_list_add(g_pushd_rsc_rep_list, pushd_rsc_rep_instance);
    } else {
      OC_PUSH_ERR("oc_memb_alloc() error!");
      result = false;
    }
  } else {
    OC_PUSH_ERR("oc_new_resource() error!");
    result = false;
  }

  return result;
}

/**
 * @brief remove receiver object array from `recv_obj_list`,
 * and app Resource pointed by `receiveruri` of each receiver
 * object in the array
 *
 * @param recvs_instance Resource representation of Push Receiver Resource
 */
static void
_purge_recv_obj_list(oc_recvs_t *recvs_instance)
{
  oc_recv_t *recv_obj = (oc_recv_t *)oc_list_pop(recvs_instance->receivers);

  while (recv_obj) {
    OC_PUSH_DBG("purge receiver obj for ( %s (device: %zu) )... ",
                oc_string(recv_obj->receiveruri),
                recvs_instance->resource->device);

    /* delete app resource pointed by `receiveruri` first.. */
    _purge_pushd_rsc(&recv_obj->receiveruri, recvs_instance->resource->device);

    oc_free_string(&recv_obj->receiveruri);
    oc_free_string_array(&recv_obj->rts);
    oc_memb_free(&g_recv_instance_memb, recv_obj);

    recv_obj = (oc_recv_t *)oc_list_pop(recvs_instance->receivers);
  }
}

/**
 * @brief update existing receiver object with new contents
 *
 * @param recv_obj existing receiver object
 * @param recvs_instance app Resource pointed by `recv_obj->receiveruri`
 * @param rep payload representation of new receiver object
 */
static void
_update_recv_obj(oc_recv_t *recv_obj, const oc_recvs_t *recvs_instance,
                 oc_rep_t *rep)
{
  oc_pushd_resource_rep_t *pushd_rsc_rep;

  while (rep) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_rep_is_property(rep, OC_PUSH_PROP_RECEIVEURI,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_RECEIVEURI))) {
        OC_PUSH_DBG("target receiveruri: \"%s\", new receiveruri: \"%s\"",
                    oc_string(recv_obj->receiveruri),
                    oc_string(rep->value.string));
        /* if `receiveruri' is different from existing `receiveruri`,
         * update URI of Resource pointed by previous `receiveruri` */
        if (strcmp(oc_string(recv_obj->receiveruri),
                   oc_string(rep->value.string)) != 0) {
          pushd_rsc_rep = _find_pushd_rsc_rep_by_uri(
            &recv_obj->receiveruri, recvs_instance->resource->device);

          if (pushd_rsc_rep) {
            OC_PUSH_DBG("pushed resource representation (\"%s\") is found",
                        oc_string(pushd_rsc_rep->resource->uri));

            oc_free_string(&pushd_rsc_rep->resource->uri);
            oc_store_uri(oc_string(rep->value.string),
                         &pushd_rsc_rep->resource->uri);
          }
        }

        oc_set_string(&recv_obj->receiveruri, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
      }
      break;

    case OC_REP_STRING_ARRAY:
      if (oc_rep_is_property(rep, OC_PUSH_PROP_RTS,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_RTS))) {
        oc_free_string_array(&recv_obj->rts);
        size_t len = oc_string_array_get_allocated_size(rep->value.array);
        oc_new_string_array(&recv_obj->rts, len);

        for (size_t i = 0; i < len; i++) {
          oc_string_array_add_item(
            recv_obj->rts, oc_string_array_get_item(rep->value.array, i));
        }
      }
      break;

    default:
      OC_PUSH_ERR("something wrong, unexpected Property type: %d", rep->type);
      return;
    }
    rep = rep->next;
  }
}

/**
 * @brief create & add new receiver object
 *
 * @param recvs_instance Resource representation of Push Receiver Resource
 * @param rep received new receiver object object
 * @return true:success, false:fail
 */
static bool
_create_recv_obj(oc_recvs_t *recvs_instance, oc_rep_t *rep)
{
  bool result = false;
  char mandatory_property_check = 0;
  oc_recv_t *recv_obj = (oc_recv_t *)oc_memb_alloc(&g_recv_instance_memb);

  if (!recv_obj) {
    OC_PUSH_ERR("oc_memb_alloc() error!");
    return result;
  }

  while (rep) {
    switch (rep->type) {
    case OC_REP_STRING:
      if (oc_rep_is_property(rep, OC_PUSH_PROP_RECEIVEURI,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_RECEIVEURI))) {
        oc_new_string(&recv_obj->receiveruri, oc_string(rep->value.string),
                      oc_string_len(rep->value.string));
        mandatory_property_check |= 0x1;
      }
      break;

    case OC_REP_STRING_ARRAY:
      if (oc_rep_is_property(rep, OC_PUSH_PROP_RTS,
                             OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_RTS))) {
        size_t len = oc_string_array_get_allocated_size(rep->value.array);
        oc_new_string_array(&recv_obj->rts, len);

        for (size_t i = 0; i < len; i++) {
          oc_string_array_add_item(
            recv_obj->rts, oc_string_array_get_item(rep->value.array, i));
        }

        mandatory_property_check |= 0x2;
      }
      break;

    default:
      OC_PUSH_ERR("something wrong, unexpected Property type: %d", rep->type);
      break;
    }
    rep = rep->next;
  }

  if (mandatory_property_check != 0x3) {
    oc_memb_free(&g_recv_instance_memb, recv_obj);
    return result;
  }

  oc_list_add(recvs_instance->receivers, recv_obj);

  /* create app resource corresponding to receiver object */
  OC_PUSH_DBG("new app resource for new receiver obj (\"%s\") is created...",
              oc_string(recv_obj->receiveruri));
  if (_create_pushd_rsc(recv_obj, recvs_instance->resource))
    result = true;

  return result;
}

/**
 * @brief validate if receiver object array has any problem or not
 *
 * @param obj_list receiver object array
 * @return true:success, false:fail
 */
static bool
_validate_recv_obj_list(oc_rep_t *obj_list)
{
  oc_rep_t *rep;
  bool result = false;
  char mandatory_property_check;

  if (!obj_list) {
    OC_PUSH_ERR("empty object array!");
    return result;
  }

  for (oc_rep_t *recv_obj = obj_list; recv_obj != NULL;
       recv_obj = recv_obj->next) {

    mandatory_property_check = 0;
    rep = recv_obj->value.object;

    for (; rep != NULL; rep = rep->next) {
      switch (rep->type) {
      case OC_REP_STRING:
        if (oc_rep_is_property(rep, OC_PUSH_PROP_RECEIVEURI,
                               OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_RECEIVEURI))) {
          mandatory_property_check |= 0x1;
        }
        break;

      case OC_REP_STRING_ARRAY:
        if (oc_rep_is_property(rep, OC_PUSH_PROP_RTS,
                               OC_CHAR_ARRAY_LEN(OC_PUSH_PROP_RTS))) {
          mandatory_property_check |= 0x2;
        }
        break;

      default:
        OC_PUSH_ERR("something wrong, unexpected Property type: %d", rep->type);
        goto exit;
      }
    }

    if (mandatory_property_check != 0x3) {
      OC_PUSH_ERR("mandatory Property is missing (%#x)",
                  0x3 - mandatory_property_check);
      goto exit;
    }
  } /* for */

  result = true;

exit:
  return result;
}

/**
 * @brief replace existing receiver object array with new one
 *
 * @param recvs_instance Resource representation of Push Receiver Resource
 * @param rep payload representation of new receiver object array
 * @return true:success, false:fail
 */
static bool
_replace_recv_obj_array(oc_recvs_t *recvs_instance, oc_rep_t *rep)
{

  if (rep == NULL || rep->type != OC_REP_OBJECT_ARRAY) {
    OC_PUSH_ERR("something wrong, unexpected Property type: %d",
                rep != NULL ? (int)rep->type : -1);
    return false;
  }

  /* check if received new receiver object array is ok */
  if (!_validate_recv_obj_list(rep->value.object_array)) {
    return false;
  }

  /* if received new receiver object array is ok, do the job... */
  /* remove existing receivers object array */
  _purge_recv_obj_list(recvs_instance);

  /* replace `receivers` obj array with new one */
  for (oc_rep_t *rep_obj = rep->value.object_array; rep_obj != NULL;
       rep_obj = rep_obj->next) {
    _create_recv_obj(recvs_instance, rep_obj->value.object);
  }

  return true;
}

/**
 * @brief	POST callback for Push Receiver Resource
 */
static void
post_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask,
              void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  const char *uri_param = NULL;
  int uri_param_len = -1;
  oc_recv_t *recv_obj;
  oc_recvs_t *recvs_instance;
  oc_rep_t *rep = request->request_payload;
  int result = OC_STATUS_CHANGED;

  /* try to get "receiveruri" parameter */
  if (request->query) {
    uri_param_len = oc_ri_get_query_value_v1(
      request->query, request->query_len, OC_PUSH_QUERY_RECEIVERURI,
      OC_CHAR_ARRAY_LEN(OC_PUSH_QUERY_RECEIVERURI), &uri_param);
    if (uri_param_len != -1) {
      OC_PUSH_DBG(
        "received query string: \"%.*s\", found \"receiveruri\": \"%.*s\" ",
        (int)request->query_len, request->query, uri_param_len, uri_param);
    }
  } else {
    OC_PUSH_DBG("request->query is NULL");
  }

  /* look up target receivers of target Push Receiver Resource */
  recvs_instance = (oc_recvs_t *)oc_list_head(g_recvs_list);
  while (recvs_instance) {
    if (recvs_instance->resource == request->resource) {
      OC_PUSH_DBG("receivers obj array instance \"%s\"@Device(%zu) is found!",
                  oc_string(request->resource->uri), request->resource->device);

      if (uri_param_len != -1) {
        recv_obj =
          _find_recv_obj_by_uri(recvs_instance, uri_param, uri_param_len);
        if (recv_obj) {

          /* if the given `receiveruri` parameter is in existing receivers
           * array, just update existing receiver object */
          OC_PUSH_DBG("existing receiver obj (\"%.*s\") is found, update it...",
                      uri_param_len, uri_param);
          _update_recv_obj(recv_obj, recvs_instance, rep);
        } else {
          /* if the given `receiveruri` parameter is not in existing receivers
           * array, add new receiver object to the receivers array */
          OC_PUSH_DBG("can't find receiver obj which has uri \"%.*s\", "
                      "creating new receiver obj...",
                      uri_param_len, uri_param);

          /*
           * if there is already NORMAL resource whose path is same as equested
           * target uri, just ignore this request and return error!
           */
          if (oc_ri_get_app_resource_by_uri(uri_param, uri_param_len,
                                            recvs_instance->resource->device)) {
            OC_PUSH_ERR("can't create receiver obj because its receiveruri is "
                        "same as existing app resource (\"%.*s\")...",
                        uri_param_len, uri_param);
            result = OC_STATUS_FORBIDDEN;
            goto exit;
          }

          /* create corresponding receiver object */
          if (!_create_recv_obj(recvs_instance, rep)) {
            OC_PUSH_ERR("failed to create receiver obj whose receiveruri is "
                        "(\"%.*s\")...",
                        uri_param_len, uri_param);
            result = OC_STATUS_BAD_REQUEST;
            goto exit;
          }
        }
      } else {
        /* if `receiveruri` param is not provided..
         * replace whole existing `receivers` object array with new one.. */
        OC_PUSH_DBG("replace existing receiver obj array with new ones...");
        if (!_replace_recv_obj_array(recvs_instance, rep)) {
          OC_PUSH_ERR("failed to replace existing whole receiver objs...");
          result = OC_STATUS_BAD_REQUEST;
          goto exit;
        }
      }

      break;
    }

    recvs_instance = recvs_instance->next;
  }

exit:
  oc_send_response_with_callback(request, result, true);
}

/**
 * @brief DELETE callback for Push Receiver Resource
 */
static void
delete_pushrecv(oc_request_t *request, oc_interface_mask_t iface_mask,
                void *user_data)
{
  (void)iface_mask;
  (void)user_data;

  const char *uri_param;
  int uri_param_len = -1;
  oc_recv_t *recv_obj;
  oc_recvs_t *recvs_instance;
  int result = OC_STATUS_DELETED;

  /* try to get "receiveruri" parameter */
  if (request->query) {
    uri_param_len = oc_ri_get_query_value_v1(
      request->query, request->query_len, OC_PUSH_QUERY_RECEIVERURI,
      OC_CHAR_ARRAY_LEN(OC_PUSH_QUERY_RECEIVERURI), &uri_param);
    if (uri_param_len != -1) {
      OC_PUSH_DBG(
        "received query string: \"%.*s\", found \"receiveruri\": \"%.*s\" ",
        (int)request->query_len, request->query, uri_param_len, uri_param);
    }
  } else {
    OC_PUSH_DBG("request->query is NULL");
  }

  /* look up target receivers of target Push Receiver Resource */
  recvs_instance = (oc_recvs_t *)oc_list_head(g_recvs_list);
  while (recvs_instance) {
    if (recvs_instance->resource == request->resource) {
      OC_PUSH_DBG("receivers obj array instance of push receiver resource "
                  "(\"%s\") is found!",
                  oc_string(request->resource->uri));

      if (uri_param_len != -1) {
        recv_obj =
          _find_recv_obj_by_uri(recvs_instance, uri_param, uri_param_len);
        if (recv_obj) {
          /* remove receiver obj from array */
          oc_list_remove(recvs_instance->receivers, recv_obj);
          OC_PUSH_DBG("receiver obj is removed from array");

          /* delete associated resource... */
          _purge_pushd_rsc(&recv_obj->receiveruri,
                           recvs_instance->resource->device);
          OC_PUSH_DBG(
            "app resource corresponding to the receiver obj is removed");

          /* free memory */
          oc_free_string(&recv_obj->receiveruri);
          oc_free_string_array(&recv_obj->rts);
          oc_memb_free(&g_recv_instance_memb, recv_obj);
        } else {
          /* if the given `receiveruri` parameter is not in existing receivers
           * array, add new receiver object to the receivers array */
#ifdef OC_PUSHDEBUG
          OC_PUSH_DBG(
            "can't find receiver object which has uri(\"%.*s\"), ignore it...",
            uri_param_len, uri_param);
#endif /* OC_PUSHDEBUG */
          result = OC_STATUS_NOT_FOUND;
        }
      } else {
        /* if `receiveruri` param is not provided..
         * remove whole existing `receivers` object array */
        _purge_recv_obj_list(recvs_instance);
      }

      break;
    }

    recvs_instance = recvs_instance->next;
  }

  oc_send_response_with_callback(request, result, true);
}

/**
 * @brief	initiate Push Receiver Resource
 *
 * @details
 * for Target Server \n
 * - Push Receiver ("oic.r.pushreceiver") \n
 *
 * @param device_index  device index
 */
void
oc_create_pushreceiver_resource(size_t device_index)
{
  /* create Push Receiver Resource */
  oc_resource_t *push_recv = oc_new_resource(
    "Push Receiver", PUSHRECEIVERS_RESOURCE_PATH, 1, device_index);

  if (push_recv) {
    oc_resource_bind_resource_type(push_recv, "oic.r.pushreceiver");
    oc_resource_bind_resource_interface(push_recv, OC_IF_RW | OC_IF_BASELINE);
    oc_resource_set_default_interface(push_recv, OC_IF_RW);
    oc_resource_set_discoverable(push_recv, true);

    oc_resource_set_request_handler(push_recv, OC_GET, get_pushrecv, NULL);
    oc_resource_set_request_handler(push_recv, OC_POST, post_pushrecv, NULL);
    oc_resource_set_request_handler(push_recv, OC_DELETE, delete_pushrecv,
                                    NULL);

    /*
     * add struct for `receivers` object list for this Resource to the list
     */
    oc_recvs_t *recvs_instance =
      (oc_recvs_t *)oc_memb_alloc(&g_recvs_instance_memb);
    if (recvs_instance) {
      oc_add_resource(push_recv);
      recvs_instance->resource = push_recv;
      OC_LIST_STRUCT_INIT(recvs_instance, receivers);
      oc_list_add(g_recvs_list, recvs_instance);
    } else {
      OC_PUSH_ERR("oc_memb_alloc() error!");
      oc_delete_resource(push_recv);
    }
  } else {
    OC_PUSH_ERR("oc_new_resource() error!");
  }
}

void
oc_push_init(void)
{
  oc_list_init(g_ns_list);
  oc_list_init(g_recvs_list);
  oc_list_init(g_pushd_rsc_rep_list);
}

/*
 * clean up push related data structure
 * - for push configuration Resource: they are cleaned when all app Resources
 * are removed (see oc_main_shutdown())
 * - for push receivers Resource: free in this function
 */
void
oc_push_free(void)
{
  OC_PUSH_DBG("begin to free push receiver list!!!");

  oc_recvs_t *recvs_instance = (oc_recvs_t *)oc_list_pop(g_recvs_list);
  while (recvs_instance) {
    _purge_recv_obj_list(recvs_instance);
    OC_PUSH_DBG("free push receiver Resource (device: %zu)... ",
                recvs_instance->resource->device);
    oc_delete_resource(recvs_instance->resource);
    oc_memb_free(&g_recvs_instance_memb, recvs_instance);
    recvs_instance = (oc_recvs_t *)oc_list_pop(g_recvs_list);
  }
}

/**
 * @brief Response callback for PUSH Update request
 *
 * @param data response payload
 */
static void
response_to_push_rsc(oc_client_response_t *data)
{
  oc_ns_t *ns_instance = (oc_ns_t *)data->user_data;

  OC_PUSH_DBG("\n   => return status code: [ %s ]",
              oc_status_to_str(data->code));

  if (data->code == OC_REQUEST_TIMEOUT) {
    /*
     * TODO4ME <2022/4/17> if update request fails... retry to resolve endpoint
     * of target device ID...
     */
    OC_PUSH_DBG("state of Push Proxy (\"%s\") is changed (%s => %s)",
                oc_string(ns_instance->resource->uri),
                oc_string(ns_instance->state), pp_statestr(OC_PP_TOUT));
    pp_update_state(ns_instance->state, pp_statestr(OC_PP_TOUT));
  } else if (data->code == OC_STATUS_CHANGED) {
    OC_PUSH_DBG("state of Push Proxy (\"%s\") is changed (%s => %s)",
                oc_string(ns_instance->resource->uri),
                oc_string(ns_instance->state), pp_statestr(OC_PP_WFU));
    pp_update_state(ns_instance->state, pp_statestr(OC_PP_WFU));
  } else {
    /*
     * <2022/4/17> check condition to enter ERR
     */
    OC_PUSH_DBG("state of Push Proxy (\"%s\") is changed (%s => %s)",
                oc_string(ns_instance->resource->uri),
                oc_string(ns_instance->state), pp_statestr(OC_PP_ERR));
    pp_update_state(ns_instance->state, pp_statestr(OC_PP_ERR));
  }
}

/**
 * @brief send PUSH update request
 *
 * @param ns_instance composition of `oic.r.notificationselector` +
 * `oic.r.pushproxy`
 * @return true:success, false:fail
 */
static bool
push_update(oc_ns_t *ns_instance)
{
  oc_resource_t *src_rsc = (oc_resource_t *)ns_instance->user_data;
  if (!ns_instance || !src_rsc) {
    OC_PUSH_ERR("something wrong! corresponding notification selector source "
                "resource is NULL, or updated resource is NULL!");
    return false;
  }

  if (!src_rsc->payload_builder) {
    OC_PUSH_ERR("payload_builder() of source resource is NULL!");
    return false;
  }

  /*
   * 1. find `notification selector` which monitors `src_rsc` from `ns_col_list`
   * 2. post UPDATE by using URI, endpoint (use oc_sting_to_endpoint())
   */
  if (!oc_init_post(oc_string(ns_instance->targetpath),
                    &ns_instance->pushtarget_ep, "if=oic.if.rw",
                    &response_to_push_rsc, HIGH_QOS, ns_instance)) {
    OC_PUSH_ERR("Could not init POST");
    return false;
  }
  /*
   * add other properties than "rep" object of "oic.r.pushpayload" Resource
   * here. payload_builder() only "rep" object.
   *
   * payload_builder() doesn't need to have "oc_rep_start_root_object()" and
   * "oc_rep_end_root_object()" they should be added here...
   */
  oc_rep_begin_root_object();

  /* anchor */
  char di[OC_UUID_LEN + 10];
  snprintf(di, sizeof(di), "ocf://");
  oc_uuid_to_str(oc_core_get_device_id(ns_instance->resource->device), di + 6,
                 OC_UUID_LEN);
  oc_rep_set_text_string(root, anchor, di);

  /* href (optional) */
  if (oc_string(ns_instance->phref) &&
      strcmp(oc_string(ns_instance->phref), "") != 0) {
    oc_rep_set_text_string(root, href, oc_string(ns_instance->phref));
  }

  /* rt */
  oc_rep_open_array(root, rt);
  for (size_t i = 0; i < oc_string_array_get_allocated_size(src_rsc->types);
       i++) {
    oc_rep_add_text_string(rt, oc_string_array_get_item(src_rsc->types, i));
  }
  oc_rep_close_array(root, rt);

  /* if */
  oc_core_encode_interfaces_mask(oc_rep_object(root), src_rsc->interfaces);

  /* build rep object */
  src_rsc->payload_builder();

  oc_rep_end_root_object();

  if (!oc_do_post()) {
    OC_PUSH_ERR("Could not send POST");
    return false;
  }
#ifdef OC_PUSHDEBUG
  oc_string64_t ep;
  oc_string_t full_uri;

  oc_endpoint_to_string64(&ns_instance->pushtarget_ep, &ep);
  if (oc_string_len(ns_instance->targetpath)) {
    oc_concat_strings(&full_uri, oc_string(ep),
                      oc_string(ns_instance->targetpath));
  } else {
    oc_new_string(&full_uri, oc_string(ep), oc_string_len(ep));
  }

  OC_PUSH_DBG("push \"%s\" ====> \"%s\"", oc_string(src_rsc->uri),
              oc_string(full_uri));
  oc_free_string(&full_uri);
#endif
  OC_PUSH_DBG("state of Push Proxy (\"%s\") is changed (%s => %s)",
              oc_string(ns_instance->resource->uri),
              oc_string(ns_instance->state), pp_statestr(OC_PP_WFR));
  pp_update_state(ns_instance->state, pp_statestr(OC_PP_WFR));

  return true;
}

OC_PROCESS_THREAD(oc_push_process, ev, data)
{
  oc_resource_t *src_rsc;
  oc_ns_t *ns_instance;
  char di[OC_UUID_LEN];

  OC_PROCESS_BEGIN();

  while (oc_process_is_running(&oc_push_process)) {

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
    if (ev == oc_event_to_oc_process_event(PUSH_RSC_STATE_CHANGED)) {
      ns_instance = (oc_ns_t *)data;
      src_rsc = (oc_resource_t *)ns_instance->user_data;

      if (!ns_instance || !src_rsc /*|| !ns_instance->user_data*/) {
        OC_PUSH_ERR("something wrong! corresponding notification selector "
                    "source resource is NULL, or updated resource is NULL!");
        break;
      }

      /*
       * client에서 POST 하는 루틴 참조할 것 (client_multithread_linux.c 참고)
       */
      /*
       * 1. find `notification selector` which monitors `src_rsc` from
       * `ns_col_list`
       * 2. post UPDATE by using URI, endpoint (use oc_sting_to_endpoint())
       */
      if (oc_init_post(oc_string(ns_instance->targetpath),
                       &ns_instance->pushtarget_ep, "if=oic.if.rw",
                       &response_to_push_rsc, LOW_QOS, NULL)) {
        /*
         * add other properties than "rep" object of "oic.r.pushpayload"
         * Resource here. payload_builder() only adds "rep" object.
         *
         * payload_builder() doesn't need to have "oc_rep_start_root_object()"
         * and "oc_rep_end_root_object()" they should be added here...
         */

        oc_rep_begin_root_object();

        /* anchor */
        oc_uuid_to_str(oc_core_get_device_id(ns_instance->resource->device), di,
                       OC_UUID_LEN);
        oc_rep_set_text_string(root, anchor, di);

        /* href
         * - option
         */
        if (oc_string(ns_instance->phref) &&
            strcmp(oc_string(ns_instance->phref), "") != 0) {
          oc_rep_set_text_string(root, href, oc_string(ns_instance->phref));
        }

        /* rt */
        oc_rep_open_array(root, rt);
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(src_rsc->types); i++) {
          oc_rep_add_text_string(rt,
                                 oc_string_array_get_item(src_rsc->types, i));
        }
        oc_rep_close_array(root, rt);

        /* if */
        oc_core_encode_interfaces_mask(oc_rep_object(root),
                                       src_rsc->interfaces);

        src_rsc->payload_builder();

        oc_rep_end_root_object();

        OC_PUSH_DBG("Sending POST request");
        if (!oc_do_post()) {
          OC_PUSH_ERR("Could not send POST");
        }
      } else {
        OC_PUSH_ERR("Could not init POST");
      }
    }
  }

  OC_PROCESS_END()
}

/**
 * @brief check if any of source array is part of target array
 * @return
 * 			false: any of source is not part of target
 * 			true: any of source is part of target
 */
static bool
_check_string_array_inclusion(oc_string_array_t *target,
                              oc_string_array_t *source)
{
  size_t tgt_len = oc_string_array_get_allocated_size(*target);
  size_t src_len = oc_string_array_get_allocated_size(*source);

  if (tgt_len == 0 || src_len == 0) {
    OC_PUSH_DBG("source or target string array is empty!");
    return false;
  }

  for (size_t i = 0; i < src_len; i++) {
    for (size_t j = 0; j < tgt_len; j++) {
      if (strcmp(oc_string_array_get_item(*source, i),
                 oc_string_array_get_item(*target, j)) == 0) {
        return true;
      }
    }
  }

  return false;
}

/**
 * @brief trigger PUSH procedure
 *
 * @param uri path of updated Resource
 * @param device_index device index which the updated Resource belongs to
 */
void
oc_resource_state_changed(const char *uri, size_t uri_len, size_t device_index)
{
  oc_resource_t *resource =
    oc_ri_get_app_resource_by_uri(uri, uri_len, device_index);
  oc_ns_t *ns_instance = (oc_ns_t *)oc_list_head(g_ns_list);
  char all_matched = 0x7;

  OC_PUSH_DBG("resource \"%s\"@device(%zu) is updated!", uri, device_index);

  if (!resource) {
    OC_PUSH_ERR("there is no resource for \"%s\"@device(%zu)", uri,
                device_index);
    return;
  }
  if (!(resource->properties & OC_PUSHABLE)) {
    OC_PUSH_ERR("resource \"%s\"@device (%zu) is not pushable!", uri,
                device_index);
    return;
  }

  for (; ns_instance; ns_instance = ns_instance->next) {
    if (ns_instance->resource->device != device_index)
      continue;

    /* if push proxy is not in "wait for update" state, just skip it... */
    if (strcmp(oc_string(ns_instance->state), pp_statestr(OC_PP_WFU)) != 0)
      continue;

    if (oc_string(ns_instance->phref)) {
      if (strcmp(oc_string(ns_instance->phref), uri) != 0) {
        OC_PUSH_DBG("%s:phref exists, but mismatches (phref:%s - uri:%s)",
                    oc_string(ns_instance->resource->uri),
                    oc_string(ns_instance->phref), uri);
        all_matched = 0;
      } else {
        OC_PUSH_DBG("%s:phref matches (phref:%s - uri:%s)",
                    oc_string(ns_instance->resource->uri),
                    oc_string(ns_instance->phref), uri);
      }
    } else {
      OC_PUSH_DBG("%s:phref does not exist",
                  oc_string(ns_instance->resource->uri));
      all_matched &= 0x6;
    }

    if (oc_string_array_get_allocated_size(ns_instance->prt) > 0) {
      if (!_check_string_array_inclusion(&ns_instance->prt, &resource->types)) {
#ifdef OC_PUSHDEBUG
        OC_PUSH_PRINT("%s:prt exists, but mismatches (prt: [",
                      oc_string(ns_instance->resource->uri));
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(ns_instance->prt); i++) {
          OC_PUSH_PRINT("%s ", oc_string_array_get_item(ns_instance->prt, i));
        }
        OC_PUSH_PRINT("] - rt of updated rsc: [");
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(resource->types); i++) {
          OC_PUSH_PRINT("%s ", oc_string_array_get_item(resource->types, i));
        }
        OC_PUSH_PRINT("])\n");
#endif
        all_matched = 0;
      } else {
#ifdef OC_PUSHDEBUG
        OC_PUSH_PRINT("%s:prt matches (prt: [",
                      oc_string(ns_instance->resource->uri));
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(ns_instance->prt); i++) {
          OC_PUSH_PRINT("%s ", oc_string_array_get_item(ns_instance->prt, i));
        }
        OC_PUSH_PRINT("] - rt of updated rsc: [");
        for (size_t i = 0;
             i < oc_string_array_get_allocated_size(resource->types); i++) {
          OC_PUSH_PRINT("%s ", oc_string_array_get_item(resource->types, i));
        }
        OC_PUSH_PRINT("])\n");
#endif
      }
    } else {
      OC_PUSH_DBG("%s:prt does not exist",
                  oc_string(ns_instance->resource->uri));
      all_matched &= 0x5;
    }

    if (oc_string_array_get_allocated_size(ns_instance->pif) > 0) {
      oc_interface_mask_t pif = 0;
      for (size_t i = 0;
           i < oc_string_array_get_allocated_size(ns_instance->pif); i++) {
        pif |= oc_ri_get_interface_mask(
          oc_string_array_get_item(ns_instance->pif, i),
          oc_byte_string_array_get_item_size(ns_instance->pif, i));
      }

      if (!(pif & resource->interfaces)) {
        OC_PUSH_DBG(
          "%s:pif exists, but mismatches (pif:%#x - if of updated rsc:%#x)",
          oc_string(ns_instance->resource->uri), pif, resource->interfaces);
        all_matched = 0;
      } else {
        OC_PUSH_DBG("%s:pif matches (pif:%#x - if of updated rsc:%#x)",
                    oc_string(ns_instance->resource->uri), pif,
                    resource->interfaces);
      }
    } else {
      OC_PUSH_DBG("%s:pif does not exist",
                  oc_string(ns_instance->resource->uri));
      all_matched &= 0x3;
    }

    if (all_matched) {
      if (!oc_process_is_running(&oc_push_process)) {
        OC_PUSH_DBG("oc_push_process is not running!");
        return;
      }

      OC_PUSH_DBG("resource \"%s\" matches notification selector \"%s\"!",
                  oc_string(resource->uri),
                  oc_string(ns_instance->resource->uri));

      /* resource is necessary to identify which resource is being pushed..,
       * before sending update to target server */
      ns_instance->user_data = resource;

      /* post "event" for Resource which has just been updated */
      if (!push_update(ns_instance)) {
        OC_PUSH_ERR("sensing PUSH Update of \"%s\" failed!",
                    oc_string(resource->uri));
      }
#if 0
      oc_process_post(&oc_push_process,
          oc_event_to_oc_process_event(PUSH_RSC_STATE_CHANGED), ns_instance);
#endif
    }
    all_matched = 0x7;
  }
}

#endif /* OC_HAS_FEATURE_PUSH */

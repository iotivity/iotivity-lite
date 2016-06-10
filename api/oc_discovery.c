/*
 // Copyright (c) 2016 Intel Corporation
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
 */

#include "oc_core_res.h"
#include "oc_api.h"
#include "messaging/coap/oc_coap.h"

static bool
filter_resource(oc_resource_t *resource,
		const char *rt,
		int rt_len, CborEncoder *links)
{
  int i;
  bool match = true;
  if(rt_len > 0) {   
    match = false;
    for(i = 0; i < oc_string_array_get_allocated_size(resource->types);
	i++) {
      int size = oc_string_array_get_item_size(resource->types, i);
      const char *t =
	(const char*)oc_string_array_get_item(resource->types, i);
      if(rt_len == size && strncmp(rt, t, rt_len) == 0) {
        match = true;
	break;
      }
    }
  }
  
  if(!match) {
    return false;
  }

  oc_rep_start_object(*links, res);

  //uri
  oc_rep_set_text_string(res, href, oc_string(resource->uri));
  
  //rt
  oc_rep_set_array(res, rt);
  for(i = 0; i < oc_string_array_get_allocated_size(resource->types);
	i++) {
    int size = oc_string_array_get_item_size(resource->types, i);
    const char *t =
      (const char*)oc_string_array_get_item(resource->types, i);
    if (size > 0)
      oc_rep_add_text_string(rt, t);
  }
  oc_rep_close_array(res, rt);
  
  //if
  oc_core_encode_interfaces_mask(oc_rep_object(res), resource->interfaces);
 
  //p
  oc_rep_set_object(res, p);
  oc_rep_set_uint(p, bm, resource->properties & ~OC_PERIODIC);
  
#ifdef OC_SECURITY  
  if(resource->properties & OC_SECURE) {
    oc_rep_set_boolean(p, sec, true);
    oc_rep_set_uint(p, port, oc_connectivity_get_dtls_port());
  }
#endif /* OC_SECURITY */
  
  oc_rep_close_object(res, p);

  oc_rep_end_object(*links, res);
  return true;
}

static int
process_device_object(CborEncoder *device, const char *uuid,
		      const char *rt, int rt_len)
{
  int dev, matches = 0;
  oc_rep_start_object(*device, links);
  oc_rep_set_text_string(links, di, uuid);
  oc_rep_set_array(links, links);
  
  if (filter_resource(oc_core_get_resource_by_index(OCF_P), rt, rt_len,
		      oc_rep_array(links)))
    matches++;
  
  for (dev = 0; dev < oc_core_get_num_devices(); dev++) {
    if (filter_resource(oc_core_get_resource_by_index(NUM_OC_CORE_RESOURCES - 1 - dev), rt, rt_len, oc_rep_array(links)))
      matches++;
  }
  
#ifdef OC_SERVER    
  oc_resource_t *resource = oc_ri_get_app_resources();    
  for (; resource; resource = resource->next) {
    
    if (!(resource->properties & OC_DISCOVERABLE))
      continue;
    
    if (filter_resource(resource, rt, rt_len, oc_rep_array(links)))
      matches++;
  }
#endif    
  
#ifdef OC_SECURITY    
  if (rt_len > 0) {
    int core = OCF_SEC_DOXM;
    while (core <= OCF_SEC_CRED) {
      if (filter_resource(oc_core_get_resource_by_index(core), rt, rt_len,
			  oc_rep_array(links)))
	matches++;
      core++;
    }
  }
#endif    
  
  oc_rep_close_array(links, links);
  oc_rep_end_object(*device, links);

  return matches;
}

static void
oc_core_discovery_handler(oc_request_t *request,
			  oc_interface_mask_t interface)
{
  char *rt = NULL;
  int rt_len = 0, matches = 0;
  if(request->query_len) {
    rt_len = oc_ri_get_query_value(request->query, request->query_len,
				   "rt", &rt);
  }

  char uuid[37];
  oc_uuid_to_str(oc_core_get_device_id(0), uuid, 37);
  
  switch (interface) {
  case OC_IF_DEFAULT:
  case OC_IF_LL:
    {
      oc_rep_start_links_array();
      matches =
	process_device_object(oc_rep_array(links),
			      uuid, rt, rt_len);
      oc_rep_end_links_array();
    }
    break;
  case OC_IF_BASELINE:
    {
      oc_rep_start_root_object();
      oc_process_baseline_interface(request->resource);
      oc_rep_set_array(root, links);
      matches =
	process_device_object(oc_rep_array(links),
			      uuid, rt, rt_len);      
      oc_rep_close_array(root, links);
      oc_rep_end_root_object();
    }
    break;
  default:
    break;
  }
  
  int response_length = oc_rep_finalize();
  
  if(matches && response_length) {
    request->response->response_buffer->response_length = response_length;
    request->response->response_buffer->code = oc_status_code(OK);
  }
  else {
    /* There were rt/if selections and there were no matches, so ignore */
    request->response->response_buffer->code = IGNORE;
  }
}

void
oc_create_discovery_resource()
{
  oc_core_populate_resource(OCF_RES, "/oic/res", "oic.wk.res",
			    OC_IF_LL | OC_IF_BASELINE,
			    OC_ACTIVE,
			    oc_core_discovery_handler, 0, 0, 0,
			    0);
}

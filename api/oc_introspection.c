/*
 // Copyright (c) 2017 Intel Corporation
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

#include "messaging/coap/oc_coap.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include <stdio.h>


#define MAX_DEVICES 5
#define MAX_FILENAME_LENGTH 128

static char IDD_names[MAX_DEVICES][MAX_FILENAME_LENGTH] = { "server_introspection.dat", 
                                                            "server_introspection.dat", 
                                                            "server_introspection.dat", 
                                                            "server_introspection.dat", 
                                                            "server_introspection.dat"};

long
IDD_storage_size(const char *store)
{
	FILE *fp;
	long filesize;

	fp = fopen(store, "rb");
	if (!fp)
	{
		PRINT("IDD_storage_size: ERROR file %s does not open\n", store);
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	filesize = ftell(fp);
	fclose(fp);
	PRINT("IDD_storage_size %s size %d [bytes] \n", store, filesize);
	return filesize;
}

long
IDD_storage_read(const char *store, uint8_t *buf, size_t size)
{
	FILE *fp = 0;

	fp = fopen(store, "rb");
	if (!fp)
	{
		PRINT("IDD_storage_size file %s does not open\n", store);
		return 0;
	}

	size = fread(buf, 1, size, fp);
	fclose(fp);
	return size;
}

static void
oc_core_introspection_data_handler(oc_request_t *request,
                                   oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;
  
  
  PRINT("oc_introspection: oc_core_introspection_data_handler\n");

  /* The file should contain a CBOR-encoded swagger description of
   * introspection data to return to clients. 
   */
    int index = 0;  // TODO this needs to be conveyed in *data, but could not figure out how set that..
    char *filename = IDD_names[index];
    long filesize;
    
    filesize = IDD_storage_size(filename);
	if (filesize < OC_MAX_APP_DATA_SIZE)
	{
		IDD_storage_read(filename, request->response->response_buffer->buffer, filesize);
		request->response->response_buffer->response_length = (uint16_t)filesize;
		request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
	}
	else
	{
		OC_DBG("oc_core_introspection_data_handler : %d is too big for buffer %d \n", filesize, OC_MAX_APP_DATA_SIZE);
		request->response->response_buffer->response_length = (uint16_t)0;
		request->response->response_buffer->code = oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR);
	}
    
}

static void
oc_core_introspection_wk_handler(oc_request_t *request,
                                 oc_interface_mask_t interface, void *data)
{
  (void)data;

  /* We are interested in only a single coap:// endpoint on this logical device.
   */

  oc_endpoint_t *eps = oc_connectivity_get_endpoints(request->resource->device);
  oc_string_t ep, uri;
  memset(&uri, 0, sizeof(oc_string_t));
  while (eps != NULL) {
#ifdef OC_SECURITY
    if ((eps->flags & SECURED)) {
#else
    if (!(eps->flags & SECURED)) {
#endif /* OC_SECURITY */
      if (oc_endpoint_to_string(eps, &ep) == 0) {
        oc_concat_strings(&uri, oc_string(ep), "/oc/introspection");
        oc_free_string(&ep);
        break;
      }
    }
 
    eps = eps->next;
  }
  oc_free_endpoint_list();

  if (oc_string_len(uri) <= 0) {
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  oc_rep_start_root_object();

  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_array(root, urlInfo);
    oc_rep_object_array_start_item(urlInfo);
    oc_rep_set_text_string(urlInfo, content-type, "application/cbor");
#ifdef OC_SECURITY
    oc_rep_set_text_string(urlInfo, protocol, "coaps");
#else
    oc_rep_set_text_string(urlInfo, protocol, "coap");
#endif /* OC_SECURITY */

    oc_rep_set_text_string(urlInfo, url, oc_string(uri));
    oc_rep_object_array_end_item(urlInfo);
    oc_rep_close_array(root, urlInfo);
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);

  PRINT("oc_introspection: oc_core_introspection_wk_handler  %s\n", oc_string(uri));
  oc_free_string(&uri);
}

void 
oc_set_introspection_file(int device, const char* filename)
{
	int filenamesize = 0;
    if (device >= MAX_DEVICES)
    {
        PRINT("oc_set_introspection_file: ERROR device index larger %d than %d\n", device, MAX_DEVICES);
    }
    filenamesize = strlen(filename);
    if (filenamesize-1 >= MAX_FILENAME_LENGTH)
    {
        PRINT("oc_set_introspection_file: filename size larger %d than %d\n", filenamesize, MAX_FILENAME_LENGTH);
    }
    strcpy(&IDD_names[device][0], filename);
    
    for (int index=0 ; index <  MAX_DEVICES; index++)
    {
         PRINT("oc_set_introspection_file: device index %d filename %s\n", index, IDD_names[index]);
    }
}


void
oc_create_introspection_resource(int device)
{
  OC_DBG("oc_introspection: Initializing introspection resource\n");
  
  
#ifdef OC_SERVER
    PRINT("oc_introspection: Initializing introspection resource as server\n");
#endif /* OC_SERVER */
  
  
  oc_core_populate_resource(OCF_INTROSPECTION_WK, device, "oc/wk/introspection",
                            OC_IF_R | OC_IF_BASELINE, OC_IF_R, OC_DISCOVERABLE | OC_SECURE,
                            oc_core_introspection_wk_handler, 0, 0, 0, 1,
                            "oic.wk.introspection");
  oc_core_populate_resource(OCF_INTROSPECTION_DATA, device, "oc/introspection",
                            OC_IF_BASELINE, OC_IF_BASELINE, OC_SECURE,
                            oc_core_introspection_data_handler, 0, 0, 0, 1,
                            "oic.introspection.data");
}


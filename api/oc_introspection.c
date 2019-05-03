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
#include "oc_introspection.h"
#include "oc_core_res.h"
#include "oc_endpoint.h"
#include <stdio.h>

#define MAX_FILENAME_LENGTH 128

#ifdef OC_IDD_FILE

#define MAX_TAG_LENGTH 20

OC_LIST(oc_introspect_info);

void
oc_set_introspection_file(size_t device, const char *filename)
{
    printf(">>> oc_set_introspection_file from FILE = \"%s\"\n", filename);
    oc_device_info_t *device_info = oc_core_get_device_info(device);
    device_info->introspect_info.source = OC_INTROSPECT_FILE;
    strncpy(device_info->introspect_info.filename, filename, MAX_INTROSPECT_FILENAME_LENGTH);
    device_info->introspect_info.filename[MAX_INTROSPECT_FILENAME_LENGTH] = "\0";
}

void oc_set_introspection_data(size_t device, uint8_t* IDD, size_t IDD_size)
{
    oc_device_info_t *device_info = oc_core_get_device_info(device);
    device_info->introspect_info.source = OC_INTROSPECT_BYTE_ARRAY;
    device_info->introspect_info.filename[0] = "\0";
    device_info->introspect_info.data = IDD;
    device_info->introspect_info.data_size = IDD_size;
}

static long
IDD_storage_size(const char *store)
{
  FILE *fp;
  long filesize;

  fp = fopen(store, "rb");
  if (!fp) {
    OC_ERR("IDD_storage_size: ERROR file %s does not open\n", store);
    return 0;
  }

  fseek(fp, 0, SEEK_END);
  filesize = ftell(fp);
  fclose(fp);
  PRINT("IDD_storage_size %s size %d [bytes] \n", store, filesize);
  return filesize;
}

static size_t
IDD_storage_read(const char *store, uint8_t *buf, size_t size)
{
  FILE *fp = 0;
  fp = fopen(store, "rb");
  if (!fp) {
    OC_ERR("IDD_storage_size file %s does not open\n", store);
    return 0;
  }

  size = fread(buf, 1, size, fp);
  fclose(fp);
  return size;
}

#else /*OC_IDD_FILE*/

#include "server_introspection.dat.h"

static long
IDD_storage_size(const char *store)
{
  (void)store;
  return introspection_data_size;
}

static size_t
IDD_storage_read(const char *store, uint8_t *buf, size_t size)
{
  (void)store;
  memcpy(buf, introspection_data, size);
  return size;
}

#endif /*OC_IDD_FILE*/

static void
oc_core_introspection_data_handler(oc_request_t *request,
                                   oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  OC_DBG("in oc_core_introspection_data_handler");

  size_t index = request->resource->device;
  oc_device_info_t *device_info = oc_core_get_device_info(index);
  char filename[MAX_FILENAME_LENGTH];
  long filesize;

  if (strlen(device_info->introspect_info.filename) > 0) {
      strncpy(filename, device_info->introspect_info.filename, MAX_FILENAME_LENGTH);
      filename[MAX_FILENAME_LENGTH] = "\0";
  } else {
      strncpy(filename, "server_introspection.dat", MAX_FILENAME_LENGTH);
  }
  if (device_info->introspect_info.source == OC_INTROSPECT_FILE) {
      filesize = IDD_storage_size(filename);
  }
  else {
      filesize = device_info->introspect_info.data_size;
  }
  if (filesize < OC_MAX_APP_DATA_SIZE) {
      if (device_info->introspect_info.source == OC_INTROSPECT_FILE) {
          IDD_storage_read(filename, request->response->response_buffer->buffer,
              filesize);
      } else {
          memcpy(request->response->response_buffer->buffer,
                 device_info->introspect_info.data,
                 filesize);
      }
    request->response->response_buffer->response_length = (uint16_t)filesize;
    request->response->response_buffer->code = oc_status_code(OC_STATUS_OK);
  } else {
    OC_ERR(
      "oc_core_introspection_data_handler : %d is too big for buffer %d \n",
      filesize, OC_MAX_APP_DATA_SIZE);
    request->response->response_buffer->response_length = (uint16_t)0;
    request->response->response_buffer->code =
      oc_status_code(OC_STATUS_INTERNAL_SERVER_ERROR);
  }
}

static void
oc_core_introspection_wk_handler(oc_request_t *request,
                                 oc_interface_mask_t iface_mask, void *data)
{
  (void)data;

  int interface_index =
    (request->origin) ? request->origin->interface_index : -1;
  enum transport_flags conn =
    (request->origin && (request->origin->flags & IPV6)) ? IPV6 : IPV4;
  /* We are interested in only a single coap:// endpoint on this logical device.
  */
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(request->resource->device);
  oc_string_t ep, uri;
  memset(&uri, 0, sizeof(oc_string_t));
  while (eps != NULL) {
    if ((interface_index == -1 || eps->interface_index == interface_index) &&
        !(eps->flags & SECURED) && (eps->flags == conn)) {
      if (oc_endpoint_to_string(eps, &ep) == 0) {
        oc_concat_strings(&uri, oc_string(ep), "/oc/introspection");
        oc_free_string(&ep);
        break;
      }
    }
    eps = eps->next;
  }

  if (oc_string_len(uri) <= 0) {
    OC_ERR("could not obtain introspection resource uri");
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
    return;
  }

  oc_rep_start_root_object();

  switch (iface_mask) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_array(root, urlInfo);
    oc_rep_object_array_start_item(urlInfo);
    oc_rep_set_text_string(urlInfo, protocol, "coap");
    oc_rep_set_text_string(urlInfo, url, oc_string(uri));
    oc_rep_object_array_end_item(urlInfo);
    oc_rep_close_array(root, urlInfo);
  } break;
  default:
    break;
  }

  oc_rep_end_root_object();
  oc_send_response(request, OC_STATUS_OK);

  OC_DBG("got introspection resource uri %s", oc_string(uri));
  oc_free_string(&uri);
}

void
oc_create_introspection_resource(size_t device)
{
  OC_DBG("oc_introspection: Initializing introspection resource");

  oc_core_populate_resource(
    OCF_INTROSPECTION_WK, device, "oc/wk/introspection",
    OC_IF_R | OC_IF_BASELINE, OC_IF_R, OC_SECURE | OC_DISCOVERABLE,
    oc_core_introspection_wk_handler, 0, 0, 0, 1, "oic.wk.introspection");
  oc_core_populate_resource(OCF_INTROSPECTION_DATA, device, "oc/introspection",
                            OC_IF_BASELINE, OC_IF_BASELINE, 0,
                            oc_core_introspection_data_handler, 0, 0, 0, 1,
                            "oic.introspection.data");
}

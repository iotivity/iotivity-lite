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

#define MAX_FILENAME_LENGTH 128

#ifdef OC_IDD_FILE

#define MAX_TAG_LENGTH 20

static void
gen_idd_tag(const char *name, int device_index, char *idd_tag)
{
  int idd_tag_len =
    snprintf(idd_tag, MAX_TAG_LENGTH, "%s_%d", name, device_index);
  idd_tag_len =
    (idd_tag_len < MAX_TAG_LENGTH) ? idd_tag_len + 1 : MAX_TAG_LENGTH;
  idd_tag[idd_tag_len] = '\0';
}

int
get_IDD_filename(int device_index, char *filename)
{
  char idd_tag[MAX_TAG_LENGTH];
  gen_idd_tag("IDD", device_index, idd_tag);
  int ret = oc_storage_read(idd_tag, (uint8_t *)filename, MAX_FILENAME_LENGTH);
  PRINT("get_IDD_filename: oc_storage_read %d\n", ret);
  if (ret <= 0) {
    strcpy(filename, "server_introspection.dat");
  }
  PRINT("get_IDD_filename: returning %s\n", filename);
  return ret;
}

void
oc_set_introspection_file(int device, const char *filename)
{
  char idd_tag[MAX_TAG_LENGTH];
  gen_idd_tag("IDD", device, idd_tag);
  long ret =
    oc_storage_write(idd_tag, (uint8_t *)filename, MAX_FILENAME_LENGTH);
  if (ret == 0) {
    OC_ERR("oc_set_introspection_file: could not set %s in store\n", filename);
  }
}

long
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

size_t
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

int
get_IDD_filename(int index, char *filename)
{
  (void)index;
  (void)filename;
  return 0;
}

long
IDD_storage_size(const char *store)
{
  (void)store;
  return introspection_data_size;
}

size_t
IDD_storage_read(const char *store, uint8_t *buf, size_t size)
{
  (void)store;
  memcpy(buf, introspection_data, size);
  return size;
}

#endif /*OC_IDD_FILE*/

static void
oc_core_introspection_data_handler(oc_request_t *request,
                                   oc_interface_mask_t interface, void *data)
{
  (void)interface;
  (void)data;

  OC_DBG("in oc_core_introspection_data_handler");

  int index = request->resource->device;
  char filename[MAX_FILENAME_LENGTH];
  long filesize;

  get_IDD_filename(index, filename);

  filesize = IDD_storage_size(filename);
  if (filesize < OC_MAX_APP_DATA_SIZE) {
    IDD_storage_read(filename, request->response->response_buffer->buffer,
                     filesize);
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
                                 oc_interface_mask_t interface, void *data)
{
  (void)data;

  int interface_index =
    (request->origin) ? request->origin->interface_index : -1;
  /* We are interested in only a single coap:// endpoint on this logical device.
  */
  oc_endpoint_t *eps = oc_connectivity_get_endpoints(request->resource->device);
  oc_string_t ep, uri;
  memset(&uri, 0, sizeof(oc_string_t));
  while (eps != NULL) {
    if ((interface_index == -1 || eps->interface_index == interface_index) &&
        !(eps->flags & SECURED)) {
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

  switch (interface) {
  case OC_IF_BASELINE:
    oc_process_baseline_interface(request->resource);
  /* fall through */
  case OC_IF_R: {
    oc_rep_set_array(root, urlInfo);
    oc_rep_object_array_start_item(urlInfo);
    oc_rep_set_text_string(urlInfo, content - type, "application/cbor");
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
oc_create_introspection_resource(int device)
{
  OC_DBG("oc_introspection: Initializing introspection resource");

  oc_core_populate_resource(OCF_INTROSPECTION_WK, device, "oc/wk/introspection",
                            OC_IF_R | OC_IF_BASELINE, OC_IF_R, OC_DISCOVERABLE,
                            oc_core_introspection_wk_handler, 0, 0, 0, 1,
                            "oic.wk.introspection");
  oc_core_populate_resource(OCF_INTROSPECTION_DATA, device, "oc/introspection",
                            OC_IF_BASELINE, OC_IF_BASELINE, 0,
                            oc_core_introspection_data_handler, 0, 0, 0, 1,
                            "oic.introspection.data");
}

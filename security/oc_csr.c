/*
// Copyright (c) 2018-2019 Intel Corporation
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

#ifdef OC_SECURITY
#ifdef OC_PKI

#include "oc_csr.h"
#include "oc_api.h"
#include "oc_certs.h"
#include "oc_core_res.h"

static oc_separate_response_t csr_response;

struct csr_callback_params
{
  size_t device;
  oc_interface_mask_t iface_mask;
};

oc_event_callback_retval_t generate_csr(void *data)
{
  if (csr_response.active)
  {
    struct csr_callback_params *params = data;
    size_t device = params->device;
    unsigned char csr = malloc(4096);

    oc_set_separate_response_buffer(&csr_response);

    if (!csr) {
      oc_send_separate_response(&csr_response, OC_STATUS_INTERNAL_SERVER_ERROR);
      free(params);
      free(csr);
      return OC_EVENT_DONE;
    }

    int ret = oc_certs_generate_csr(device, csr, OC_PDU_SIZE);

    if (ret != 0) {
      oc_send_separate_response(&csr_response, OC_STATUS_INTERNAL_SERVER_ERROR);
      free(params);
      free(csr);
      return OC_EVENT_DONE;
    }

    oc_rep_start_root_object();
    if (params->iface_mask & OC_IF_BASELINE) {
      oc_process_baseline_interface(
        oc_core_get_resource_by_index(OCF_SEC_CSR, device));
    }
    oc_rep_set_text_string(root, csr, (const char *)csr);
    oc_rep_set_text_string(root, encoding, "oic.sec.encoding.pem");
    oc_rep_end_root_object();

    oc_send_separate_response(&csr_response, OC_STATUS_OK);
    free(params);
  }
  return OC_EVENT_DONE;
}

void
get_csr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  oc_indicate_separate_response(request, &csr_response);
  struct csr_callback_params *params = malloc(sizeof(struct csr_callback_params));
  params->device = request->resource->device;
  params->iface_mask = iface_mask;
  oc_set_delayed_callback(params, generate_csr, 1);
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

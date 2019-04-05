/*
// Copyright (c) 2018 Intel Corporation
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

void
get_csr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)iface_mask;
  (void)data;

  size_t device = request->resource->device;

#ifdef OC_DYNAMIC_ALLOCATION
  unsigned char *csr =
    (unsigned char *)calloc(OC_PDU_SIZE, sizeof(unsigned char));
  if (!csr) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    return;
  }
#else  /* OC_DYNAMIC_ALLOCATION */
  unsigned char csr[OC_PDU_SIZE];
#endif /* !OC_DYNAMIC_ALLOCATION */

  int csr_len = oc_certs_generate_csr(device, csr, OC_PDU_SIZE);
  if (csr_len < 0) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
#ifdef OC_DYNAMIC_ALLOCATION
    free(csr);
#endif /* OC_DYNAMIC_ALLOCATION */
    return;
  }

  oc_rep_start_root_object();
  oc_process_baseline_interface(
    oc_core_get_resource_by_index(OCF_SEC_CSR, device));
  oc_rep_set_byte_string(root, csr, csr, csr_len);
  oc_rep_set_text_string(root, encoding, "oic.sec.encoding.der");
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);

#ifdef OC_DYNAMIC_ALLOCATION
  free(csr);
#endif /* OC_DYNAMIC_ALLOCATION */
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */

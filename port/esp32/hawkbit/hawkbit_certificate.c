/****************************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
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
 ****************************************************************************/

#include "util/oc_features.h"

#if defined(OC_SECURITY) || defined(OC_PKI)

#include "hawkbit_certificate.h"
#include "oc_cred.h"
#include "security/oc_cred_util_internal.h"

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#define HAWKBIT_PEM_BUFFER_SIZE (2048)

static bool
certificate_is_CA(const oc_sec_cred_t *cred, void *user_data)
{
  (void)user_data;
  return cred->credusage == OC_CREDUSAGE_TRUSTCA ||
         cred->credusage == OC_CREDUSAGE_MFG_TRUSTCA;
}

static long
hawkbit_certificate_get_CA_pem(size_t device, char *buffer, size_t buffer_size)
{
  oc_sec_creds_t *creds = oc_sec_get_creds(device);
  if (creds == NULL) {
    return -1;
  }
  long pem_size = oc_cred_serialize(creds->creds, certificate_is_CA, NULL,
                                    buffer, buffer_size);

  if (pem_size < 0 || buffer == NULL) {
    return pem_size;
  }
  if ((size_t)pem_size == buffer_size) {
    return -1;
  }
  buffer[(size_t)pem_size] = '\0';
  return pem_size;
}

long
hawkbit_certificate_get_CA(size_t device, hawkbit_buffer_t *hb)
{
#ifdef OC_DYNAMIC_ALLOCATION
  long pem_size = hawkbit_certificate_get_CA_pem(device, NULL, 0);
  if (pem_size < 0) {
    return -1;
  }
  if (!hawkbit_buffer_init(hb, pem_size + 1)) { // +1 for nul-terminator
    return -1;
  }
#else  /* !OC_DYNAMIC_ALLOCATION */
  hawkbit_buffer_init(hb, HAWKBIT_PEM_BUFFER_SIZE);
#endif /* OC_DYNAMIC_ALLOCATION */
  long ret =
    hawkbit_certificate_get_CA_pem(device, hb->buffer, hawkbit_buffer_size(hb));
  if (ret < 0) {
    hawkbit_buffer_free(hb);
    return -1;
  }
  return ret;
}

#endif /* OC_SECURITY || OC_PKI */

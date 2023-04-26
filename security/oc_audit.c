/****************************************************************************
 *
 * Copyright (c) 2016-2019 Intel Corporation
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#ifdef OC_SECURITY

#include "oc_audit.h"
#include "oc_ael.h"
#include "port/oc_log_internal.h"
#include <stdbool.h>
#include <stdlib.h>

void
oc_audit_log(size_t device, const char *aeid, const char *message,
             uint8_t category, uint8_t priority, const char **aux,
             size_t aux_len)
{
  bool ret =
    oc_sec_ael_add(device, category, priority, aeid, message, aux, aux_len);
#if OC_DBG_IS_ENABLED
  OC_DBG("audit_log: %s %s %u %u; status = %d", aeid, message, category,
         priority, ret);
#else  /* !OC_DBG_IS_ENABLED */
  (void)ret;
#endif /* OC_DBG_IS_ENABLED */
}

#endif /* OC_SECURITY */

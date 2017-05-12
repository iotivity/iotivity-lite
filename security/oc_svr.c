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

#ifdef OC_SECURITY

#include "oc_svr.h"
#include "oc_acl.h"
#include "oc_api.h"
#include "oc_core_res.h"
#include "oc_cred.h"
#include "oc_doxm.h"
#include "oc_pstat.h"
#include "oc_ri.h"
#include "port/oc_log.h"

// Multiple devices?
// What methods do sec resources support

/* check resource properties */
void
oc_sec_create_svr(void)
{
  oc_core_populate_resource(OCF_SEC_DOXM, 0, "/oic/sec/doxm", OC_IF_BASELINE,
                            OC_IF_BASELINE, OC_SECURE | OC_DISCOVERABLE,
                            get_doxm, 0, post_doxm, 0, 1, "oic.r.doxm");
  oc_core_populate_resource(OCF_SEC_PSTAT, 0, "/oic/sec/pstat", OC_IF_BASELINE,
                            OC_IF_BASELINE, OC_SECURE | OC_DISCOVERABLE, get_pstat, 0, post_pstat,
                            0, 1, "oic.r.pstat");
  oc_core_populate_resource(OCF_SEC_ACL, 0, "/oic/sec/acl", OC_IF_BASELINE,
                            OC_IF_BASELINE, OC_SECURE, get_acl, 0, post_acl,
                            delete_acl, 1, "oic.r.acl");
  oc_core_populate_resource(OCF_SEC_CRED, 0, "/oic/sec/cred", OC_IF_BASELINE,
                            OC_IF_BASELINE, OC_SECURE, get_cred, 0, post_cred,
                            delete_cred, 1, "oic.r.cred");
}

#endif /* OC_SECURITY */

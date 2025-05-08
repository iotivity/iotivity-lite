/****************************************************************************
 *
 * Copyright (c) 2023 Daniel Adam, All Rights Reserved.
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

#ifndef OC_CLOUD_RESOURCE_INTERNAL_H
#define OC_CLOUD_RESOURCE_INTERNAL_H

#include "api/oc_helpers_internal.h"
#include "oc_cloud.h"
#include "oc_ri.h"
#include "oc_uuid.h"
#include "util/oc_compiler.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OCF_COAPCLOUDCONF_URI "/CoapCloudConfResURI"
#define OCF_COAPCLOUDCONF_RT "oic.r.coapcloudconf"
#define OCF_COAPCLOUDCONF_IF_MASK (OC_IF_RW | OC_IF_BASELINE)
#define OCF_COAPCLOUDCONF_DEFAULT_IF (OC_IF_RW)

/// Default cis value from OCF Device to Cloud Services Specification
#define OCF_COAPCLOUDCONF_DEFAULT_CIS "coaps+tcp://127.0.0.1"

/// Default sid value from OCF Device to Cloud Services Specification,
/// equivalent to "00000000-0000-0000-0000-000000000000"
#ifdef __cplusplus
#define OCF_COAPCLOUDCONF_DEFAULT_SID oc_uuid_t{ 0 }
#else /* !__cplusplus */
#define OCF_COAPCLOUDCONF_DEFAULT_SID (oc_uuid_t){ 0 }
#endif /* __cplusplus */

#define OCF_COAPCLOUDCONF_PROP_ACCESSTOKEN "at"
#define OCF_COAPCLOUDCONF_PROP_AUTHPROVIDER "apn"
#define OCF_COAPCLOUDCONF_PROP_CISERVER "cis"
#define OCF_COAPCLOUDCONF_PROP_CISERVERS "x.org.iotivity.servers"
#define OCF_COAPCLOUDCONF_PROP_SERVERID "sid"
#define OCF_COAPCLOUDCONF_PROP_LASTERRORCODE "clec"
#define OCF_COAPCLOUDCONF_PROP_PROVISIONINGSTATUS "cps"

#define OC_CPS_UNINITIALIZED_STR "uninitialized"
#define OC_CPS_READYTOREGISTER_STR "readytoregister"
#define OC_CPS_REGISTERING_STR "registering"
#define OC_CPS_REGISTERED_STR "registered"
#define OC_CPS_FAILED_STR "failed"
#define OC_CPS_DEREGISTERING_STR "deregistering"

/// Convert oc_cps_t to string
oc_string_view_t oc_cps_to_string(oc_cps_t cps);

/// Create CoAPCloudConf resource
void oc_create_cloudconf_resource(size_t device);

/// Encode CoAPCloudConf resource to global encoder
bool oc_cloud_encode(const oc_cloud_context_t *ctx) OC_NONNULL();

#ifdef __cplusplus
}
#endif

#endif /* OC_CLOUD_RESOURCE_INTERNAL_H */

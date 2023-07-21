/******************************************************************
 *
 * Copyright (c) 2023 plgd.dev s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef OC_CON_RESOURCE_INTERNAL_H
#define OC_CON_RESOURCE_INTERNAL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Although used several times in the OCF spec, "/oic/con" is not
   accepted by the spec. Use a private prefix instead. */
#define OC_CON_URI "/oc/con"
#define OC_CON_RT "oic.wk.con"
#define OC_CON_IF_MASK (OC_IF_RW | OC_IF_BASELINE)
#define OC_CON_DEFAULT_IF (OC_IF_RW)
#define OC_CON_PROPERTY_MASK (OC_DISCOVERABLE | OC_OBSERVABLE | OC_SECURE)

#define OC_CON_PROP_NAME "n"
#define OC_CON_PROP_LOCATION "locn"

/**
 * @brief Create the /oc/con resource
 *
 * @param device index of the device to which the resource will be added
 */
void oc_create_con_resource(size_t device);

#ifdef __cplusplus
}
#endif

#endif /* OC_CON_RESOURCE_INTERNAL_H */

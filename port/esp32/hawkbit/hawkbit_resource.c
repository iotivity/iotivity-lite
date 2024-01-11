
/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
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

#include "debug_print.h"
#include "hawkbit_context.h"
#include "hawkbit.h"

#include "oc_api.h"
#include "oc_cloud.h"
#include "oc_ri.h"

static void
hawkbit_resource_get(oc_request_t *request, oc_interface_mask_t interface,
                     void *user_data)
{
  (void)user_data;
  APP_DBG("GET hawkbit:");
  if (request->resource == NULL) {
    APP_ERR("resource not set");
    return;
  }
  hawkbit_context_t *ctx = hawkbit_get_context(request->resource->device);
  hawkbit_encode(ctx, request->resource, interface, false);
  oc_send_response(request, OC_STATUS_OK);
}

void
hawkbit_resource_register(size_t device)
{
  oc_resource_t *res = oc_new_resource("hawkbit", "/hawkbit", 1, device);
  oc_resource_bind_resource_type(res, "oic.r.hawkbit");
  oc_resource_bind_resource_interface(res, OC_IF_BASELINE | OC_IF_R);
  oc_resource_set_default_interface(res, OC_IF_R);
  oc_resource_set_discoverable(res, true);
  oc_resource_set_observable(res, true);
  oc_resource_set_request_handler(res, OC_GET, hawkbit_resource_get, NULL);
  oc_add_resource(res);
#ifdef OC_CLOUD
  oc_cloud_add_resource(res);
#endif /* OC_CLOUD */
}

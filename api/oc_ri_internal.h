/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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
 ***************************************************************************/

#ifndef OC_RI_INTERNAL_H
#define OC_RI_INTERNAL_H

#include "oc_ri.h"

/**
 * @brief removes the client callback. This is silent remove client without
 * trigger 'cb.handler'.
 *
 * @param cb is oc_client_cb_t* type
 * @return returns OC_EVENT_DONE
 */
oc_event_callback_retval_t oc_ri_remove_client_cb(void *cb);

/**
 * @brief removes the client callback with triggering
 * OC_REQUEST_TIMEOUT to handler.
 *
 * @param cb is oc_client_cb_t* type
 * @return returns OC_EVENT_DONE
 */
oc_event_callback_retval_t oc_ri_remove_client_cb_with_notify_503(void *cb);

#endif /* OC_RI_INTERNAL_H */

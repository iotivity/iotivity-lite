/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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

#ifndef ES_RESOURCE_HANDLER_H
#define ES_RESOURCE_HANDLER_H

#include "easysetup.h"

#ifdef __cplusplus
extern "C" {
#endif

es_result_e create_easysetup_resources(bool is_secured,
                                       es_resource_mask_e resource_mask,
                                       es_provisioning_callbacks_s callbacks);
void delete_easysetup_resources(void);
es_result_e set_device_property(es_device_property *device_property);
es_result_e set_enrollee_state(es_enrollee_state es_state);
es_result_e set_enrollee_err_code(es_error_code es_err_code);
es_result_e set_callback_for_userdata(es_read_userdata_cb readcb,
                                      es_write_userdata_cb writecb,
                                      es_free_userdata free_userdata);
void notify_connection_change(void);
#ifdef __cplusplus
}
#endif

#endif /* ES_RESOURCE_HANDLER_H */

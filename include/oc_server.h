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

#ifndef OC_SERVER_H
#define OC_SERVER_H

#include <stdio.h>
#include <stdint.h>
#include "port/oc_storage.h"
#include "port/oc_log.h"
#include "port/oc_connectivity.h"
#include "messaging/coap/oc_coap.h"
#include "oc_rep.h"
#include "oc_ri.h"
#include "oc_api.h"

void app_init(void);
void fetch_credentials(void);
void register_resources(void);

#endif /* OC_SERVER_H */

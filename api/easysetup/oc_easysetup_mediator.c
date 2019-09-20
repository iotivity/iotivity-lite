/****************************************************************************
 *
 * Copyright (c) 2019 Samsung Electronics
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specificlanguage governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
//#include "oc_helpers.h"
//#include "oc_rep.h"
//#include "oc_config.h"
#include "oc_easysetup_mediator.h"
//#include "oc_api.h"
//#include "oc_core_res.h"
//#include "oc_log.h"
//#include "es_utils.h"

#ifdef OC_WIFI_EASYSETUP
void oc_find_wes_resource()
{
}
void oc_get_wes_configuration()
{
}

// Update Enrollee Resources
void oc_set_wes_properties()
{
}
void oc_set_device_properties()
{
}
void oc_set_wifi_properties()
{
}
void oc_set_cloud_properties()
{
}
int oc_get_wifi_enrollee_status()
{
  return 0;
}

#endif // OC_WIFI_EASYSETUP

#ifdef OC_ESIM_EASYSETUP

void find_ees_enrollee_resource()
{
}
#endif // OC_ESIM_EASYSETUP
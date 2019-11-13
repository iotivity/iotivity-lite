/****************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics
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
#include "lpa.h"

int lpa_init(int reset)
{
  //Open I/O interface with eUICC
  //Reset eUICC memory is requested by application
  return 0;
}

// euicc_challenge : Output
int lpa_get_euicc_challenge(char *euicc_challenge)
{
  // Read eUICC chanllenge from eUICC
  return 0;
}

// euicc_info : Output
int lpa_get_euicc_info(char *euicc_info)
{
  char dummy[34] = "slo34jsk[alskdjfpasksassadjjaojsdo";
  // Read EUICCInfo2 from eUICC and fill euicc_info
  strncpy(euicc_info, dummy, sizeof(dummy));
  return 0;
}

// device_info : Input
// di_response : Output
int  lpa_get_device_info(DeviceInfo device_info, void *di_response)
{
  // Use CtxParamsForCommonAuthentication Request to get signed by eUICC
  return 0;
}

// activation_code : Input
// ac_response : Output
int lpa_authenticate_activation_code(char *activation_code, void *ac_response)
{
  // Use CtxParamsForCommonAuthentication Request to get signed by eUICC
  return 0;
}

// Dwnload Bound Profile package from SD-DP+
// Download the profile to eUICC
// Enable the profile
int  lpa_downalod_profile(void *di_response, char *euicc_challenge, 
	void *euicc_info, void *ac_response)
{
  // Initiate authentication with SMDP+
  // Authenitcate Client
  // Get Bound Profile Package
  // Update default SMDP+ address
  // Load Bound Profile package (transfer to eUICC)
  // Enable Profile on eUICC
  // Set Nick name to the profile
  return 0;
}

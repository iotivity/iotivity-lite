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

 #ifndef _LPA_H_
#define _LPA_H_

/*
  Device Info defined by SGP.22 RSP Technical specification
  DeviceInfo ::= SEQUENCE { tac Octet4, deviceCapabilities DeviceCapabilities, imei Octet8 OPTIONAL }
  Should be coded using ASN.1 DER

typedef struct DeviceInfoTag {
	unsigned char tac[4]; // Indicative TAC of Samsung Fold 5G
	unsigned char dev_cap[3]; // gsmSupportedRelease 13
	unsigned char imei[8]; // Indicative IMEI of Vodafone UK
} DeviceInfo;
DeviceInfo device_info =  {{0x35, 0x68, 0x46, 0x10},{13,0,0},{0x23, 0x42, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00}};
*/

typedef void (*ees_download_cb_t)(int);
typedef void (*ees_install_cb_t)(int);

// Initialize local profie assistant
int lpa_init(int reset);

int lpa_is_user_confirmation_required(void);

int lpa_read_profile_metadata(char *pm);

// Use GetEUICCInfo of SGP.22 RSP Technical specification
// euicc_info : Output
int lpa_read_euicc_info(char *euicc_info);

// Use CtxParamsForCommonAuthentication Request to get signed by eUICC
// di_response : Output
int lpa_read_device_info(char *di_response);

// Use CtxParamsForCommonAuthentication Request to get signed by eUICC
// activation_code : Input
void lpa_write_activation_code(char *activation_code);

// Download eUICC Profile
int  lpa_download_profile(ees_download_cb_t cbk);

// Install eUICC profile to eUICC module
int  lpa_install_profile(ees_install_cb_t cbk);

#endif //_LPA_H_

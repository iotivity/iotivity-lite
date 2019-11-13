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
#include <stdio.h>
#include <string.h>
#include "lpa.h"

int lpa_init(int reset)
{
  (void)reset;
  //Open I/O interface with eUICC
  //Reset eUICC memory is requested by application
  return 0;
}

/* 
SAMPLE EUICC INFO

EUICCInfo2 ::= { -- Tag 'BF22'
  profileVersion '020000'H, -- tag '81'
  svn '020201'H, -- tag '82'
  euiccFirmVer '410105'H, -- tag '83'
  extCardResource '810100820305494083021645'H, -- tag '84'
  uiccCapability '057F36E0'H, -- tag '85'
  ts102241Version '090200'H, -- tag '86'
  globalplatformVersion '020300'H, -- tag '87'
  rspCapability '0490'H, -- tag '88'
  euiccCiPKIdListForVerification {'665A1433D67C1A2C5DB8B52C967F10A057BA5CB2'H} -- tag 'A9'
  euiccCiPKIdListForSigning {'665A1433D67C1A2C5DB8B52C967F10A057BA5CB2'H}, -- tag 'AA'
  euiccCategory mediumEuicc, -- tag '8B'
  ppVersion '010000'H, -- tag 04
  sasAcreditationNumber "31303030303030303030303030303030" -- tag 0C
}

# ASN.1 DER encoding:
BF227B810302000082030202018303410105840C8101008203054940830216458504057F36E
08603090200870302030088020490A9160414665A1433D67C1A2C5DB8B52C967F10A057BA5
CB2AA160414665A1433D67C1A2C5DB8B52C967F10A057BA5CB28B010204030100000C1031
303030303030303030303030303030

# JSON base64 encoding:
vyJ7gQMCAACCAwICAYMDQQEFhAyBAQCCAwVJQIMCFkWFBAV/NuCGAwkCAIcDAgMAiAIEkK
kWBBRmWhQz1nwaLF24tSyWfxCgV7pcsqoWBBRmWhQz1nwaLF24tSyWfxCgV7pcsosBAgQDA
QAADBAxMDAwMDAwMDAwMDAwMDAw
*/

char g_euicc_info[] = "BF227B810302000082030202018303410105840C81010082030549 \
40830216458504057F36E08603090200870302030088020490A9160414665A1433D67C1A2C \
5DB8B52C967F10A057BA5CB2AA160414665A1433D67C1A2C5DB8B52C967F10A057BA5CB28 \
B010204030100000C1031303030303030303030303030303030";

int
lpa_read_euicc_info(char *euicc_info)
{
  // provide dummy euicc info for testing
  strncpy(euicc_info, g_euicc_info, sizeof(g_euicc_info));
  return 0;
}

/* 
SAMPLE EUICC INFO

# ASN.1 notation:
deviceInfo ::= 
{
  tac '12345678'H,
  deviceCapabilities {
    gsmSupportedRelease '010203'H,
    utranSupportedRelease '020304'H,
    cdma2000onexSupportedRelease '030405'H,
    cdma2000hrpdSupportedRelease '040506'H,
    cdma2000ehrpdSupportedRelease '050607'H,
    eutranSupportedRelease '060708'H,
    contactlessSupportedRelease '070809'H
    rspCrlSupportedVersion '08090A'H
}

# ASN.1 DER encoding:
A030800412345678A1288003010203810302030482030304058303040506840305060785030607088603070809870308090A

# JSON w/ base64 encoding:
oDCABBI0VnihKIADAQIDgQMCAwSCAwMEBYMDBAUGhAMFBgeFAwYHCIYDBwgJhwMICQo=
*/

char g_device_info[] = "A030800412345678A128800301020381030203048203030405830 \
3040506840305060785030607088603070809870308090A";

int
lpa_read_device_info(char *di_response)
{
  //Standard Procedure : Use CtxParamsForCommonAuthentication Request to get signed by eUICC

  // provide dummy device info for testing
  strncpy(di_response, g_device_info, sizeof(g_device_info));
  return 0;
}
char g_activation_code[] = "1$SMDP.GSMA.COM$04386-AGYFT-A74Y8-3F815$1.3.6.1.4.1.31746$1";
// activation_code : Input
int lpa_write_activation_code(char *activation_code)
{
  (void)activation_code;
  if(!strncmp(g_activation_code, activation_code, strlen(activation_code))) {
     // Activaiton code matched, return success
    return 1;
  }
  // Use CtxParamsForCommonAuthentication Request to get signed by eUICC

  return 0;
}

// Dwnload Bound Profile package from SD-DP+
// Download the profile to eUICC
// Enable the profile
int  lpa_downalod_profile(void *di_response, char *euicc_challenge, 
	void *euicc_info, void *ac_response)
{
  (void)di_response;
  (void)euicc_challenge;
  (void)euicc_info;
  (void)ac_response;
  // Initiate authentication with SMDP+
  // Authenitcate Client
  // Get Bound Profile Package
  // Update default SMDP+ address
  // Load Bound Profile package (transfer to eUICC)
  // Enable Profile on eUICC
  // Set Nick name to the profile
  return 0;
}

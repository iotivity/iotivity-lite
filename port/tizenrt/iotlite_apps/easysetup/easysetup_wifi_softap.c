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

#include <stdio.h>
#include <easysetup_wifi_softap.h>
#include <slsi_wifi/slsi_wifi_api.h>
#include <net/lwip/dhcp.h>
#include <net/lwip/netif.h>

static int g_wifi_state;
static struct netif *gnet_if;

char *softap_ssid = "IOTLITE";
char *softap_passwd = "12345678";
char *softap_security = "wpa2_aes";
int ch =  1;

static slsi_security_config_t *get_security_config_(char *sec_type, char *psk)
{
    slsi_security_config_t *ret = NULL;
    if (strncmp(SLSI_WIFI_SECURITY_OPEN,
                sec_type, sizeof(SLSI_WIFI_SECURITY_OPEN)) != 0 ) {
        ret = (slsi_security_config_t *)zalloc(sizeof(slsi_security_config_t));
        if (ret) {
            if (strncmp(SLSI_WIFI_SECURITY_WEP_OPEN,
                        sec_type, sizeof(SLSI_WIFI_SECURITY_WEP_OPEN)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WEP;
            } else if (strncmp(SLSI_WIFI_SECURITY_WEP_SHARED,
                        sec_type, sizeof(SLSI_WIFI_SECURITY_WEP_SHARED)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WEP_SHARED;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA_MIXED,
                        sec_type,sizeof(SLSI_WIFI_SECURITY_WPA_MIXED)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA_MIXED;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA_TKIP,
                        sec_type,sizeof(SLSI_WIFI_SECURITY_WPA_TKIP)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA_TKIP;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA_AES,
                        sec_type,sizeof(SLSI_WIFI_SECURITY_WPA_AES)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA_CCMP;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_MIXED,
                        sec_type,sizeof(SLSI_WIFI_SECURITY_WPA2_MIXED)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA2_MIXED;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_TKIP,
                        sec_type, sizeof(SLSI_WIFI_SECURITY_WPA2_TKIP)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA2_TKIP;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_AES,
                        sec_type, sizeof(SLSI_WIFI_SECURITY_WPA2_AES)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA2_CCMP;
            }
        }

        if(psk) {
            memcpy(ret->passphrase, psk, strlen(psk));
        } else {
            free(ret);
            ret = NULL;
        }
    }
    return ret;
}

static void linkUpHandler(slsi_reason_t* reason)
{
    g_wifi_state = WIFI_CONNECTED;
    printf("Connected to network\n");
}

static void linkDownHandler(slsi_reason_t* reason)
{
    if (reason) {
        printf("Disconnected from network reason_code: %d %s\n", reason->reason_code,
                reason->locally_generated ? "(locally_generated)": "");
    } else {
        printf("Disconnected from network\n");
    }
}

int es_create_softap(void)
{
    slsi_ap_config_t *app_settings = (slsi_ap_config_t *)zalloc(sizeof(slsi_ap_config_t));
    if(app_settings == NULL)
        return -1;
    g_wifi_state = WIFI_DISCONNECTED;

    memcpy(app_settings->ssid, (uint8_t *)softap_ssid, strlen((char *)softap_ssid));
    app_settings->ssid_len = strlen((char *)softap_ssid);
    app_settings->beacon_period = 100;
    app_settings->DTIM = 2;
    app_settings->channel = ch;
    app_settings->phy_mode = 1;
    //app_settings->security = get_security_config_(softap_security, softap_passwd);
    app_settings->security = NULL;

    printf("Starting AP mode...\n");
    if(WiFiStart(SLSI_WIFI_SOFT_AP_IF, app_settings)  == SLSI_STATUS_SUCCESS) {
      if (!WiFiRegisterLinkCallback(&linkUpHandler, &linkDownHandler)) {
          printf("Link call back handles registered - per default!\n");
      } else {
          printf("Link call back handles registered - status failed !\n");
      }
    } else {
        printf("WiFiStart AP mode failed !\n");
        return -1;
    }
    return 0;
}

int dhcpserver_start(void)
{   
    ip_addr_t ipaddr, netmask, gateway;
    gnet_if = netif_find(CTRL_IFNAME);

    if (gnet_if == NULL) {
        return -1;
    }

    // Setting static IP as 192.168.43.10 in AP mode
    ipaddr.addr = 0x0A2BA8C0;
    netmask.addr = 0x00FFFFFF;
    gateway.addr = 0x012FA8C0;
    netif_set_addr(gnet_if, &ipaddr, &netmask, &gateway);
    netif_set_up(gnet_if);    
    
    if (dhcps_start(gnet_if) != ERR_OK) {
        printf("DHCP Server - started Fail\n");
        return -1;
    }
    
    printf("DHCP Server - started Success\n");
    return 0;
}

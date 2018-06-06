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
#include <net/lwip/dhcp.h>
#include <net/lwip/prot/dhcp.h>
#include <net/lwip/netif.h>
#include "easysetup_wifi_softap.h"

static int g_wifi_state;
static struct netif *gnet_if;

char *softap_ssid = CONFIG_IOTLITE_SSID_SOFTAP;
char *softap_passwd = CONFIG_IOTLITE_PWD_SOFTAP;
char *softap_security = CONFIG_IOTLITE_SECURITY_SOFTAP;
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
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA_PSK,
                        sec_type, sizeof(SLSI_WIFI_SECURITY_WPA_PSK)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA2_MIXED;
            } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_PSK,
                        sec_type, sizeof(SLSI_WIFI_SECURITY_WPA2_PSK)) == 0) {
                ret->secmode = SLSI_SEC_MODE_WPA2_MIXED;
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

int wifi_start_station(void)
{
    int result = -1;
    printf("Starting STA mode...\n");

    g_wifi_state = WIFI_DISCONNECTED;

    if (WiFiStart(SLSI_WIFI_STATION_IF, NULL) == SLSI_STATUS_SUCCESS) {
        result = 0;
        if (!WiFiRegisterLinkCallback(&linkUpHandler, &linkDownHandler)) {
            printf("Link call back handles registered - per default!\n");
        } else {
            printf("Link call back handles registered - status failed !\n");
        }
    } else {
        printf("WiFiStart STA mode failed !\n");
    }

    return result;
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
    app_settings->security = get_security_config_(softap_security, softap_passwd);

    printf("Starting AP mode...\n");
    if(WiFiStart(SLSI_WIFI_SOFT_AP_IF, app_settings)  == SLSI_STATUS_SUCCESS) {
      if (!WiFiRegisterLinkCallback(&linkUpHandler, &linkDownHandler)) {
          printf("Link call back handles registered - per default!\n");
      } else {
          printf("Link call back handles registered - status failed !\n");
      }
    } else {
        printf("WiFiStart AP mode failed !\n");
        free(app_settings->security);
        return -1;
    }

    free(app_settings->security);
    return 0;
}

int wifi_join(char *ssid, char *security, char *passwd)
{
    slsi_security_config_t *security_config;

    uint8_t ssid_len = strlen((char *)ssid);

    security_config = get_security_config_(security, passwd);
    printf("Joining selected network...\n");

    if (WiFiNetworkJoin((uint8_t *)ssid, ssid_len, NULL, security_config) != 0) {
        printf("SLSI_WiFiNetworkJoin start failed!\n");
        if (security_config) {
            free(security_config);
            security_config = NULL;
        }
        return -1;
    } else {
        printf("WiFiNetworkJoin start success!\n");
        if (security_config) {
            free(security_config);
            security_config = NULL;
        }
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

int dhcpc_start(void)
{
    gnet_if = netif_find(CTRL_IFNAME);

    if (gnet_if == NULL) {
        return -1;
    }

    if (gnet_if->dhcp != NULL){
        gnet_if->dhcp = NULL;
    }

    printf( "netic hwaddr_len %d\n"
            "netic hwaddr %x%x%x%x%x%x\n"
            "netic mtu %d\n"
            "netic flags %x\n",
            gnet_if->hwaddr_len,
            gnet_if->hwaddr[0], gnet_if->hwaddr[1], gnet_if->hwaddr[2],
            gnet_if->hwaddr[3], gnet_if->hwaddr[4], gnet_if->hwaddr[5],
            gnet_if->mtu, gnet_if->flags);

    err_t res = dhcp_start(gnet_if);

    if (res) {
        printf("slsi_start_dhcp dhcp_start result %d\n", res);
        return -1;
    }

    printf("slsi_start_dhcp start success state %d result %d\n",
            gnet_if->dhcp->state, res);

    int32_t timeleft = 5000000;

    while (gnet_if->dhcp->state != DHCP_STATE_BOUND) {
        usleep(10000);
        timeleft -= 10000;
        if (timeleft <= 0)
            break;
    }
    if (gnet_if->dhcp->state == DHCP_STATE_BOUND) {
        printf("DHCP Client - got IP address %u.%u.%u.%u\n",
                (unsigned char) ((htonl(gnet_if->ip_addr.addr) >> 24) & 0xff),
                (unsigned char) ((htonl(gnet_if->ip_addr.addr) >> 16) & 0xff),
                (unsigned char) ((htonl(gnet_if->ip_addr.addr) >> 8) & 0xff),
                (unsigned char) ((htonl(gnet_if->ip_addr.addr) >> 0) & 0xff));
    } else {
        if (timeleft <= 0) {
            printf("DHCP Client - Timeout fail to get ip address\n");
            return -1;
        }
    }

    return 0;
}

int stop_dhcp(int interface)
{
    ip_addr_t ipaddr;

    if (gnet_if == NULL) {
        printf("stop_dhcp - nothing to stop\n");
        return 0;
    }

    if (interface == SLSI_WIFI_STATION_IF) {
        if (gnet_if->dhcp != NULL) {
            dhcp_stop(gnet_if);
            printf("dhcp client stop!!");
        } else {
            return -1;
        }
    } else if (interface == SLSI_WIFI_SOFT_AP_IF) {
        if (gnet_if->dhcps_pcb != NULL) {
            dhcps_stop(gnet_if);
            printf("dhcp server stop!!");

            ipaddr.addr = 0;
            netif_set_ipaddr(gnet_if, &ipaddr);
        } else {
            return -1;
        }
    }

    gnet_if = NULL;
    return 0;
}

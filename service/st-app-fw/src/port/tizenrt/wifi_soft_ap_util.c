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

#include "wifi_soft_ap_util.h"

#include <net/lwip/dhcp.h>
#include <net/lwip/netif.h>

#define DHCP_BOUND 10
static int g_wifi_state;
static struct netif *gnet_if;

static slsi_security_config_t *
es_get_security_config(const char *sec_type, const char *psk)
{
  slsi_security_config_t *ret = NULL;
  if (strncmp(SLSI_WIFI_SECURITY_OPEN, sec_type,
              sizeof(SLSI_WIFI_SECURITY_OPEN)) != 0) {
    ret = (slsi_security_config_t *)zalloc(sizeof(slsi_security_config_t));
    if (ret) {
      if (strncmp(SLSI_WIFI_SECURITY_WEP_OPEN, sec_type,
                  sizeof(SLSI_WIFI_SECURITY_WEP_OPEN)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WEP;
      } else if (strncmp(SLSI_WIFI_SECURITY_WEP_SHARED, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WEP_SHARED)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WEP_SHARED;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA_MIXED, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA_MIXED)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA_MIXED;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA_TKIP, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA_TKIP)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA_TKIP;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA_AES, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA_AES)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA_CCMP;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_MIXED, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA2_MIXED)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA2_MIXED;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_TKIP, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA2_TKIP)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA2_TKIP;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_AES, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA2_AES)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA2_CCMP;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA_PSK, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA_PSK)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA2_MIXED;
      } else if (strncmp(SLSI_WIFI_SECURITY_WPA2_PSK, sec_type,
                         sizeof(SLSI_WIFI_SECURITY_WPA2_PSK)) == 0) {
        ret->secmode = SLSI_SEC_MODE_WPA2_MIXED;
      }
    }

    if (psk) {
      memcpy(ret->passphrase, psk, strlen(psk));
    } else {
      free(ret);
      ret = NULL;
    }
  }
  return ret;
}

static void
linkUpHandler(slsi_reason_t *reason)
{
  g_wifi_state = WIFI_CONNECTED;
  printf("Connected to network\n");
}

static void
linkDownHandler(slsi_reason_t *reason)
{
  if (reason) {
    printf("Disconnected from network reason_code: %d %s\n",
           reason->reason_code,
           reason->locally_generated ? "(locally_generated)" : "");
  } else {
    printf("Disconnected from network\n");
  }
}

int
wifi_start_station(void)
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

int
es_create_softap(const char *ssid, const char *passwd)
{
  if (!ssid || !passwd) {
    return -1;
  }
  printf("es_create_softap in\n");
  slsi_ap_config_t *app_settings =
    (slsi_ap_config_t *)zalloc(sizeof(slsi_ap_config_t));
  if (app_settings == NULL)
    return -1;
  g_wifi_state = WIFI_DISCONNECTED;

  // SSID Format: <device name>_E1<MNID><onboarding id>0<last 2 segments of mac>
  // device name - is as per device name (refer st_main.c)
  // MNID and onboarding id - you get from s-devworkspace

  char *es_softap_ssid = ssid;
  char *es_softap_passphrase = passwd;
  char *es_softap_security = CONFIG_IOTLITE_SECURITY_SOFTAP;

  printf("SoftAP SSID : %s\n", es_softap_ssid);

  memcpy(app_settings->ssid, (uint8_t *)es_softap_ssid, strlen(es_softap_ssid));
  app_settings->ssid_len = strlen(es_softap_ssid);
  app_settings->beacon_period = 100;
  app_settings->DTIM = 2;
  app_settings->channel = 1;
  app_settings->phy_mode = 1;
  app_settings->security =
    es_get_security_config(es_softap_security, es_softap_passphrase);

  printf("Starting AP mode...\n");
  if (WiFiStart(SLSI_WIFI_SOFT_AP_IF, app_settings) == SLSI_STATUS_SUCCESS) {
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

  printf("es_create_softap out\n");
  return 0;
}

void
es_stop_softap(void)
{
  printf("es_stop_softap in\n");
  stop_dhcp(SLSI_WIFI_SOFT_AP_IF);
  printf("es_stop_softap out\n");
}

int
wifi_join(const char *ssid, const char *security, const char *passwd)
{
  printf("wifi_join in\n");
  int ret;
  slsi_security_config_t *security_config;

  uint8_t ssid_len = strlen((char *)ssid);

  security_config = es_get_security_config(security, passwd);
  printf("Joining selected network...\n");

  ret = WiFiNetworkJoin((uint8_t *)ssid, ssid_len, NULL, security_config);
  if (ret != 0) {
    printf("SLSI_WiFiNetworkJoin start failed, ret = %d!\n", ret);
    return -1;
  } else {
    printf("WiFiNetworkJoin start success!\n");
  }

  if (security_config) {
    free(security_config);
    security_config = NULL;
  }

  printf("wifi_join out\n");
  return ret;
}

int
dhcpserver_start(void)
{
  printf("dhcpserver_start in\n");
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

  printf("dhcpserver_start out: start success\n");
  return 0;
}

int
dhcpc_start(void)
{
  printf("dhcpc_start in\n");
  gnet_if = netif_find(CTRL_IFNAME);

  if (gnet_if == NULL) {
    return -1;
  }

  if (gnet_if->dhcp != NULL) {
    gnet_if->dhcp = NULL;
  }

  printf("netic hwaddr_len %d\n"
         "netic hwaddr %x%x%x%x%x%x\n"
         "netic mtu %d\n"
         "netic flags %x\n",
         gnet_if->hwaddr_len, gnet_if->hwaddr[0], gnet_if->hwaddr[1],
         gnet_if->hwaddr[2], gnet_if->hwaddr[3], gnet_if->hwaddr[4],
         gnet_if->hwaddr[5], gnet_if->mtu, gnet_if->flags);

  err_t res = dhcp_start(gnet_if);

  if (res) {
    printf("slsi_start_dhcp dhcp_start result %d\n", res);
    return -1;
  }
  printf("dhcpc_start out\n");
  return 0;
}

int
stop_dhcp(int interface)
{
  printf("stop_dhcp in\n");
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
  printf("stop_dhcp out\n");
  return 0;
}

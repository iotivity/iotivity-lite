
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
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#ifdef LIB_DBUS_GLIB
#include <gio/gio.h>
#include <glib.h>
#endif
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "port/oc_log.h"
#include "wifi.h"

#ifdef LIB_DBUS_GLIB
#define SUPPLICANT_PROP_INTERFACE "org.freedesktop.DBus.Properties"
#define SUPPLICANT_SERVICE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH "/fi/w1/wpa_supplicant1"
#define WIRELESS_CTRL_INTF_PATH "/sys/class/net"

#define PID_DIRECTORY "/var/run"

#define DNSMASQ_LEASES_FILE "/var/lib/misc/dnsmasq.leases"

#define DHCLIENT_CONF_LEN 1024
#define DHCLIENT_LEASES_FILE "/var/lib/dhcp/dhclient.leases"
#define DHCLIENT_CONF_FILE "/etc/dhclient.conf"
#define DHCLIENT_CONF "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8; \n" \
                      "send host-name \"%s\";\n" \
                      "request subnet-mask, broadcast-address, time-offset, routers," \
                      "domain-name, domain-name-servers, domain-search, host-name," \
                      "dhcp6.name-servers, dhcp6.domain-search," \
                      "netbios-name-servers, netbios-scope, interface-mtu," \
                      "rfc3442-classless-static-routes, ntp-servers;\n"

static char *g_iface;
static char *g_network;
static GDBusConnection *g_connection;

static int dnsmasq_pid = 0;
static int dhclient_pid = 0;

static int
supplicant_gdbus_method_call_sync(GDBusConnection *connection,
                                  char *service,
                                  char *object_path,
                                  char *iface,
                                  char *method,
                                  GVariant *parameter,
                                  GVariant **reply) {
   g_autoptr(GError) error = NULL;
   if (!connection)
     return -EINVAL;

   *reply = g_dbus_connection_call_sync(connection,
                                        service,
                                        object_path,
                                        iface,
                                        method,
                                        parameter,
                                        NULL,
                                        G_DBUS_CALL_FLAGS_NONE,
                                        1000,
                                        NULL,
                                        &error);
   if (error) {
      OC_ERR("Error while sending dbus method call %s\n", error->message);
      return error->code;
   }
   return 0;
}

static int
supplicant_get_wireless_interface(char **ctrl_ifname) {
  struct dirent *dent;

  DIR *dir = opendir(WIRELESS_CTRL_INTF_PATH);
  if (dir) {
    while ((dent = readdir (dir)) != NULL) {
      if (dent->d_name[0] == 'w' && dent->d_name[1] == 'l') {
        *ctrl_ifname = strdup(dent->d_name);
        OC_DBG("Wireless interface: %s", *ctrl_ifname);
        closedir(dir);
        return 0;
      }
    }
    closedir(dir);
  }
  return -ENOENT;
}

static int
supplicant_create_interface(GDBusConnection *connection, char *ctrl_ifname, char **iface) {
  int ret;
  GVariant *reply;
  GVariant *parameter;
  GVariantBuilder *builder;

  builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
  g_variant_builder_add(builder, "{sv}", "Ifname", g_variant_new_string(ctrl_ifname));
  parameter = g_variant_builder_end(builder);
  g_variant_builder_unref(builder);

  ret = supplicant_gdbus_method_call_sync(connection,
                                          SUPPLICANT_SERVICE,
                                          SUPPLICANT_PATH,
                                          SUPPLICANT_INTERFACE,
                                          "CreateInterface",
                                          g_variant_new_tuple(&parameter, 1),
                                          &reply);
  if (ret) {
    OC_ERR("error while sending create interface method call: %d\n", ret);
    return -1;
  }

  g_variant_get(reply, "(&o)", iface);
  OC_DBG("WPA supplicant new interface:%s", *iface);
  return 0;
}

static int
supplicant_get_interface(GDBusConnection *connection, char *ctrl_ifname, char **iface) {
  int ret;
  GVariant *reply;

  ret = supplicant_gdbus_method_call_sync(connection,
                                          SUPPLICANT_SERVICE,
                                          SUPPLICANT_PATH,
                                          SUPPLICANT_INTERFACE,
                                          "GetInterface",
                                          g_variant_new("(s)", (const gchar *)ctrl_ifname),
                                          &reply);
  if (ret) {
     OC_ERR("error while sending get interface method call %d\n", ret);
     return -1;
  }
  g_variant_get(reply, "(&o)", iface);
  OC_DBG("WPA supplicant active interface:%s", *iface);
  return 0;
}

static int
supplicant_remove_interface(GDBusConnection *connection, char *iface) {
  int ret;
  GVariant *reply;

  ret = supplicant_gdbus_method_call_sync(connection,
                                          SUPPLICANT_SERVICE,
                                          SUPPLICANT_PATH,
                                          SUPPLICANT_INTERFACE,
                                          "RemoveInterface",
                                          g_variant_new("(o)", iface),
                                          &reply);
  if (ret) {
     OC_ERR("error while sending remove interface method call %d\n", ret);
     return -1;
  }
  return 0;
}

static int
supplicant_set_interface(GDBusConnection *connection, char *iface, int ap_scan) {
  int ret;
  GVariant *reply;

  ret = supplicant_gdbus_method_call_sync(connection,
                                          SUPPLICANT_SERVICE,
                                          iface,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Set",
                                          g_variant_new("(ssv)", SUPPLICANT_INTERFACE".Interface",
                                                        "ApScan", g_variant_new("u", ap_scan)),
                                          &reply);
  if (ret) {
    OC_ERR("error while updating ap_scan mode of the interface %d\n", ret);
    return -1;
  }
  return 0;
}

static int
supplicant_get_apscan(GDBusConnection *connection, char *iface, int *ap_scan) {
  int ret;
  GVariant *reply;
  GVariant *iter;

  ret = supplicant_gdbus_method_call_sync(connection,
                                          SUPPLICANT_SERVICE,
                                          iface,
                                          SUPPLICANT_PROP_INTERFACE,
                                          "Get",
                                          g_variant_new("(ss)", SUPPLICANT_INTERFACE".Interface",
                                                        "ApScan"),
                                          &reply);
  if (ret) {
    OC_ERR("error while fetching ap_scan mode of the interface %d\n", ret);
    return -1;
  }
  g_variant_get(reply, "(v)", &iter);
  g_variant_get(iter, "u", ap_scan);
  return 0;
}

static int
supplicant_variant_buidler(struct wpa_ssid *ssid, GVariant **parameter) {
   GVariantBuilder *builder;
   builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

   if (ssid == NULL) {
     OC_ERR("invalid wpa_ssid parameter\n");
     return -EINVAL;
   }

   g_variant_builder_add(builder, "{sv}", "ssid", g_variant_new_string(strdup(ssid->ssid)));
   g_variant_builder_add(builder, "{sv}", "mode", g_variant_new("u", ssid->mode));
   g_variant_builder_add(builder, "{sv}", "key_mgmt", g_variant_new_string(ssid->key_mgmt));
   g_variant_builder_add(builder, "{sv}", "psk", g_variant_new_string(strdup(ssid->psk)));

   *parameter = g_variant_builder_end(builder);
   g_variant_builder_unref(builder);
   return 0;
}

static int
supplicant_add_network(GDBusConnection *connection, char *iface, struct wpa_ssid *ssid) {
   GVariant *reply;
   GVariant *parameter;
   int ret;

   supplicant_variant_buidler(ssid, &parameter);
   ret = supplicant_gdbus_method_call_sync(connection,
                                           SUPPLICANT_SERVICE,
                                           iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "AddNetwork",
                                           g_variant_new_tuple(&parameter, 1),
                                           &reply);
    if (ret) {
      OC_ERR("error while sending add network method call %d\n", ret);
      return -1;
    }

    g_variant_get(reply, "(&o)", &g_network);
    OC_DBG("added new network %s", g_network);
    return 0;
}

static int
supplicant_remove_network(GDBusConnection *connection, char *iface) {
   GVariant *reply;
   int ret;

   ret = supplicant_gdbus_method_call_sync(connection,
                                           SUPPLICANT_SERVICE,
                                           iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "RemoveNetwork",
                                           g_variant_new("(o)", g_network),
                                           &reply);
  if (ret) {
    OC_ERR("error while removing network %d\n", ret);
    return -1;
  }
  return 0;
}

static int
supplicant_select_network(GDBusConnection *connection, char *iface) {
   GVariant *reply;
   GVariant *parameter;
   int ret;

   parameter = g_variant_new("o", g_network);
   ret = supplicant_gdbus_method_call_sync(connection,
                                           SUPPLICANT_SERVICE,
                                           iface,
                                           SUPPLICANT_INTERFACE".Interface",
                                           "SelectNetwork",
                                           g_variant_new_tuple(&parameter, 1),
                                           &reply);
   if (ret) {
     OC_ERR("error while sending select network method call: %d\n", ret);
     return -1;
   }
   return 0;
}

static int
supplicant_enable_network(GDBusConnection *connection) {
   GVariant *reply;
   int ret;

   ret = supplicant_gdbus_method_call_sync(connection,
                                           SUPPLICANT_SERVICE,
                                           g_network,
                                           SUPPLICANT_PROP_INTERFACE,
                                           "Set",
                                           g_variant_new("(ssv)", SUPPLICANT_INTERFACE".Network",
                                                         "Enabled", g_variant_new("b", true)),
                                           &reply);
    if (ret) {
      OC_ERR("error while enabling the network %d\n", ret);
      return -1;
    }
    return 0;
}

static int
supplicant_configure_interface(GDBusConnection *connection, char **iface, int mode) {
  char *ctrl_ifname;
  char *temp_interface;
  int ap_scan;
  int ret;

  ret = supplicant_get_wireless_interface(&ctrl_ifname);
  if (ret) {
    OC_ERR("unable to fetch wireless interface name %d\n", ret);
    return -1;
  }
  ret = supplicant_get_interface(connection, ctrl_ifname, &temp_interface);
  if (ret) {
    OC_ERR("unable to send get interface method call %d\n", ret);
    return -1;
  }
  *iface = temp_interface;

  supplicant_get_apscan(connection, *iface, &ap_scan);
  if (ap_scan == mode) {
    OC_DBG("already in required mode");
  }
  else {
    ret = supplicant_remove_interface(connection, *iface);
    if (ret) {
      OC_ERR("unable to send remove interface method call: %d\n", ret);
      return -1;
    }

    ret = supplicant_create_interface(connection, ctrl_ifname, &temp_interface);
    if (ret) {
      OC_ERR("unable to send get interface method call: %d\n", ret);
      return -1;
    }
    *iface = temp_interface;

    ret = supplicant_set_interface(connection, *iface, mode);
    if (ret) {
      OC_ERR("unable to send set interface method call: %d\n", ret);
      return -1;
    }
  }
  return 0;
}

static int
wifi_execute_command(const char *file_path, char *const args[], char *const envs[]) {
  int pid;
  int rv;
  errno = 0;

  pid = fork();
  switch (pid) {
    case -1:
           OC_ERR("fork failed");
           return -1;
    case 0:
           if (execve(file_path, args, envs) == -1) {
	     OC_ERR("failed to execute command (%s)", strerror(errno));
	     exit(1);
             return -1;
           }
           break;
    default:
           if (waitpid(pid, &rv, 0) == -1) {
             OC_ERR("wait pid (%u) rv (%d)", pid, rv);
           }
           break;
  }
  return pid;
}

int
wifi_start_station(void)
{
  if (!g_connection) {
    g_autoptr(GError) error = NULL;
    g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) {
      OC_ERR("failed to get gdbus connection %s\n", error->message);
      return -1;
    }
  }
  if (supplicant_configure_interface(g_connection, &g_iface, 1) == -1) {
    OC_ERR("failed to configure network while starting station mode\n");
    return -1;
  }
  return 0;
}

int
wifi_stop_station(void)
{
  if (supplicant_remove_network(g_connection, g_iface) == -1) {
    OC_ERR("failed to remove network while stopping station\n");
    return -1;
  }
  return 0;
}

int
wifi_start_softap(char *ssid_key, char *psk)
{
  struct wpa_ssid *ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));
  char *iface;
  if (!g_connection) {
    g_autoptr(GError) error = NULL;
    g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) {
      OC_ERR("failed to get gdbus connection %s\n", error->message);
      return -1;
    }
  }
  if (supplicant_configure_interface(g_connection, &iface, 2) == -1) {
    OC_ERR("failed to configure network while starting softAP mode\n");
    return -1;
  }

  snprintf(ssid->ssid, MAX_LEN_SSID, "%s", ssid_key);
  snprintf(ssid->psk, MAX_LEN_PSK, "%s", psk);
  ssid->mode = WPAS_MODE_AP;
  ssid->key_mgmt = "WPA-PSK";

  if (supplicant_add_network(g_connection, iface, ssid) == -1) {
    OC_ERR("failed to add network in SoftAP mode\n");
    return -1;
  }
  if (supplicant_select_network(g_connection, iface) == -1) {
    OC_ERR("failed to select network in SoftAP mode\n");
    return -1;
  }
  if (supplicant_enable_network(g_connection) == -1) {
    OC_ERR("failed to enable network in SoftAP mode\n");
    return -1;
  }
  return 0;
}

int
wifi_stop_softap()
{
  if (supplicant_remove_network(g_connection, g_iface) == -1) {
    OC_ERR("failed to remove network while stopping softAP\n");
    return -1;
  }
  return 0;
}

int
wifi_join(char *ssid_key, char *password)
{
  struct wpa_ssid *ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));
  snprintf(ssid->ssid, MAX_LEN_SSID, "%s", ssid_key);
  snprintf(ssid->psk, MAX_LEN_PSK, "%s", password);
  ssid->mode = WPAS_MODE_INFRA;
  ssid->key_mgmt = "WPA-PSK";
  if (supplicant_add_network(g_connection, g_iface, ssid) == -1) {
    OC_ERR("failed to add network while joining AP\n");
    return -1;
  }
  if (supplicant_select_network(g_connection, g_iface) == -1) {
    OC_ERR("failed to select network while joining AP\n");
    return -1;
  }
  if (supplicant_enable_network(g_connection) == -1) {
    OC_ERR("failed to enable network while joining AP\n");
    return -1;
  }
  return 0;
}

static
int wifi_fetch_pid(char *process_name)
{
  int max_pid_len = 32768;
  char line[max_pid_len];
  char command[100];

  snprintf(command, sizeof(command), "pidof %s", process_name);
  FILE *proc = popen(command, "r");
  if(fgets(line, max_pid_len, proc)) {
    pid_t pid = strtoul(line, NULL, 10);
    pclose(proc);
    return pid;
  }
  pclose(proc);
  return -1;
}

int
wifi_start_dhcp_client()
{
  FILE *fp = NULL;
  char buf[DHCLIENT_CONF_LEN] = "";
  char hostname[150];
  char *const args[] = {"/sbin/dhclient", "-cf", "/etc/dhclient.conf", NULL};
  char *const envs[] = { NULL };

  if (wifi_fetch_pid("dhclient")) {
    OC_DBG("DHclient is already running");
    return 0;
  }

  if (remove(DHCLIENT_LEASES_FILE) < 0) {
    OC_ERR("failed to remove %s", DHCLIENT_LEASES_FILE);
  }

  fp = fopen(DHCLIENT_CONF_FILE, "w");
  if (!fp) {
    OC_ERR("could not create the file\n");
    return -EINVAL;
  }

  gethostname(hostname, 150);
  snprintf(buf, DHCLIENT_CONF_LEN, DHCLIENT_CONF, hostname);
  fputs(buf, fp);
  fclose(fp);

  /* run Dhclient daemon */
  dhclient_pid = wifi_execute_command(args[0], &args[0], envs);
  if (dhclient_pid < 0) {
    OC_ERR("failed to start Dhclient %d\n", dhclient_pid);
    return -1;
  }
  dhclient_pid = wifi_fetch_pid("dhclient");
  return 0;
}

int
wifi_stop_dhcp_client()
{
  if(dhclient_pid == 0) {
    OC_ERR("DHCP client is not running\n");
    return -1;
  }

  kill(dhclient_pid, SIGTERM);
  waitpid(dhclient_pid, NULL, 0);
  dhclient_pid = 0;
  if(remove(DHCLIENT_CONF_FILE) < 0){
    OC_ERR("error in removing configuration file\n");
    return -1;
  }
  return 0;
}

int
wifi_start_dhcp_server()
{
  char *ctrl_ifname;
  char *const args_dns[] = {"/usr/sbin/dnsmasq", "-p0", "-F192.168.0.20,192.168.0.30", "-O3,192.168.0.1", NULL};
  char *const envs[] = { NULL };

  if (supplicant_get_wireless_interface(&ctrl_ifname)) {
    OC_ERR("unable to fetch the wireless interface\n");
    return -1;
  }
  /* Assigning IP address to the DHCP server host */
  char *const args_ip_flush[] = {"/sbin/ip", "addr", "flush", "dev", ctrl_ifname, NULL};
  char *const args_ip[] = {"/sbin/ip", "addr", "add", "192.168.0.20/24", "dev", ctrl_ifname, NULL};

  if (wifi_execute_command(args_ip_flush[0], &args_ip_flush[0], envs) < 0) {
    OC_ERR("unable to flush already assigned IP address\n");
    return -1;
  }
  if (wifi_execute_command(args_ip[0], &args_ip[0], envs) < 0) {
    OC_ERR("unable to assign IP address to the host\n");
    return -1;
  }

  if (wifi_fetch_pid("dnsmasq")) {
    OC_DBG("Dnsmasq is already running");
  }
  if (remove(DNSMASQ_LEASES_FILE) < 0) {
    OC_ERR("failed to remove %s", DNSMASQ_LEASES_FILE);
  }

  dnsmasq_pid = wifi_execute_command(args_dns[0], &args_dns[0], envs);
  if (dnsmasq_pid < 0) {
    OC_ERR("failed to start DHCP server %d\n", dnsmasq_pid);
    return -1;
  }
  dnsmasq_pid = wifi_fetch_pid("dnsmasq");
  return 0;
}

int
wifi_stop_dhcp_server()
{
  if (dnsmasq_pid == 0) {
    OC_ERR("no DHCP server is running\n");
    return -1;
  }

  kill(dnsmasq_pid, SIGTERM);
  waitpid(dnsmasq_pid, NULL, 0);
  dnsmasq_pid = 0;
  return 0;
}
#endif

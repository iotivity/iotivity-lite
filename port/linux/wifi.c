
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
#include <gio/gio.h>
#include <glib.h>
#include <dirent.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include "wifi.h"

#define SUPPLICANT_PROP_INTERFACE "org.freedesktop.DBus.Properties"
#define SUPPLICANT_SERVICE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE "fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH "/fi/w1/wpa_supplicant1"
#define WIRELESS_CTRL_INTF_PATH "/sys/class/net"

#define DNSMASQ_CONF_LEN 1024
#define DNSMASQ_LEASES_FILE "/var/lib/misc/dnsmasq.leases"
#define DNSMASQ_CONF_FILE "/etc/dnsmasq.conf"

#define MAX_HOSTNAME_LEN 150

#define DHCLIENT_CONF_LEN 1024
#define DHCLIENT_LEASES_FILE "/var/lib/dhcp/dhclient.leases"
#define DHCLIENT_CONF_FILE "/etc/dhclient.conf"
#define DHCLIENT_PID_DIRECTORY "/var/run"
#define DHCLIENT_CONF "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8; \n" \
                      "send host-name \"%s\";\n" \
                      "request subnet-mask, broadcast-address, time-offset, routers," \
                      "domain-name, domain-name-servers, domain-search, host-name," \
                      "dhcp6.name-servers, dhcp6.domain-search," \
                      "netbios-name-servers, netbios-scope, interface-mtu," \
                      "rfc3442-classless-static-routes, ntp-servers;\n"

static int dnsmasq_pid = 0;
static int dhclient_pid = 0;
static char *g_iface;
static char *g_network;
static GDBusConnection *g_connection;

static int
supplicant_gdbus_method_call_sync(GDBusConnection *connection,
                                  char *service, char *object_path, char *iface,
                                  char *method, GVariant *parameter, GVariant **reply)
{
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
    printf("Error while sending dbus method call, %s\n", error->message);
    return error->code;
  }
  return 0;
}

int
supplicant_get_wireless_interface(char **ctrl_ifname)
{
  int ret = -1;
  struct dirent *dent;

  DIR *dir = opendir(WIRELESS_CTRL_INTF_PATH);
  if (dir) {
    while ((dent = readdir (dir)) != NULL) {
      if (dent->d_name[0] == 'w' && dent->d_name[1] == 'l') {
        *ctrl_ifname = strdup(dent->d_name);
        ret = 0;
        printf("Wireless interface: %s\n", *ctrl_ifname);
        break;
      }
    }
    closedir(dir);
  } else {
    printf("Unable to open the wireless interface directory: %d\n", errno);
  }
  return ret;
}

static int
supplicant_create_interface(GDBusConnection *connection,
								char *ctrl_ifname, char **iface)
{
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
    printf("Error while sending create interface method: %d\n", ret);
    return ret;
  }
  g_variant_get(reply, "(&o)", iface);
  printf("Get Interface: %s\n", *iface);
  return 0;
}

static int
supplicant_get_interface(GDBusConnection *connection,
					char *ctrl_ifname, char **iface)
{
  int ret = 0;
  GVariant *reply;
  ret = supplicant_gdbus_method_call_sync(connection,
					SUPPLICANT_SERVICE,
					SUPPLICANT_PATH,
					SUPPLICANT_INTERFACE,
					"GetInterface",
					g_variant_new("(s)", (const gchar *)ctrl_ifname),
					&reply);
  if (ret) {
    printf("Error while sending get interface method call: %d\n", ret);
    return ret;
  }

  g_variant_get(reply, "(&o)", iface);
  return ret;
}

static int
supplicant_remove_interface(GDBusConnection *connection, char *iface)
{
  int ret = 0;
  GVariant *reply;

  ret = supplicant_gdbus_method_call_sync(connection,
					SUPPLICANT_SERVICE,
					SUPPLICANT_PATH,
					SUPPLICANT_INTERFACE,
					"RemoveInterface",
					g_variant_new("(o)", iface),
					&reply);
  if (ret) {
    printf("Error while sending remove interface method call: %d\n", ret);
  }
  return ret;
}

static int
supplicant_set_interface(GDBusConnection *connection, char *iface, int ap_scan)
{
  int ret = 0;
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
    printf("Error while setting up ap_scan mode, %d\n", ret);
  }
  return ret;
}

static void
supplicant_get_apscan(GDBusConnection *connection, char *iface, int *ap_scan)
{
  int ret = 0;
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
    printf("Error while fetching interface mdoe, %d\n", ret);
    return;
  }
  g_variant_get(reply, "(v)", &iter);
  g_variant_get(iter, "u", ap_scan);
  return;
}

static void
supplicant_variant_buidler(struct wpa_ssid *ssid, GVariant **parameter)
{
  GVariantBuilder *builder;
  builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

  if (ssid == NULL) {
    printf("Empty wpa_ssid\n");
    return;
  }
  g_variant_builder_add(builder, "{sv}", "ssid", g_variant_new_string(strdup(ssid->ssid)));
  g_variant_builder_add(builder, "{sv}", "mode", g_variant_new("u", ssid->mode));
  g_variant_builder_add(builder, "{sv}", "key_mgmt", g_variant_new_string(ssid->key_mgmt));
  g_variant_builder_add(builder, "{sv}", "psk", g_variant_new_string(strdup(ssid->psk)));
  *parameter = g_variant_builder_end(builder);
  g_variant_builder_unref(builder);

  return;
}

static int
supplicant_add_network(GDBusConnection *connection, char *iface, struct wpa_ssid *ssid)
{
  int ret = 0;
  GVariant *reply;
  GVariant *parameter;

  supplicant_variant_buidler(ssid, &parameter);
  ret = supplicant_gdbus_method_call_sync(connection,
					SUPPLICANT_SERVICE,
					iface,
					SUPPLICANT_INTERFACE".Interface",
					"AddNetwork",
					g_variant_new_tuple(&parameter, 1),
					&reply);
  if (ret) {
    printf("Error while sending add network method call: %d\n", ret);
    return ret;
  }
  g_variant_get(reply, "(&o)", &g_network);
  printf("Add Network: %s\n", g_network);

  return ret;
}

int
supplicant_remove_network(GDBusConnection *connection, char *iface)
{
  int ret = 0;
  GVariant *reply;

  ret = supplicant_gdbus_method_call_sync(connection,
					SUPPLICANT_SERVICE,
					iface,
					SUPPLICANT_INTERFACE".Interface",
					"RemoveNetwork",
					g_variant_new("(o)", g_network),
					&reply);
  if (ret) {
    printf("Error while removing network, %d\n", ret);
  }
  return ret;
}

static void
supplicant_select_network(GDBusConnection *connection, char *iface)
{
  int ret = 0;
  GVariant *reply;
  GVariant *parameter;

  parameter = g_variant_new("o", g_network);
  ret = supplicant_gdbus_method_call_sync(connection,
					SUPPLICANT_SERVICE,
					iface,
					SUPPLICANT_INTERFACE".Interface",
					"SelectNetwork",
					g_variant_new_tuple(&parameter, 1),
					&reply);
  if (ret) {
    printf("Error while sending selecting that network: %d\n", ret);
  }
  return;
}

static void
supplicant_enable_network(GDBusConnection *connection)
{
  int ret = 0;
  GVariant *reply;

  ret = supplicant_gdbus_method_call_sync(connection,
					SUPPLICANT_SERVICE,
					g_network,
					SUPPLICANT_PROP_INTERFACE,
					"Set",
					g_variant_new("(ssv)", SUPPLICANT_INTERFACE".Network",
						"Enabled", g_variant_new("b", true)),
					&reply);
  if (ret) {
    printf("Error while enabling network, %d\n", ret);
  }
  return;
}

int
supplicant_configure_interface(GDBusConnection *connection, char **iface, int mode)
{
  int ret = 0;
  char *ctrl_ifname;
  char *temp_iface;
  int ap_scan;

  ret = supplicant_get_wireless_interface(&ctrl_ifname);
  if (ret) {
    printf("Unable to fetch wireless interface name: %d\n", ret);
    return ret;
  }

  ret = supplicant_get_interface(connection, ctrl_ifname, &temp_iface);
  if (ret) {
    printf("Unable to send get interface method call: %d\n", ret);
    return ret;
  }
  *iface = temp_iface;

  supplicant_get_apscan(connection, *iface, &ap_scan);
  if (ap_scan == mode) {
    printf("Already in required mode\n");
  } else {
    ret = supplicant_remove_interface(connection, *iface);
    if (ret) {
      printf("Unable to send remove interface method call: %d\n", ret);
      return ret;
    }

    ret = supplicant_create_interface(connection, ctrl_ifname, &temp_iface);
    if (ret) {
      printf("Unable to send get interface method call: %d\n", ret);
      return ret;
    }
    *iface = temp_iface;

    ret = supplicant_set_interface(connection, *iface, mode);
    if (ret) {
      printf("Unable to send set interface method call: %d\n", ret);
      return ret;
    }
  }
  return ret;
}

int
supplicant_start_softap(GDBusConnection *connection, char *ssid_key, char *psk)
{
  int ret = 0;
  char *iface;
  struct wpa_ssid *ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));

  ret = supplicant_configure_interface(connection, &iface, 2);
  if (ret) {
    printf("Unable to configure interface: %d\n", ret);
    return ret;
  }
  snprintf(ssid->ssid, MAX_LEN_SSID, "%s", ssid_key);
  snprintf(ssid->psk, MAX_LEN_PSK, "%s", psk);
  ssid->mode = WPAS_MODE_AP;
  ssid->key_mgmt = "WPA-PSK";

  ret = supplicant_add_network(connection, iface, ssid);
  if (ret) {
    printf("Error while adding SoftAP network: %d\n", ret);
    return ret;
  }
  supplicant_select_network(connection, iface);
  supplicant_enable_network(connection);
  return ret;
}

int
supplicant_start_sta(GDBusConnection *connection, char **iface)
{
  int ret = 0;
  char *temp_iface;

  ret = supplicant_configure_interface(connection, &temp_iface, 1);
  if (ret) {
    printf("Unable to configure interface: %d\n", ret);
    return ret;
  }
  *iface = temp_iface;
  return ret;
}

int
supplicant_wifi_join(GDBusConnection *connection, char *iface, char *ssid_key, char *psk)
{
  int ret = 0;
  struct wpa_ssid *ssid = (struct wpa_ssid *)malloc(sizeof(struct wpa_ssid));

  snprintf(ssid->ssid, MAX_LEN_SSID, "%s", ssid_key);
  snprintf(ssid->psk, MAX_LEN_PSK, "%s", psk);
  ssid->mode = WPAS_MODE_INFRA;
  ssid->key_mgmt = "WPA-PSK";
  ret = supplicant_add_network(connection, iface, ssid);
  if (ret) {
    printf("Error while joining network: %d\n", ret);
    return ret;
  }
  supplicant_select_network(connection, iface);
  supplicant_enable_network(connection);
  return ret;
}

static int
execute_cmd(const char *file_path, char *const args[], char *const envs[])
{
  int pid;
  int rv;
  errno = 0;

  pid = fork();
  switch (pid) {
    case -1:
      printf("fork failed");
      return -1;
    case 0:
      printf("Inside child, exec (%s) command", file_path);
      if (execve(file_path, args, envs) == -1) {
        printf("Failed to execute command (%s)", strerror(errno));
        exit(1);
      }
      break;
    default:
      if (waitpid(pid, &rv, 0) == -1)
        printf("wait pid (%u) rv (%d)", pid, rv);
      break;
  }
  return pid;
}

int
wifi_start_station(void)
{
  int ret = 0;
  if (!g_connection) {
    g_autoptr(GError) error = NULL;
    g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) {
      printf("Failed to get gdbus connection: %s\n", error->message);
      return -1;
    }
  }
  ret = supplicant_start_sta(g_connection, &g_iface);
  if (ret) {
    printf("Error while starting station, %d\n", ret);
  }
  return ret;
}

int
wifi_stop_station(void)
{
  int ret = 0;
  ret = supplicant_remove_network(g_connection, g_iface);
  if (ret) {
    printf("Error while stopping station, %d\n", ret);
  }
  return ret;
}
 
int 
wifi_start_softap(char *ssid, char *psk)
{
  int ret = 0;
  if (!g_connection) {
    g_autoptr(GError) error = NULL;
    g_connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
    if (error) {
      printf("Failed to get gdbus connection: %s\n", error->message);
      return -1;
    }
  }

  ret = supplicant_start_softap(g_connection, ssid, psk);
  if (ret) {
    printf("Error while starting softAP, %d\n", ret);
  }
  return ret;
}

int 
wifi_stop_softap(void)
{
  int ret = 0;
  ret = supplicant_remove_network(g_connection, g_iface);
  if (ret) {
    printf("Error while stopping softAP, %d\n", ret);
  }
  return ret;
}
 
int
wifi_join(char *ssid, char *password)
{
  int ret = 0;
  ret = supplicant_wifi_join(g_connection, g_iface, ssid, password);
  if (ret) {
    printf("Error while joining, %d\n", ret);
  }
  return ret;
}

int 
wifi_start_dhcp_client(void)
{
  char buf[DHCLIENT_CONF_LEN] = "";
  char hostname[MAX_HOSTNAME_LEN];
  char *pidfile = NULL;
  struct dirent *dent;
  FILE *fp = NULL;
  char *const args[] = {"/sbin/dhclient", "-d", "-cf", "/etc/dhclient.conf", NULL};
  char *const envs[] = { NULL };

  DIR *dir = opendir(DHCLIENT_PID_DIRECTORY);
  if (dir) {
    while ((dent = readdir (dir)) != NULL) {
      pidfile = strdup(dent->d_name);
      if (!strncmp(pidfile, "dhclient", 8)) {
        printf("Dhclient process already running: %s\n", pidfile);
        return 0;
      }
    }
    closedir(dir);
  }

  if (remove(DHCLIENT_LEASES_FILE) < 0)
    printf("Failed to remove %s", DHCLIENT_LEASES_FILE);

  if (dhclient_pid == 0) {
    fp = fopen(DHCLIENT_CONF_FILE, "w");
    if (NULL == fp) {
      printf("Could not create the file.\n");
      return -1;
    }
    gethostname(hostname, MAX_HOSTNAME_LEN);
    snprintf(buf, DHCLIENT_CONF_LEN, DHCLIENT_CONF, hostname);
    fputs(buf, fp);
    fclose(fp);

    //run DHCLIENT daemon
    dhclient_pid = execute_cmd(args[0], &args[0], envs);
  } else {
    printf("DHCP client is already running\n");
  }
  return 0;
}

int
wifi_stop_dhcp_client(void)
{
  int ret;

  if(dhclient_pid == 0) {
    printf("There is an already DHCP client running.\n");
    return -1;
  }
  kill(dhclient_pid, SIGTERM);
  waitpid(dhclient_pid, NULL, 0);
  dhclient_pid = 0;

  ret = remove(DHCLIENT_CONF_FILE);
  if(ret < 0){
    printf("Error in unlinking.\n");
    return -1;
  }
  return 0;
}

int 
wifi_start_dhcp_server(void)
{
  int ret;
  char *ctrl_ifname;
  char *const args_dns[] = {"/usr/sbin/dnsmasq", "-d", "-p0", "-F192.168.0.20,192.168.0.30", "-O3,192.168.0.1", NULL};
  char *const envs[] = { NULL };

  // Assign IP Address
  ret = supplicant_get_wireless_interface(&ctrl_ifname);
  if (ret) {
    printf("Unable to fetch wireless interface name: %d\n", ret);
    return ret;
  }
  char *const args_ip[] = {"/sbin/ip", "addr", "add", "192.168.0.20/24", "dev", ctrl_ifname, NULL};

  execute_cmd(args_ip[0], &args_ip[0], envs);

  if (remove(DNSMASQ_LEASES_FILE) < 0)
    printf("Failed to remove %s", DNSMASQ_LEASES_FILE);

  if (dnsmasq_pid == 0) {
    //run DNSMASQ daemon
    dnsmasq_pid = execute_cmd(args_dns[0], &args_dns[0], envs);
  } else {
    printf("DHCP server is already running\n");
  }
  return 0;
}

int
wifi_stop_dhcp_server(void)
{
  if(dnsmasq_pid == 0) {
    printf("There is no DHCP server running.\n");
    return -1;
  }

  kill(dnsmasq_pid, SIGTERM);
  printf("DNSMASQ PID:%d", dnsmasq_pid);
  waitpid(dnsmasq_pid, NULL, 0);
  dnsmasq_pid = 0;
  return 0;
}

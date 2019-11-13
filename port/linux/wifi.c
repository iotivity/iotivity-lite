
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
#include "wifi.h"

int
wifi_start_station(void)
{
  return 0;
}

int
wifi_stop_station(void)
{
  return 0;
}
 
int 
wifi_start_softap()
{
  return 0;
}

int 
wifi_stop_softap(char *ssid, char *password, char *security, int channel)
{
  (void)(*ssid);
  (void)(*password);
  (void)(*security);
  (void)channel;
  return 0;
}
 
int
wifi_join(char *ssid, char *password, char *security)
{
  (void)(*ssid);
  (void)(*password);
  (void)(*security);
  return 0;
}

int 
wifi_start_dhcp_client()
{
  return 0;
}

int 
wifi_start_dhcp_server()
{
  return 0;
}

int 
wifi_stop_dhcp_server()
{
  return 0;
}

int
wifi_stop_dhcp_client() 
{
  return 0;
}

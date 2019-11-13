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
#ifndef _WIFI_H_
#define _WIFI_H_

int wifi_start_station(void);
int wifi_stop_station(void);
int wifi_start_softap();
int wifi_stop_softap(char *ssid, char *password, char *security, int channel);
int wifi_join(char *ssid, char *password, char *security);
int wifi_start_dhcp_client();
int wifi_stop_dhcp_client();
int wifi_start_dhcp_server();
int wifi_stop_dhcp_server();

#endif //_WIFI_H_

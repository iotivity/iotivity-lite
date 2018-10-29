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

#ifndef ST_WIFI_SOFT_AP_UTIL_H
#define ST_WIFI_SOFT_AP_UTIL_H

#include <wifi_manager/wifi_manager.h>

int es_create_softap(const char *ssid, const char *passwd);
int es_stop_softap(void);
int wifi_join(const char *ssid, const char *auth_type, const char *enc_type, const char *passwd);
wifi_manager_scan_info_s* stapp_wifi_get_wifi_aps(void);

#define WM_TEST_WAIT(cond,mutex)                     \
    do{                                              \
        pthread_mutex_lock(&mutex);                  \
        st_print_log("T%d waiting...\n",getpid());   \
        pthread_cond_wait(&cond,&mutex);             \
        pthread_mutex_unlock(&mutex);                \
    }while(0)

#define WM_TEST_SIGNAL(cond,mutex)                   \
    do{                                              \
        pthread_mutex_lock(&mutex);                  \
        printf("%d send signal\n",getpid());         \
        pthread_cond_signal(&cond);                  \
        pthread_mutex_unlock(&mutex);                \
    }while(0)

#endif /* ST_WIFI_SOFT_AP_UTIL_H */

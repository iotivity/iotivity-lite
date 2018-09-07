/******************************************************************
 *
 * Copyright 2018 GRANITE RIVER LABS All Rights Reserved.
 *
 *
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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#define RESOURCE_NAME "lightbulb"
#define RESOURCE_URI "/light/"
#define NUMRESOURCESTYPES 1
#define DEVICE 0
#define RESOURCE_LIGHT_TYPE "core.light"
#define MAX_LIGHT_RESOURCE_COUNT 4
#define NDEVICE 1
#define MAX_STRING 65
#define FAN_INVISIBLE_URI "/device/fan-invisible"
#define MAX_URI_LENGTH (30)

extern char g_3DPrinter_RESOURCE_ENDPOINT[];
extern char g_AudioControls_RESOURCE_ENDPOINT[];
extern int g_AudioControls_nr_resource_types;
extern int quit;
pthread_mutex_t mutex;
pthread_cond_t cv;
struct timespec ts;
extern int g_3DPrinter_nr_resource_types;

int convert_if_string(char *interface_name);
void register_resources();
void signal_event_loop(void);
void signal_event_loop(void);
void handle_signal(int signal);
int app_init(void);

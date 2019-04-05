/******************************************************************
 *
 * Copyright 2016 Granite River Labs All Rights Reserved.
 *
 *
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

//Includes
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <stdbool.h>
#include <time.h>
#include <DUTController.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <pthread.h>

//Definations
#define TAFServerPort	5001
#define CertAppServerPort	5000
#define TAG                  "OCF_TAF_AGENT"
#define DEFAULT_CONTEXT_VALUE 0x99
#define QOS_NON               0
#define QOS_CON               1
#define IPv4                  4
#define IPv6                  6
#define SLEEP_TIME            2
#define JUSTWORKS             1
#define RANDOMPIN             2
#define MFG_CERT              3
#define FRESH_CLIENT          1
#define REUSE_CLIENT          3
#define FRESH_SERVER          2
#define REUSE_SERVER          4

//Global Variables//
char gCertificationApp[24] = "CertificationApp";
int gIPDiscovered = 0;
int gInsideMainLoop = 0;
pid_t gPid;
int gQuitFlag = 0;
int gRestartFlag = 0;
int gReuseIUT = 0;
char *gConfigPath = NULL;
char *gConfigFilename = NULL;
char *gConfigFileContent = NULL;
char gIp[30];
char globalBuffer[1025];
char gLocalIp[50];
char gPort[25];
char gUuid[50];
char gPinValue[9];
char gCommandsArray[10][255];
char *globalIPv6_firstHextet = "fe80";
static int quit = 0;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
char GIP[30];
//macros//
#define FREE(x)           if(x){free(x);x=NULL;}

/////////////////////////////////////////////////////CTT Messages/////////////////////////////////////////////////////////
#define CTTmsg1 "Waiting for CoAP response"
#define CTTmsg2 "Please send a CoAP Ping message to the CTT"
#define CTTmsg3 "If the device uses an OCF Rooted Certificate Chain"
#define CTTmsg4	"Please enter PIN:"
#define CTTmsg5	"Please initiate IUT to revert to \"ready for OTM\" state"
#define CTTmsg6	"Please cycle power on the IUT"
#define CTTmsg7	"Please revert IUT to RFOTM / reset the device"
#define CTTmsg8 "Did IUT receive response:"
#define CTTmsg9 "Was device discovered sucessfully?"
#define CTTmsg10 "Did IUT received NOTIFY:"
#define CTTmsg11 "Please send a multicast discovery request message"
#define CTTmsg12 "Please initiate the Endpoint discovery process"
#define CTTmsg13 "Please have the IUT establish a TCP connection"
#define CTTmsg14 "send a unicast RETRIEVE request"
#define CTTmsg15 "send a unicast partial UPDATE request"
#define CTTmsg16 "send a unicast request message"
#define CTTmsg17 "Does IUT have the possibility to display received properties values?"
#define CTTmsg18 "Does IUT has discovered a device (i.e. the CTT) with the expected Resource Types?"
#define CTTmsg19 "Does IUT presents following properties values?"
#define CTTmsg20 "Please initiate the Resource discovery process."
#define CTTmsg21 "Please trigger the IUT to register with the CTT Cloud"
#define CTTmsg22 "Please trigger the IUT to log into the CTT Cloud"
#define CTTmsg23 "Please trigger the IUT to log out of the CTT Cloud"
#define CTTmsg24 "Please trigger the IUT to deregister from the CTT Cloud"
#define CTTmsg25 "Please trigger the IUT to trigger the IUT to refresh the Access Token with the CTT Cloud."

//////////////////////////////////////////////////////////CTT Action/////////////////////////////////////////////////////////////////////////////////
#define CTTAction1 "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>"
#define CTTAction2 "<actionResult><userDialogResponse><answer>Set_Value</answer><data>%s</data></userDialogResponse></actionResult>"
#define CTTAction3 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>"
#define CTTAction4 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>"

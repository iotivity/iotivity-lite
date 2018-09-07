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

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <stdbool.h>

//#include "ocstack.h"
//#include "ocpayload.h"
//#include "pinoxmcommon.h"
//#include "cacommon.h"
//#include "cainterface.h"
//#include "platform_features.h"
//#include "experimental/logger.h"
#include <time.h>
#include <DUTController.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

//#defines
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

//macros
#define FREE(x)           if(x){free(x);x=NULL;}

//Globals
char gIUTSimulator[24] = "IUTSimulator";
int gIPDiscovered = 0;
int gInsideMainLoop = 0;
pid_t gPid;
int gQuitFlag = 0;
int gRestartFlag = 0;
int gReuseIUT = 0;
char *gConfigPath = NULL;
char *gConfigFilename = NULL;
char *gConfigFileContent = NULL;
char gIUTlog[100] = "IUTSimulator_";
//OCDoHandle gObserveHandle;
bool gSecured = false;
char gIp[25];
char gLocalIp[50];
char gPort[25];
char gUuid[50];
int gFd;
char gPinValue[9];
static char s_DISCOVERY_QUERY[] = "%s/oic/res";
char gCommandsArray[10][255];

//Function declaration
void SendDiscovery();

/*Replace String*/
char *replaceString(const char *str, const char *from, const char *to)
{

    /* Adjust each of the below values to suit your needs. */

    /* Increment positions cache size initially by this number. */
    size_t cacheSizeInc = 16;
    /* Thereafter, each time capacity needs to be increased,
     * multiply the increment by this factor. */
    const size_t cacheSizeIncFactor = 3;
    /* But never increment capacity by more than this number. */
    const size_t cacheSizeIncMax = 1048576;

    char *pret, *ret = NULL;
    const char *pstr2, *pstr = str;
    size_t i, count = 0;
    ptrdiff_t *posCache = NULL;
    size_t cacheSize = 0;
    size_t cpyLen, orgLen, retLen, toLen, fromLen = strlen(from);

    /* Find all matches and cache their positions. */
    while ((pstr2 = strstr(pstr, from)) != NULL)
    {
        count++;

        /* Increase the cache size when necessary. */
        if (cacheSize < count)
        {
            cacheSize += cacheSizeInc;
            posCache = realloc(posCache, sizeof(*posCache) * cacheSize);
            if (posCache == NULL)
            {
                goto end_repl_str;
            }
            cacheSizeInc *= cacheSizeIncFactor;
            if (cacheSizeInc > cacheSizeIncMax)
            {
                cacheSizeInc = cacheSizeIncMax;
            }
        }

        posCache[count - 1] = pstr2 - str;
        pstr = pstr2 + fromLen;
    }

    orgLen = pstr - str + strlen(pstr);

    /* Allocate memory for the post-replacement string. */
    if (count > 0)
    {
        toLen = strlen(to);
        retLen = orgLen + (toLen - fromLen) * count;
    }
    else    retLen = orgLen;
    ret = malloc(retLen + 1);
    if (ret == NULL)
    {
        goto end_repl_str;
    }

    if (count == 0)
    {
        /* If no matches, then just duplicate the string. */
        strcpy(ret, str);
    }
    else
    {
        /* Otherwise, duplicate the string whilst performing
         * the replacements using the position cache. */
        pret = ret;
        memcpy(pret, str, posCache[0]);
        pret += posCache[0];
        for (i = 0; i < count; i++)
        {
            memcpy(pret, to, toLen);
            pret += toLen;
            pstr = str + posCache[i] + fromLen;
            cpyLen = (i == count - 1 ? orgLen : posCache[i + 1]) - posCache[i] - fromLen;
            memcpy(pret, pstr, cpyLen);
            pret += cpyLen;
        }
        ret[retLen] = '\0';
    }

end_repl_str:
    /* Free the cache and return the post-replacement string,
     * which will be NULL in the event of an error. */
    FREE(posCache);
    return ret;
}

/*Function to get the ip address of the machine where TAF is running*/
void getIP(int ipVersion)
{
    struct ifaddrs *ifAddress;
    char ipv6Address[50];
    FILE *fp;
    switch (ipVersion)
    {
        case IPv6:
            
           

            if (getifaddrs(&ifAddress) == -1)
            {
                //OIC_LOG(ERROR, TAG, "Could not collect address of interfaces");
                printf("Could not collect adress interfaces\n");
                exit(1);
            }

            do
            {
                if (ifAddress->ifa_addr->sa_family == AF_INET6)
                {
                    char firstHextet[5];
                    struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifAddress->ifa_addr;
                    inet_ntop(AF_INET6, &in6->sin6_addr, ipv6Address, sizeof(ipv6Address));

                    memcpy(firstHextet, &ipv6Address, 4);
                    firstHextet[4] = '\0';
                    if(!strcmp(firstHextet, "fe80"))
                        break;
                }
            } while (ifAddress = ifAddress->ifa_next);

            strcat(gLocalIp, ipv6Address);
            strcat(gLocalIp, "%");
            strcat(gLocalIp, ifAddress->ifa_name);
            break;

        case IPv4:
            //Works only on ubuntu
            fp = popen("hostname -I", "r");
            fscanf(fp, "%s", gLocalIp);
            pclose(fp);
            break;
    }

    if(gLocalIp[0] == '\0')
    {
        //OIC_LOG(ERROR, TAG, "Could not get Ip address");
        printf("Could not get Ip address\n");
        exit(1);
    }

    //OIC_LOG_V(INFO, TAG, "Local IP address: %s", gLocalIp);
}

/*Send command to the IUT simulator*/
void SendCommand(char *cmd)
{

    if (cmd != NULL)
    {
        char searchCmd[256] = "xdotool search --name \"";
        strcat(searchCmd, gIUTSimulator);
        strcat(searchCmd, "\" windowactivate");
        char command[128] = "xdotool type --delay 1 --clearmodifiers ";
        strcat(command, cmd);

        system(searchCmd);
        printf("Command %s\n", searchCmd);
        system("xdotool key --clearmodifiers Return");

        sleep(4);

        system(command);
        printf("Command %s\n", command);

        system("xdotool key --clearmodifiers Return");
        //OIC_LOG_V(INFO, TAG, "Command %s", searchCmd);
    }
}

/*Find the value of the string in the log file*/
void FindValue(char *searchString, char *value)
{
    FILE *fp1 = fopen(gIUTlog, "r");
    char *line = NULL;
    int i, j;
    size_t len = 0;
    ssize_t read;
    int lineNo = 0;
    if (fp1)
    {
        //OIC_LOG(DEBUG,TAG, "Inside File");
        while ((read = getline(&line, &len, fp1)) != -1)
        {
            ++lineNo;
            if ( (strstr(line, searchString) != NULL) &&
                 (strstr(line , ":") != NULL)
               )
            {
                //OIC_LOG_V(INFO, TAG, "%s", line);
                char *pos = strstr(line, ":");
                char data;
                for (i = 1, j = 0; * (pos + i) != '\0'; i++)
                {
                    data = *(pos + i);
                    if (!isspace(data))
                    {
                        //OIC_LOG_V(INFO, TAG, "data=%c",data);
                        *(value + j) = data;
                        j++;
                    }
                }
                *(value + j) = '\0';

                //OIC_LOG_V(INFO, TAG, "value=%s", value);
            }

        }
        fclose(fp1);

    }
}

/*Find the key in the string*/
void FindKey(char *searchString, char *key)
{
    FILE *fp1 = fopen(gIUTlog, "r");
    char *line = NULL;
    int i, j;
    size_t len = 0;
    ssize_t read;
    int lineNo = 0;
    if (fp1)
    {
        //OIC_LOG(DEBUG,TAG, "Inside File");
        while ((read = getline(&line, &len, fp1)) != -1)
        {
            ++lineNo;
            if ( (strstr(line, ". ") != NULL) &&
                 //(strstr(line , "-") != NULL) &&
                 (strstr(line , searchString) != NULL))
            {
                //OIC_LOG_V(INFO, TAG, "%s", line);
                char *pos = strstr(line, ".");
                char data;
                for (i = 0, j = 0; (i < 8) && (line[i] != *pos); i++)
                {
                    data = *(line + i);
                    if (!isspace(data))
                    {
                        //OIC_LOG_V(INFO, TAG, "data=%c",data);
                        *(key + j) = data;
                        j++;
                    }
                }
                *(key + j) = '\0';

                //OIC_LOG_V(INFO, TAG, "value=%s", key);
            }
            //OIC_LOG_V(DEBUG, TAG, "line=%d",lineNo);

        }
        fclose(fp1);

    }
}


/*Send command to the IUT Simulator in bulk*/
void SendCommands(int commandLength)
{
    //OIC_LOG_V(DEBUG, TAG, "Inside SendCommand");
    sleep(5 * SLEEP_TIME);
    for (int i = 0; i < commandLength; i++)
    {
        SendCommand(gCommandsArray[i]);
        sleep(SLEEP_TIME);
    }
}

/*XML Doc Ptr Clean*/
void CleanXmlDocPtr(xmlDocPtr doc)
{
    if(doc)
        xmlFreeDoc(doc);
}

/*XML action handler*/
xmlDocPtr ActionHandler(xmlDocPtr doc)
{

    char *result = (char *)"";
    char val[8], value[128];

    const char *messageXml = docToString(doc);

    if (strstr(messageXml, "<message>Waiting for CoAP response... ") == NULL &&
        strstr(messageXml, "<message>Please wait...") == NULL )
    {
        //OIC_LOG_V(INFO, TAG, "%s", messageXml);
        printf("%s\n", messageXml);
    }

    if (strstr(messageXml, "<message>Waiting for CoAP response... ") != NULL)
    {
        //SKIP
    }
    else if ( strstr(messageXml , "<message>If IUT uses an OCF Rooted Certificate Chain") != NULL)
    {
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
    }
    else if ( strstr(messageXml , "<message>Please provide (paste) public key of CA (PEM type)") != NULL)
    {
        //OIC_LOG(INFO, TAG, "Please provide (paste) public key of CA (PEM type)");

        const char *publicKey =
            "-----BEGIN CERTIFICATE-----\n"
            "MIICBDCCAaugAwIBAgIIZ0QY0VJs8zIwCgYIKoZIzj0EAwIwSjELMAkGA1UEBhMC\n"
            "VVMxDDAKBgNVBAoMA09DRjETMBEGA1UECwwKT0NGIENUVCBDQTEYMBYGA1UEAwwP\n"
            "T0NGIENUVCBST09UIENBMB4XDTE3MDEwMTAwMDAwMFoXDTI3MDEwMTAwMDAwMFow\n"
            "SjELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA09DRjETMBEGA1UECwwKT0NGIENUVCBD\n"
            "QTEYMBYGA1UEAwwPT0NGIENUVCBST09UIENBMFkwEwYHKoZIzj0CAQYIKoZIzj0D\n"
            "AQcDQgAEuKkiScoLLyjGALXhr2PijOyf0RRqXnKY8VXFM+aHkdYxiJHD5MziSXsT\n"
            "hDB82Hx7ykz8Fil0cBuE1tX4gX87/qN7MHkwKwYDVR0jBCQwIoAgVapQxp8Fthci\n"
            "DZjQdj0AdbaKBr9aXrlJxD9unFaRlCswKQYDVR0OBCIEIFWqUMafBbYXIg2Y0HY9\n"
            "AHW2iga/Wl65ScQ/bpxWkZQrMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD\n"
            "AgEGMAoGCCqGSM49BAMCA0cAMEQCIEfUv9VTQrFDg9/kqnTHpLBDRVgoMlAFsDgW\n"
            "S02KANuyAiAQsZeEhxTCqGhQwRQpIoI+WJ2maHa+pfuuwGXc+GH+Tg==\n"
            "-----END CERTIFICATE-----";

        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Set_Value</answer><data>%s</data></userDialogResponse></actionResult>",
                 publicKey);
        //OIC_LOG_V(DEBUG, TAG, "TAF==Send response %s", result);
    }
    else if ( strstr(messageXml , "<message>Please enter PIN:") != NULL)
    {
        // Get PIN generated by the IUTSimulator
        //OIC_LOG(INFO, TAG, "Please enter PIN:");
        FindValue("PIN CODE : ", gPinValue);
        //OIC_LOG_V(INFO, TAG, "PIN=%s", gPinValue);

        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Set_Value</answer><data>%s</data></userDialogResponse></actionResult>",
                 gPinValue);
        //OIC_LOG_V(DEBUG, TAG, "TAF==Send response %s", result);
    }
    else if ( strstr(messageXml,
                     "<message>Please initiate device to revert to \"ready for OTM\" state") != NULL ||
              strstr(messageXml, "<message>Please reset DUT's ACL in order to have empty list.") != NULL)
    {
        // Reset the IUTSimulator
        gRestartFlag = 1;
	sleep(1);
	while(gInsideMainLoop == 0){
	    sleep(1);
	}
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if ( strstr(messageXml, "<message>Please cycle power on the IUT") != NULL)
    {
        /* Reset the IUTSimulator */
        gRestartFlag = 1;
        gReuseIUT = 1;
        gIPDiscovered = 0;
        //OIC_LOG(INFO, TAG, "Wait for TAF to discover IUT after reset");
        do {sleep(1);} while (!gIPDiscovered);
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if ( strstr(messageXml, "<message>Please reset the IUT") != NULL)
    {
        /* Reset the IUTSimulator */
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml, "<message>Please change some value in /BinarySwitchResURI resource") !=
             NULL)
    {
        //asprintf(&result, "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
        if (strstr(messageXml, "and press OK") != NULL)
        {
            sleep(10);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
        }
        else
        {

            strcpy(gCommandsArray[0], "34");
            strcpy(gCommandsArray[1], "1");
            strcpy(gCommandsArray[2], "value");
            strcpy(gCommandsArray[3], "4");
            strcpy(gCommandsArray[4], "0");
            SendCommands(5);
        }
    }
    else if (strstr(messageXml, "<message>Did IUT receive response:") != NULL)
    {

        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml, "<message>Was device discovered sucessfully?") != NULL)
    {
        //TODO: Check if device was indeed discovered
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml, "<message>Did IUT received NOTIFY:") != NULL)
    {
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");

    }
    else if (strstr(messageXml, "<message>Please change some value in /AirFlowResURI resource") !=
             NULL)
    {
        //asprintf(&result, "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
        if (strstr(messageXml, "and press OK") != NULL)
        {
            sleep(10);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
        }
        else
        {
            strcpy(gCommandsArray[0], "34");
            strcpy(gCommandsArray[1], "5");
            strcpy(gCommandsArray[2], "speed");
            strcpy(gCommandsArray[3], "1");
            strcpy(gCommandsArray[4], "25");
            SendCommands(5);

        }
    }

    else if (strstr(messageXml, "<message>Please change some value in /TemperatureResURI resource") !=
             NULL)
    {
        //asprintf(&result, "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
        if (strstr(messageXml, "and press OK") != NULL)
        {
            //OIC_LOG(INFO, TAG, "Temperature URI Ok");
            sleep(10);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
        }
        else
        {
            //OIC_LOG(INFO, TAG, "Temperature URI");
            strcpy(gCommandsArray[0], "34");
            strcpy(gCommandsArray[1], "3");
            strcpy(gCommandsArray[2], "temperature");
            strcpy(gCommandsArray[3], "3");
            strcpy(gCommandsArray[4], "25.5");
            SendCommands(5);
        }
    }
    else if (strstr(messageXml,
                    "<message>Please send a multicast discovery request message (i.e. CoAP GET) to") != NULL ||
             strstr(messageXml,
                    "Please initiate the Endpoint discovery process") != NULL)
    {
        SendCommand("12");
        sleep(SLEEP_TIME);
    }
    else if (strstr(messageXml, "<message>Please have the IUT establish a TCP connection") != NULL)
    {
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/BinarySwitchResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            SendCommand("n");
            FindKey("coaps+tcp", val);
            SendCommand(val);
            sleep(SLEEP_TIME);

        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml, " send a unicast RETRIEVE request (i.e. CoAP GET) to ") != NULL)
    {
        if (strstr(messageXml, "/BinarySwitchResURI") != NULL)
        {
            //OIC_LOG(INFO, TAG, "Inside /BinarySwitchResURI");
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/BinarySwitchResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
        }
        else if (strstr(messageXml, "/TemperatureResURI") != NULL)
        {
            //OIC_LOG(INFO, TAG, "Inside /TemperatureResURI");
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/TemperatureResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
        }
        else
        {
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>CANCEL</answer></userDialogResponse></actionResult>");
        }
    }
    else if (strstr(messageXml, "send a unicast partial UPDATE request") != NULL)
    {
        sleep(2 * SLEEP_TIME);
        if (strstr(messageXml, "/BinarySwitchResURI") != NULL)
        {
            //OIC_LOG(INFO, TAG, "Inside Switch");
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/BinarySwitchResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
            FindValue("value", value);
            SendCommand("22");
            FindKey("/BinarySwitchResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
            SendCommand("value");
            sleep(SLEEP_TIME);
            SendCommand("4");
            sleep(SLEEP_TIME);
            if (strcmp(value, "false") == 0)
            {
                SendCommand("1");
            }
            else if (strcmp(value, "true") == 0)
            {
                SendCommand("0");

            }
            sleep(SLEEP_TIME);
        }
        else if (strstr(messageXml, "/TemperatureResURI") != NULL)
        {
            //OIC_LOG(INFO, TAG, "Inside Switch");
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("22");
            FindKey("/TemperatureResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
            SendCommand("temperature");
            sleep(SLEEP_TIME);
            SendCommand("3");
            sleep(SLEEP_TIME);
            SendCommand("22.5");
            sleep(SLEEP_TIME);

        }
        else
        {
            asprintf(&result,
                    "<actionResult><userDialogResponse><answer>CANCEL</answer></userDialogResponse></actionResult>");
        }
    }
    else if (strstr(messageXml, " send a unicast request message (") != NULL)
    {
        //OIC_LOG(INFO, TAG, "Inside unicast request");
        if (strstr(messageXml, "/BinarySwitchResURI") != NULL)
        {
            sleep(SLEEP_TIME);
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            if (strstr(messageXml, "with observe option = 0") != NULL)
            {
                SendCommand("25");
            }
            else if (strstr(messageXml, "with observe option = 1") != NULL)
            {
                SendCommand("25");
                FindKey("/BinarySwitchResURI", val);
                SendCommand(val);
                sleep(SLEEP_TIME);
                if (strstr(messageXml, "over TCP") != NULL)
                {
                    SendCommand("n");
                    FindKey("coaps+tcp", val);
                    SendCommand(val);
                }
                else
                {
                    SendCommand("y");
                }
                sleep(SLEEP_TIME);
                SendCommand("26");
            }
            FindKey("/BinarySwitchResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
        }
        else if (strstr(messageXml, "/TemperatureResURI") != NULL)
        {
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            if (strstr(messageXml, "with observe option = 0") != NULL)
            {
                SendCommand("25");
            }
            else if (strstr(messageXml, "with observe option = 1") != NULL)
            {
                SendCommand("26");
            }
            FindKey("/TemperatureResURI", val);
            SendCommand(val);
            sleep(SLEEP_TIME);
            if (strstr(messageXml, "over TCP") != NULL)
            {
                SendCommand("n");
                FindKey("coaps+tcp", val);
                SendCommand(val);
            }
            else
            {
                SendCommand("y");
            }
            sleep(SLEEP_TIME);
        }
    }
    else if (strstr(messageXml, "send UPDATE to /oic/rd") != NULL)
    {
        //OIC_LOG(INFO, TAG, "Inside RD request");
        SendCommand("12");
        sleep(4 * SLEEP_TIME);
        SendCommand("110");
        sleep(2 * SLEEP_TIME);
    }
    else if (strstr(messageXml, "send DELETE to /oic/rd") != NULL)
    {
        //OIC_LOG(INFO, TAG, "Inside RD request");
        SendCommand("12");
        sleep(2 * SLEEP_TIME);
        SendCommand("112");
        sleep(2 * SLEEP_TIME);
    }
    else if (strstr(messageXml, "Please provide the Mediator with the generated cis") != NULL)
    {
        asprintf(&result,
                "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml, "Please initiate transfer of Cloud configuration") != NULL)
    {
        SendCommand("12");
        sleep(SLEEP_TIME);
        SendCommand("39");
        sleep(SLEEP_TIME);
    }
    else if (strstr(messageXml,
                    "<message>Does IUT have the possibility to display received properties values?") != NULL)
    {
#if 0
        asprintf(&result, "<actionResult><userDialogResponse><answer>No</answer></userDialogResponse></actionResult>");
#endif
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml,
                    "<message>Does IUT has discovered a device (i.e. the CTT) with the expected Resource Types?") !=
             NULL)
    {
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if (strstr(messageXml, "<message>Does IUT presents following properties values?") != NULL)
    {
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else
    {
        //OIC_LOG_V(DEBUG, TAG, "TAF==Received not handled POST /actions: %s", messageXml);
    }

    if (result != "")
    {
        //OIC_LOG_V(INFO, TAG, "%s", result);
        printf("%s\n", result);
    }

    return stringToDoc(result);
}

/*Abort Signal Handler*/
xmlDocPtr AbortSignalHandler(xmlDocPtr doc)
{
    //OIC_LOG_V(DEBUG, TAG, "TAF==Received GET /abortSignal:");
    return stringToDoc("<abortSignal><abortTestcase>false</abortTestcase><abortTestRun>false</abortTestRun></abortSignal>");

}

/*Configuration handler*/
xmlDocPtr ConfigurationHandler(xmlDocPtr doc)
{
    //OIC_LOG(INFO , TAG, "Inside Configuration Handler");
    if (gConfigFileContent == NULL)
    {
        long length;
        FILE *f = fopen (gConfigPath, "rb");
        if (f)
        {
            //OIC_LOG(INFO, TAG, "FILE OPENED");
            fseek (f, 0, SEEK_END);
            length = ftell (f);
            fseek (f, 0, SEEK_SET);
            gConfigFileContent = malloc (length + 1);

            if (gConfigFileContent )
            {
                fread (gConfigFileContent , 1, length, f);
                gConfigFileContent[length] = '\0';
            }
            fclose (f);
        }
        else
        {
            //OIC_LOG_V(ERROR, TAG, "Could not open file %s", gConfigFileContent);
            return stringToDoc("");
        }
    }
    uint32_t tempSize = 0;
    char *result = gConfigFileContent;
    char *tmp = replaceString(gConfigFileContent, "%IP%", gIp);
    tmp = replaceString(tmp, "%UUID%", gUuid);
    result = replaceString(tmp, "%PORT%", gPort);
    return stringToDoc(result);
}

/*Init TAF Agent*/
void  InitTAF()
{

    //OIC_LOG(INFO, TAG, "TAF Init Start");

    initDutControllers();
    addRouteBasic("POST", "/actions", ActionHandler, CleanXmlDocPtr);
    addRouteBasic("GET", "/abortSignal", AbortSignalHandler, CleanXmlDocPtr);
    if (gConfigPath != NULL)
    {
        addRouteSetup("GET", "/processes/ctt/configuration", ConfigurationHandler, CleanXmlDocPtr);
    }
    startDutControllerBasic("0.0.0.0", 32000);
    startDutControllerExtended("0.0.0.0", 32001);
    startDutControllerSetup("0.0.0.0", 32002);

    //OIC_LOG(INFO, TAG, "TAF Init Done");
}


/*Init the IUT Simulator*/
void initIUT(int qosArg, int ipVerArg, int securityArg, char *ocfVerArg, char initActions[][5], int initActionsSize)
{
    printf("IUT options: %d %d %d\n", qosArg, ipVerArg, securityArg);
    char app[255] = "IUTSimulator";

    switch (qosArg)
    {
        case QOS_NON:
            strcat(app, " 0");
            break;

        case QOS_CON:
            strcat(app, " 1");
            break;

        default:
            //OIC_LOG_V(ERROR, TAG, "QoS argument \"%d\" is invalid\n", qosArg);
            printf("QoS argument \"%d\" is invalid\n", qosArg);
            exit(1);
    }

    switch (ipVerArg)
    {
        case IPv4:
            strcat(app, " 4");
            break;

        case IPv6:
            strcat(app, " 6");
            break;

        default:
            //OIC_LOG_V(ERROR, TAG, "IP version argument \"%d\" is invalid\n", ipVerArg);
            printf("IP version argument \"%d\" is invalid\n", ipVerArg);
            exit(1);
    }

    switch (securityArg/10)
    {
        case FRESH_CLIENT:
            strcat(app, " 1");
            break;

        case REUSE_CLIENT:
            strcat(app, " 3");
            break;

        case FRESH_SERVER:
            strcat(app, " 2");
            break;

        case REUSE_SERVER:
            strcat(app, " 4");
            break;

        default:
            //OIC_LOG_V(ERROR, TAG, "Security argument \"%d\" is invalid\n", securityArg);
            printf("Security argument \"%d\" is invalid\n", securityArg);
            exit(1);
    }

    switch (securityArg%10)
    {
        case JUSTWORKS:
            strcat(app, "1");
            break;

        case RANDOMPIN:
            strcat(app, "2");
            break;

        case MFG_CERT:
            strcat(app, "3");
            break;

        default:
            //OIC_LOG_V(ERROR, TAG, "Security argument \"%d\" is invalid\n", securityArg);
            printf("Security argument \"%d\" is invalid\n", securityArg);
            exit(1);
    }

    strcat(app, " ");
    strcat(app, ocfVerArg);

    char parameters[255] = "result=1\nwhile [ $result -ne 0 ]; do \nxterm -title \"";
    strcat(parameters, gIUTSimulator);
    strcat(parameters, "\" -e \"./");
    strcat(parameters, app);
    strcat(parameters, " | tee ");
    strcat(parameters, gIUTlog);
    strcat(parameters, "\"\n result=$?\ndone");
    printf("Command Executed:%s\n", parameters);
    //OIC_LOG_V(DEBUG, TAG, "Command Executed:%s", parameters);
    if ((gPid = fork()) < 0)
    {
        //OIC_LOG(ERROR, TAG, "Fork failed");
        exit(1);
    }
    if (gPid == 0)
    {
        system("pkill --signal SIGKILL IUTSimulator");
        sleep(1);
        printf("gPid == 0\n");
        execlp("/bin/sh", "/bin/sh", "-c", parameters, NULL);
        sleep(5);
        exit(0);
    }

    sleep(3);
    for(int i = 0; i < initActionsSize; i++)
    {
        printf("%d\n", i);
        printf("Sending %s to IUTSimulator\n", initActions[i]);
        //OIC_LOG_V(DEBUG, TAG, "Sending %s to IUTSimulator\n", initActions[i]);

        SendCommand(initActions[i]);
        sleep(1);
    }
}
#if 0
/*Callback function on discovery*/
OCStackApplicationResult HandleDiscover(void *ctx,
                                        OCDoHandle handle,
                                        OCClientResponse *clientResponse)
{
    if (!clientResponse)
    {
        //OIC_LOG(ERROR, TAG, "Payload is NULL, No resources found");
        return OC_STACK_DELETE_TRANSACTION;
    }
    if (!gIPDiscovered)
    {

        if (!strcmp(gLocalIp, clientResponse->devAddr.addr))
        {
            //OIC_LOG_V(INFO, TAG,
                      "Device =============> Discovered @ %s:%d",
                      clientResponse->devAddr.addr,
                      clientResponse->devAddr.port);

            strcpy(gIp, clientResponse->devAddr.addr);
            strcpy(gIp, strtok(gIp, "%"));
            sprintf(gPort, "%d", clientResponse->devAddr.port);
            strcpy(gUuid, clientResponse->devAddr.remoteId);

            //OIC_LOG_V(INFO, TAG, "Port: %s", gPort);

            gIPDiscovered = 1;
        }
    }
    return OC_STACK_KEEP_TRANSACTION;

}

/*Send Discovery to discover the OCF Devices*/
void SendDiscovery()
{
    OCCallbackData cbData = {NULL, NULL, NULL};
    OCStackResult ret;
    char queryUri[200];
    char ipaddr[100] = {'\0'};

    snprintf(queryUri, sizeof(queryUri), s_DISCOVERY_QUERY, ipaddr);

    cbData.cb = HandleDiscover;
    cbData.context = (void *)DEFAULT_CONTEXT_VALUE;

    //Start a discovery query
    //OIC_LOG_V(INFO, TAG, "Resource Discovery:%s\n", queryUri);

    ret = OCDoResource(NULL, OC_REST_DISCOVER, queryUri, NULL, 0, CT_DEFAULT, OC_LOW_QOS, &cbData, NULL,
                       0);
    if (ret != OC_STACK_OK)
    {
        //OIC_LOG(ERROR, TAG, "Device Discovery error");
    }
    else
    {
        //OIC_LOG(INFO, TAG, "Device Discovery Success");
    }
}

#endif

/*Stop the IUTSimulator*/
void stopIUT()
{
    char value[255] = "0";
    printf("Sending %s to IUTSimulator\n", value);
    SendCommand(value);
}
#if 0
/*Discovery the IUT Simulator port */
void discoverIUT(int ipVersion)
{
    switch (ipVersion)
    {
        case IPv4:
            if (OCInit1(OC_CLIENT, OC_IP_USE_V4 , OC_IP_USE_V4) != OC_STACK_OK)
            {
                //OIC_LOG(ERROR, TAG, "OCStack init error");
                exit(0);
            }
            break;

        case IPv6:
            if (OCInit1(OC_CLIENT, OC_IP_USE_V6 , OC_IP_USE_V6) != OC_STACK_OK)
            {
                //OIC_LOG(ERROR, TAG, "OCStack init error");
                exit(0);
            }
            break;
    }

    SendDiscovery();

    do
    {
        if (OCProcess() != OC_STACK_OK)
        {
            fprintf(stdout, "OCStack process error\n");
            fflush(stdout);
            exit(0);
        }
    }
    while (!gIPDiscovered);

    if (OCStop() != OC_STACK_OK)
    {
        //OIC_LOG(ERROR, TAG, "OCStack process error");
        return OC_STACK_DELETE_TRANSACTION;
    }
    else
    {
        //OIC_LOG(INFO, TAG, "OC Stack Stopped");
    }
}
#endif

/*SIGINT handler: set gQuitFlag to 1 for graceful termination*/
void HandleSigInt(int signum)
{
    if ((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGTSTP))
    {
        gQuitFlag = 1;
        gRestartFlag = 1;
        stopIUT();
    }

}

/*Main Entry point of the code*/
int main(int argc, char **argv)
{
    printf("Started\n");

    int qosArg = 1;
    int ipVerArg = 4;
    int securityArg = 25;
    char* ocfVerArg = NULL;

    if (argc < 6)
    {
        printf("Error: Wrong amount of arguments, shoule be:\n./TAFAgent conf_path QoS ipVersion security ocfVersion\n");
        return -1;
    }

    /* get the configuration file path */
    gConfigPath = argv[1];

    char* tempConfigPath = strdup(gConfigPath);
    gConfigFilename = basename(tempConfigPath);
    gConfigFilename = strtok(gConfigFilename, ".");

    strcat(gIUTlog, gConfigFilename);
    strcat(gIUTlog, ".log");

    printf("Start to open file %s\n", gConfigPath);
    FILE *fp;

    fp = fopen(gConfigPath, "r");
    if (fp == NULL)
    {
        //OIC_LOG_V(ERROR, TAG, "Could not find file %s", gConfigPath);
        printf("Error: Could not find file %s", gConfigPath);
        return -1;
    }
    fclose(fp);


    /* get the options to start IUT Simulator */
    qosArg = atoi(argv[2]);
    ipVerArg = atoi(argv[3]);
    securityArg = atoi(argv[4]);
    ocfVerArg = argv[5];

    int initActionsSize = argc - 6;
    char initActions[initActionsSize][5];
    for(int i = 0; i < initActionsSize; i++)
    {
        strcpy(initActions[i], argv[6 + i]);
    }

    getIP(ipVerArg);

    signal(SIGINT, HandleSigInt);
    const int trigger = CLOCKS_PER_SEC;
    InitTAF();
    while (!gQuitFlag)
    {
        printf("InitIUT\n");
        if (gReuseIUT)
        {
            initIUT(qosArg, ipVerArg, securityArg + 20, ocfVerArg, initActions, initActionsSize);
            gReuseIUT = 0;
        }
        else
        {
            initIUT(qosArg, ipVerArg, securityArg, ocfVerArg, initActions, initActionsSize);
        }

       // printf("DiscoverIUT\n");
        //discoverIUT(ipVerArg);
        printf("Entering TAF Agent main loop...\n");
        //OIC_LOG(INFO, TAG, "Entering TAF Agent main loop...");
        clock_t prevClock = clock() - trigger;
        while (!gRestartFlag)
        {
            gInsideMainLoop = 1;
            clock_t curClock = clock();
            if(curClock - prevClock >= trigger){
                printf(".\n");
                prevClock = curClock;
            }
        }
        gInsideMainLoop = 0;
        //OIC_LOG(INFO, TAG, "Exiting TAF Agent main loop...");
        stopIUT();
        gIPDiscovered = 0;
        gRestartFlag = 0;
    }
    stopDutControllers();
    disposeDutControllers();
    FREE(gConfigFileContent);

    return 0;
}

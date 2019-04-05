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
char gIUTlog[100] = "CertAppLog.log";
bool gSecured = false;
char gIp[30];
char gLocalIp[50];
char gPort[25];
char gUuid[50];
int gFd;
char gPinValue[9];
static char s_DISCOVERY_QUERY[] = "%s/oic/res";
char gCommandsArray[10][255];
static int quit = 0;
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
char globalBuffer[1025];
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
    while((pstr2 = strstr(pstr, from)) != NULL){
        count++;
        /* Increase the cache size when necessary. */
        if(cacheSize < count){
            cacheSize += cacheSizeInc;
            posCache = realloc(posCache, sizeof(*posCache) * cacheSize);
            if(posCache == NULL){
                goto end_repl_str;
            }
            cacheSizeInc *= cacheSizeIncFactor;
            if(cacheSizeInc > cacheSizeIncMax){
                cacheSizeInc = cacheSizeIncMax;
            }
        }
        posCache[count - 1] = pstr2 - str;
        pstr = pstr2 + fromLen;
    }
    orgLen = pstr - str + strlen(pstr);
    /* Allocate memory for the post-replacement string. */
    if(count > 0){
        toLen = strlen(to);
        retLen = orgLen + (toLen - fromLen) * count;
    }
    else    retLen = orgLen;
    ret = (char*) malloc(retLen + 1);
    if(ret == NULL){
        goto end_repl_str;
    }
    if(count == 0){
        /* If no matches, then just duplicate the string. */
        strcpy(ret, str);
    }
    else{
        /* Otherwise, duplicate the string whilst performing
         * the replacements using the position cache. */
        pret = ret;
        memcpy(pret, str, posCache[0]);
        pret += posCache[0];
        for(i = 0; i < count; i++){
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
void getIP(int ipVersion){
    struct ifaddrs *ifAddress;
    char ipv6Address[50];
    FILE *fp;
    switch(ipVersion){
        case IPv6:
            if(getifaddrs(&ifAddress) == -1){
                printf("Could not collect adress interfaces\n");
                exit(1);
            }
           do{
                if(ifAddress->ifa_addr->sa_family == AF_INET6){
                    char firstHextet[5];
                    struct sockaddr_in6 *in6 = (struct sockaddr_in6*) ifAddress->ifa_addr;
                    inet_ntop(AF_INET6, &in6->sin6_addr, ipv6Address, sizeof(ipv6Address));
                    memcpy(firstHextet, &ipv6Address, 4);
                    firstHextet[4] = '\0';
                    if(!strcmp(firstHextet, "fe80"))
                        break;
                }
            } while(ifAddress = ifAddress->ifa_next);
            strcat(gLocalIp, ipv6Address);
            strcat(gLocalIp, "%");
            strcat(gLocalIp, ifAddress->ifa_name);
            printf("Local IP :%s",gLocalIp);
            break;
        case IPv4:
            fp = popen("hostname -I", "r");
            fscanf(fp, "%s", gLocalIp);
            pclose(fp);
            break;
    }
    if(gLocalIp[0] == '\0'){
        printf("Could not get Ip address\n");
        exit(1);
    }
    printf("Local IP address: %s", gLocalIp);
}

/*Send command to the IUT simulator*/
void SendCommand(char *cmd){
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr;
    int num = 0;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("\nTAFAgent_Error: Could not Create Socket \n");
        return;
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000);
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0){
        printf("\n inet_pton error occured\n");
        return;
    }
    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
       printf("\nTAFAgent_Error: Connect Failed \n");
       return;
    }
        printf("\nTAFAgent: Sending Command \"%s\" to CertApp\n", cmd);
            if((send(sockfd,cmd, strlen(cmd),0))== -1){
                fprintf(stderr, "Failure Sending Message\n");
                close(sockfd);
                return;
        }
       else{
    }
    close(sockfd);
}

/*Find the value of the string in the log file*/
void FindValue(char *searchString, char *value){
    FILE *fp1 = fopen(gIUTlog, "r");
    char *line = NULL;
    int i, j;
    size_t len = 0;
    ssize_t read;
    int lineNo = 0;
    if(fp1){
        while((read = getline(&line, &len, fp1)) != -1){
            ++lineNo;
            if((strstr(line, searchString) != NULL) &&
                 (strstr(line , ":") != NULL)
               ){
                char *pos = strstr(line, ":");
                char data;
                for(i = 1, j = 0; * (pos + i) != '\0'; i++){
                    data = *(pos + i);
                    if(!isspace(data)){
                        *(value + j) = data;
                        j++;
                    }
                }
                *(value + j) = '\0';
            }
        }
        fclose(fp1);
    }
}

/*Find the key in the string*/
void FindKey(char *cmd, char *key){
    int sockfd = 0, n = 0;
    struct sockaddr_in serv_addr;
    int num = 0;
    if((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0){
        printf("\nTAFAgent_Error: Could not Create Socket \n");
        return ;
    }
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(5000);
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0){
        printf("\n inet_pton error occured\n");
        return ;
    }
    if( connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
       printf("\nTAFAgent_Error: Connect Failed \n");
       return;
    }
        printf("\nTAFAgent: Sending Message \"%s\" to CertApp\n", cmd);
            if((send(sockfd,cmd, strlen(cmd),0))== -1){
                fprintf(stderr, "Failure Sending Message\n");
                close(sockfd);
                return;
        }
       else{
    }
    close(sockfd);
}
/*Send command to the IUT Simulator in bulk*/
void SendCommands(int commandLength){
    printf("Inside SendCommand \n");
    sleep(5 * SLEEP_TIME);
    for(int i = 0; i < commandLength; i++){
        SendCommand(gCommandsArray[i]);
        sleep(SLEEP_TIME);
    }
}

/*XML Doc Ptr Clean*/
void CleanXmlDocPtr(xmlDocPtr doc){
    if(doc)
        xmlFreeDoc(doc);
}

/*XML action handler*/
xmlDocPtr ActionHandler(xmlDocPtr doc){
    char *result = (char *)"";
    char val[8], value[128];
    const char *messageXml = docToString(doc);
    printf("Message Received from CTT: %s\n",messageXml);
    if(strstr(messageXml, "<message>Waiting for CoAP response... ") == NULL &&
        strstr(messageXml, "<message>Please wait...") == NULL ){
        printf("%s\n", messageXml);
    }
    if(strstr(messageXml, "<message>Waiting for CoAP response... ") != NULL){
        //SKIP
    }
    else if( strstr(messageXml , "<message>Please send a CoAP Ping message to the CTT") != NULL){
        char tempString[256];
        char delimiters[] = "()";
        char headerString[43] = "coap+tcp://";
        char cmdString[46] = "40,";
        strncpy(tempString, messageXml,256);
        char* reqString = strtok(tempString, delimiters);
        reqString = strtok(NULL, delimiters);
        strcat(headerString, reqString);
        strcat(cmdString,headerString);
        SendCommand(cmdString);
    }
    else if( strstr(messageXml , "<message>If IUT uses an OCF Rooted Certificate Chain") != NULL){
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
    }
    else if( strstr(messageXml , "<message>Please provide (paste) public key of CA (PEM type)") != NULL){
        printf("Please provide (paste) public key of CA (PEM type) \n");

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
    }
    else if( strstr(messageXml , "<message>Please enter PIN:") != NULL){
      // Get PIN generated by the CertificationApp
      strcpy(gPinValue, globalBuffer);
      asprintf(&result,
               "<actionResult><userDialogResponse><answer>Set_Value</"
               "answer><data>%s</data></userDialogResponse></actionResult>",
               gPinValue);
    }
    else if( strstr(messageXml,
                     "<message>Please initiate device to revert to \"ready for OTM\" state") != NULL ||
              strstr(messageXml, "<message>Please reset DUT's ACL in order to have empty list.") != NULL ||
              strstr(messageXml, "<message>Please initiate IUT to revert to \"ready for OTM\" state") != NULL){
      // Reset the CertificationApp
      gRestartFlag = 1;
      sleep(1);
      while(gInsideMainLoop == 0){
        sleep(1);
      }
      asprintf(&result, "<actionResult><userDialogResponse><answer>OK</"
                        "answer></userDialogResponse></actionResult>");
    }
    else if ( strstr(messageXml, "<message>Please cycle power on the IUT") != NULL){
      /* Reset the CertificationApp */
      asprintf(&result, "<actionResult><userDialogResponse><answer>OK</"
                        "answer></userDialogResponse></actionResult>");
    }
    else if ( strstr(messageXml, "<message>Please revert IUT to RFOTM / reset the device") != NULL){
         /* Reset the CertificationApp */
        gRestartFlag = 1;
        gReuseIUT = 1;
        gIPDiscovered = 0;
        printf("Wait for TAF to discover IUT after reset \n");
        do{sleep(1);} while(!gIPDiscovered);
        /* Reset the CertificationApp */
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if( strstr(messageXml, "<message>Please reset the IUT") != NULL){
        /* Reset the CertificationApp */
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "<message>Please change some value in /BinarySwitchResURI resource") !=
             NULL){
        if(strstr(messageXml, "and press OK") != NULL){
            sleep(10);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
        }
        else{
            strcpy(gCommandsArray[0], "34");
            strcpy(gCommandsArray[1], "1");
            strcpy(gCommandsArray[2], "value");
            strcpy(gCommandsArray[3], "4");
            strcpy(gCommandsArray[4], "0");
            SendCommands(5);
        }
    }
    else if(strstr(messageXml, "<message>If the device uses an OCF Rooted Certificate Chain, click 'Skip'. Otherwise please provide (paste) the CA (PEM type) known to the device") != NULL){
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "<message>Please change some value in /binaryswitch resource and press OK") != NULL){
            sleep(2);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
     }
     else if(strstr(messageXml, "<message>Please change some value in /humidity resource and press OK") !=
             NULL){
            sleep(2);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");

     }

    else if(strstr(messageXml, "<message>Did IUT receive response:") != NULL){

        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "<message>Was device discovered sucessfully?") != NULL){
        //TODO: Check if device was indeed discovered
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "<message>Did IUT received NOTIFY:") != NULL){
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");

    }
    else if(strstr(messageXml, "<message>Please change some value in /AirFlowResURI resource") !=
             NULL){
        if(strstr(messageXml, "and press OK") != NULL){
            sleep(10);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
        }
        else{
            strcpy(gCommandsArray[0], "34");
            strcpy(gCommandsArray[1], "5");
            strcpy(gCommandsArray[2], "speed");
            strcpy(gCommandsArray[3], "1");
            strcpy(gCommandsArray[4], "25");
            SendCommands(5);
        }
    }
    else if(strstr(messageXml, "<message>Please change some value in /HumidityResURI resource") !=
             NULL){
        if(strstr(messageXml, "and press OK") != NULL){
            sleep(10);
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
        }
        else{
            strcpy(gCommandsArray[0], "34");
            strcpy(gCommandsArray[1], "3");
            strcpy(gCommandsArray[2], "temperature");
            strcpy(gCommandsArray[3], "3");
            strcpy(gCommandsArray[4], "25.5");
            SendCommands(5);
        }
    }
    else if(strstr(messageXml,
                    "<message>Please send a multicast discovery request message (i.e. CoAP GET) to") != NULL ||
             strstr(messageXml,
                    "Please initiate the Endpoint discovery process") != NULL){
        SendCommand("12");
        sleep(SLEEP_TIME);
    }
    else if(strstr(messageXml, "<message>If the device uses an OCF Rooted Certificate Chain, click 'Skip'. Otherwise please provide (paste) the CA (PEM type) known to the device") != NULL){
            asprintf(&result,
                     "<actionResult><userDialogResponse><answer>Skip</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "<message>Please have the IUT establish a TCP connection") != NULL){
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/BinarySwitchResURI", val);
            sleep(2 * SLEEP_TIME);
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, " send a unicast RETRIEVE request (i.e. CoAP GET) to ") != NULL){
        if(strstr(messageXml, "/BinarySwitchResURI") != NULL){
            printf("Inside /BinarySwitchResURI \n");
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/BinarySwitchResURI", val);
            sleep(SLEEP_TIME);
        }
        else if(strstr(messageXml, "/HumidityResURI") != NULL){
            printf("Inside /BinarySwitchResURI \n");
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
            SendCommand("17");
            FindKey("/HumidityResURI", val);
            sleep(SLEEP_TIME);
        }
    } else if (strstr(messageXml, "send a unicast partial UPDATE request") !=
               NULL) {
      if (strstr(messageXml, "/BinarySwitchResURI") != NULL) {
        SendCommand("12");
        sleep(2 * SLEEP_TIME);
        SendCommand("46");
        FindKey("/BinarySwitchResURI", val);
        sleep(SLEEP_TIME);
      }
      if (strstr(messageXml, "/HumidityResURI") != NULL) {
        SendCommand("12");
        sleep(2 * SLEEP_TIME);
        SendCommand("47");
        FindKey("/HumidityResURI", val);
        sleep(SLEEP_TIME);
      }
    }
    else if(strstr(messageXml, " send a unicast request message (") != NULL){
            sleep(SLEEP_TIME);
            SendCommand("12");
            sleep(2 * SLEEP_TIME);
                SendCommand("25");
            FindKey("/BinarySwitchResURI", val);
            sleep(SLEEP_TIME);
    }
    else if(strstr(messageXml, "send UPDATE to /oic/rd") != NULL){
        printf("Inside RD request \n");
        SendCommand("12");
        sleep(4 * SLEEP_TIME);
        SendCommand("110");
        sleep(2 * SLEEP_TIME);
    }
    else if(strstr(messageXml, "send DELETE to /oic/rd") != NULL){
        printf("Inside RD request \n");
        SendCommand("12");
        sleep(2 * SLEEP_TIME);
        SendCommand("112");
        sleep(2 * SLEEP_TIME);
    }
    else if(strstr(messageXml, "Please provide the Mediator with the generated cis") != NULL){
        asprintf(&result,
                "<actionResult><userDialogResponse><answer>OK</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "Please initiate transfer of Cloud configuration") != NULL){
        SendCommand("12");
        sleep(SLEEP_TIME);
        SendCommand("39");
        sleep(SLEEP_TIME);
    }
    else if(strstr(messageXml,
                    "<message>Does IUT have the possibility to display received properties values?") != NULL){
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml,
                    "<message>Does IUT has discovered a device (i.e. the CTT) with the expected Resource Types?") !=
             NULL){
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else if(strstr(messageXml, "<message>Does IUT presents following properties values?") != NULL){
        asprintf(&result,
                 "<actionResult><userDialogResponse><answer>Yes</answer></userDialogResponse></actionResult>");
    }
    else{
        printf("TAF==Received not handled POST /actions: %s \n", messageXml);
    }

    if(result != ""){
        printf("%s\n", result);
    }

    return stringToDoc(result);
}

/*Abort Signal Handler*/
xmlDocPtr AbortSignalHandler(xmlDocPtr doc){
    printf("TAF==Received GET /abortSignal: \n");
    return stringToDoc("<abortSignal><abortTestcase>false</abortTestcase><abortTestRun>false</abortTestRun></abortSignal>");
}

/*Configuration handler*/
xmlDocPtr ConfigurationHandler(xmlDocPtr doc){
    printf("Inside Configuration Handler \n");
    if(gConfigFileContent == NULL){
        long length;
        FILE *f = fopen (gConfigPath, "rb");
        if(f){
            printf("FILE OPENED \n");
            fseek (f, 0, SEEK_END);
            length = ftell (f);
            fseek (f, 0, SEEK_SET);
            gConfigFileContent = (char*) malloc (length + 1);
            if(gConfigFileContent ){
                fread (gConfigFileContent , 1, length, f);
                gConfigFileContent[length] = '\0';
            }
            fclose (f);
        }
        else{
            printf("Could not open file %s \n", gConfigFileContent);
            return stringToDoc("");
        }
    }
    uint32_t tempSize = 0;
    char *result = gConfigFileContent;
    char *tmp = replaceString(gConfigFileContent, "%IP%", gIp);
    strcpy(gUuid,"294f1f35-6161-4895-6e7d-c2d0f729c42c");
    result = replaceString(tmp, "%PORT%", gPort);
    printf("config:%s",result);
    return stringToDoc(result);
}

/*Init TAF Agent*/
void  InitTAF(char* ipv4Address){
    printf("TAF Init Start \n");
    initDutControllers();
    addRouteBasic("POST", "/actions", ActionHandler, CleanXmlDocPtr);
    addRouteBasic("GET", "/abortSignal", AbortSignalHandler, CleanXmlDocPtr);
    if(gConfigPath != NULL){
        addRouteSetup("GET", "/processes/ctt/configuration", ConfigurationHandler, CleanXmlDocPtr);
    }
    startDutControllerBasic(ipv4Address, 32000);
    // startDutControllerExtended("0.0.0.0", 32001);
    startDutControllerSetup(ipv4Address, 32002);
    printf("TAF Init Done \n");
}


/*Init the IUT Simulator*/
void initIUT(int qosArg, int ipVerArg, int securityArg, char *ocfVerArg, char initActions[][5], int initActionsSize){
    printf("IUT options: %d %d %d\n", qosArg, ipVerArg, securityArg);
    char app[255] = "CertificationApp";

    switch(qosArg){
        case QOS_NON:
            strcat(app, " 0");
            break;
        case QOS_CON:
            strcat(app, " 1");
            break;
        default:
            printf("QoS argument \"%d\" is invalid\n", qosArg);
            exit(1);
    }
    switch(ipVerArg){
        case IPv4:
            strcat(app, " 4");
            break;
        case IPv6:
            strcat(app, " 6");
            break;
        default:
            printf("IP version argument \"%d\" is invalid\n", ipVerArg);
            exit(1);
    }
    switch (securityArg/10){
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
            printf("Security argument \"%d\" is invalid\n", securityArg);
            exit(1);
    }
    switch(securityArg%10){
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
            printf("Security argument \"%d\" is invalid\n", securityArg);
            exit(1);
    }

    strcat(app, " ");
    strcat(app, ocfVerArg);
    char parameters[255] = "./";
    strcat(parameters,gCertificationApp);
    strcat(parameters," 1 2 3 auto");
    if((gPid = fork()) < 0){
        printf("Fork failed \n");
        exit(1);
    }
    if(gPid == 0){
        system("pkill --signal SIGKILL CertificationApp");
        sleep(1);
        printf("gPid == 0\n");
        execlp("/bin/sh","/bin/sh", "-c", parameters, NULL);
        sleep(5);
        exit(0);
    }
    sleep(3);
    for(int i = 0; i < initActionsSize; i++){
        SendCommand(initActions[i]);
        sleep(1);
    }
}

/*Stop the CertificationApp*/
void stopIUT(){
    char value[1] = "0";
    printf("TAFAgent: Sending \"%s\" to CertApp", value);
    SendCommand(value);
}

/*Discovery the IUT Simulator port */
void discoverIUT(int ipVersion, char* IUTInterfaceIndex, char* CTTScopeID){
    FILE *fp;
    char path[1035];
do{
    sleep(2);
    char cmdStr[5] = "18,";
    strcat(cmdStr, IUTInterfaceIndex);
    SendCommand(cmdStr);
    sleep(2);
    char cmdStr2[4] = "%";
    strcat(cmdStr2, CTTScopeID);
    strcpy(path, globalBuffer);
    printf("TAFAgent: IUT Discovery Done IUT_IP: %s\n", path);
    if(strcmp(path,"") !=0){
        sleep(2);
        if(ipVersion == 6){  //IPV6
            const char s[3] = "]:";
            char *token;
            int first = 0;
            strcpy(gIp, gLocalIp);
            strcpy(gIp, strtok(gIp, "%"));
            strcat(gIp, cmdStr2);
            token = strtok(path, s);
            while( token != NULL ){
                if(first == 0){
                    first = 1;
                }
                else{
                    if(strlen(token) ==5){
                        strncpy(gPort,token,5);
                        gIPDiscovered = 1;
                        break;
                    }
                }
                token = strtok(NULL, s);
                }
            }
            else if(ipVersion == 4){ //IPV4
            gIPDiscovered = 1;
            }
    }
}while(gIPDiscovered == 0);
}
/*SIGINT handler: set gQuitFlag to 1 for graceful termination*/
void HandleSigInt(int signum){
    if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGTSTP)){
        gQuitFlag = 1;
        gRestartFlag = 1;
    }
}

void startIUTfromArguments(int argc, char **argv){
    int qosArg = atoi(argv[2]);
    int ipVerArg = atoi(argv[3]);
    int securityArg = atoi(argv[4]);
    char* ocfVerArg = argv[5];
    int initialCommandsSize = argc - 10;
    char initialCommands[initialCommandsSize][5];
    for(int i = 0; i < initialCommandsSize; i++){
        strcpy(initialCommands[i], argv[10 + i]);
    }
    if(gReuseIUT){
      initIUT(qosArg, ipVerArg, securityArg + 20, ocfVerArg, initialCommands,
              initialCommandsSize);
      gReuseIUT = 0;
    }
    else{
        initIUT(qosArg, ipVerArg, securityArg, ocfVerArg, initialCommands, initialCommandsSize);
    }
}

static void* tafserver(){
    int listenfd = 0, client_fd = 0;
    struct sockaddr_in serv_addr;
    struct sockaddr_in dest;
    int num = 0;
    socklen_t size = 0;
    char buffer[1024];
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5001);
    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
    listen(listenfd, 10);
    memset(globalBuffer,0,sizeof(globalBuffer));
    printf("TAFAgent_Server: Started @ 5001\n");
    while(quit != 1){
        size = sizeof(struct sockaddr_in);
        if((client_fd = accept(listenfd, (struct sockaddr *)&dest, &size))==-1 ){
            perror("accept");
            break;
        }
            while(1){
                 memset(buffer, '0', sizeof(buffer));
                if((num = recv(client_fd, buffer, 1024,0))== -1){
                        perror("recv");
                        break;
                }
                else if(num == 0){
                        printf("TAFAgent_Sever: Connection Closed\n");
                        //So I can now wait for another client
                        break;
                }
                buffer[num] = '\0';
                memset(globalBuffer,0,sizeof(globalBuffer));
                strncpy(globalBuffer,buffer,num);
                printf("TAFAgent_Server: Message Received %s form CertApp\n", globalBuffer);
        }
    }
}
/*Main Entry point of the code*/
int main(int argc, char **argv){
    printf("Starting Tool Automation Framework\n");
    int ipVerArg = atoi(argv[3]);
    if(argc < 12){
    printf("ERROR: Wrong Command or Amount of Arguments, Shoule Be:\n\nExample:\n[./TAFAgent conf_path QoS IP_Version Security OCF_Version IP_Address InterfaceIndex ScopeID TAF_Mode CertAppInput1 CertAppInput2]\n");
    printf(
      "\nDescription:\nTAFAgent:\ttafagent\nconf_path:\tclient_config.txt -For Client Test Cases\n\t\tserver_config.txt -For Server Test  Cases\nQoS:\t    \
    0 -Using Non Server\n\t\t1 -Using CON Server\nIP_Version:\t4 -IPV_4\n\t\t6 -IPV_6\nSecurity:\t11 -Just Works\n\t\t12 -Random Pin\n\t\t13 -Manufacturing Certificate\nOCF_Version:\
    1.3.0\n\t\t2.0.0\n\t\t2.0.2\nIP_Address:\tIPv4 -Address of Machine Running TAFAgent\nInterfaceIndex:\tIndex -Of the Machine Running TAFAgent\nScopeID:\tScope_ID -Of the Machine Running CTT\nTAF_Mode:\
    server -To Start TAF in Server Mode\n\t\tclient -To Start TAF in Client Mode\nCertAppInput1:\t1 -Create a Resource\nCertAppInput2:\t1 -Create a Resource\n");
    return -1;
    }
    pthread_t thread;
  if(pthread_create(&thread, NULL, tafserver, NULL) != 0){
   printf("Failed to create main thread\n");
  }
    /* get the configuration file path */
    gConfigPath = argv[1];
    printf("Start to open file %s\n", gConfigPath);
    FILE *fp;
    fp = fopen(gConfigPath, "r");
    if(fp == NULL){
        printf("TAFAgent_Error: PICS File Not Found %s\n", gConfigPath);
        return -1;
    }
    printf("TAFAgent: Opening PICS File %s\n", gConfigPath);
    fclose(fp);
    startIUTfromArguments(argc, argv);
    getIP(ipVerArg);
    signal(SIGINT, HandleSigInt);
    const int trigger = CLOCKS_PER_SEC;
    sleep(3);
    printf("\nDiscoverIUT first time\n");
    discoverIUT(atoi(argv[3]), argv[7], argv[8]);
    InitTAF(argv[6]);
    while(!gQuitFlag){
      if(!gIPDiscovered){
        sleep(5);
        startIUTfromArguments(argc, argv);
        discoverIUT(atoi(argv[3]), argv[7], argv[8]);
        }
        if (strcmp(argv[9], "client") == 0){
            SendCommand("12");
            sleep(SLEEP_TIME);
            printf("\nTAFAgent: Entering Main Loop For Iotivity-Lite Client Tests...\n");
        }
        if (strcmp(argv[9], "server") == 0){
            printf("\nTAFAgent: Entering Main Loop For Iotivity-Lite Server Tests...\n");
        }
        clock_t prevClock = clock() - trigger;
        while(!gRestartFlag){
            gInsideMainLoop = 1;
            clock_t curClock = clock();
            if(curClock - prevClock >= trigger){
                printf(".\n");
                prevClock = curClock;
            }
        }
        gInsideMainLoop = 0;
        printf("Exiting TAF Agent main loop...\n");
        stopIUT();
        system("ls -lrt CertificationApp_creds/");
        system("rm -rf CertificationApp_creds/*");

        gIPDiscovered = 0;
        gRestartFlag = 0;
    }
    stopDutControllers();
    disposeDutControllers();
    FREE(gConfigFileContent);
    return 0;
}
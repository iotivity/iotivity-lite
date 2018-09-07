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

#include <DUTController.h>
#include <MiniHttpServer.h>
#include <uv.h>

/*Static resources Start*/
static ResourceMap* s_resourceMapBasic = 0;
static ResourceMap* s_resourceMapExtended = 0;
static ResourceMap* s_resourceMapSetup = 0;
static uv_thread_t s_serverID;
/*Static resource End*/

/*Doc to string conversion*/
char* docToString(xmlDocPtr doc)
{
    char* ret = 0;

    if (doc != 0)
    {
        xmlChar* xmlbuff;
        int buffersize;
        xmlDocDumpFormatMemory(doc, &xmlbuff, &buffersize, 1);
        ret = (char*)xmlbuff;
    }

    return ret;
}

/*String to Doc conversion*/
xmlDocPtr stringToDoc(const char* str)
{
    return xmlParseMemory(str, strlen(str));
}

/*Callback Function to be invoked for Basic HTTP request*/
char* onHttpRequestBasic(const char* method, const char* url, const char* body)
{
    xmlDocPtr reqDoc = 0;
    xmlDocPtr rspDoc = 0;
    char* ret = 0;
    ResourceCBS resourceCBS;

    if (body != 0)
    {
        reqDoc = stringToDoc(body);

        if (reqDoc == 0) goto error;
    }

    resourceCBS = getResourceCBS(s_resourceMapBasic, method, url);

    if (resourceCBS.onResource)
    {
        rspDoc = resourceCBS.onResource(reqDoc);
        ret = docToString(rspDoc);
    }

    if (resourceCBS.onAfterResource)
    {
        resourceCBS.onAfterResource(rspDoc);
    }

    goto cleanup;

error:
    printf("Error for %s %s\n", method, url);

cleanup:
    if (reqDoc != 0)
    {
        xmlFreeDoc(reqDoc);
    }

    return ret;
}

/*Callback Function to be invoked after executing Basic HTTP request*/
void onAfterHttpRequestBasic(char* rspBody)
{
    free(rspBody);
}


/*Callback Function to be invoked for Setup HTTP request*/
char* onHttpRequestSetup(const char* method, const char* url, const char* body)
{
    xmlDocPtr reqDoc = 0;
    xmlDocPtr rspDoc = 0;
    char* ret = 0;
    ResourceCBS resourceCBS;

    if (body != 0)
    {
        reqDoc = stringToDoc(body);

        if (reqDoc == 0) goto error;
    }

    resourceCBS = getResourceCBS(s_resourceMapSetup, method, url);

    if (resourceCBS.onResource)
    {
        rspDoc = resourceCBS.onResource(reqDoc);
        ret = docToString(rspDoc);
    }

    if (resourceCBS.onAfterResource)
    {
        resourceCBS.onAfterResource(rspDoc);

    }

    goto cleanup;

error:
    printf("Error for %s %s\n", method, url);

cleanup:
    if (reqDoc != 0)
    {
        xmlFreeDoc(reqDoc);
    }

    return ret;
}


/*Callback Function to be invoked after executing Setup HTTP request*/
void onAfterHttpRequestSetup(char* rspBody)
{
    free(rspBody);
}


/*Callback Function to be invoked for Extended HTTP request*/
char* onHttpRequestExtended(const char* method, const char* url, const char* body)
{
    xmlDocPtr reqDoc = 0;
    xmlDocPtr rspDoc = 0;
    char* ret = 0;
    ResourceCBS resourceCBS;

    if (body != 0)
    {
        reqDoc = stringToDoc(body);

        if (reqDoc == 0) goto error;
    }

    resourceCBS = getResourceCBS(s_resourceMapExtended, method, url);

    if (resourceCBS.onResource)
    {
        rspDoc = resourceCBS.onResource(reqDoc);
        ret = docToString(rspDoc);
    }

    if (resourceCBS.onAfterResource)
    {
        resourceCBS.onAfterResource(rspDoc);
    }

    goto cleanup;

error:
    printf("Error for %s %s\n", method, url);

cleanup:
    if (reqDoc != 0)
    {
        xmlFreeDoc(reqDoc);
    }

    return ret;
}


/*Callback Function to be invoked after executing Extended HTTP request*/
void onAfterHttpRequestExtended(char* rspBody)
{
    free(rspBody);
}


/*Init DUT Controllers related to Basic,Setup and Extended*/
void initDutControllers()
{
    s_resourceMapBasic = createResourceMap();
    s_resourceMapSetup = createResourceMap();
    s_resourceMapExtended = createResourceMap();
}

/*Dispose DUT Controllers related to Basic,Setup and Extended*/
void disposeDutControllers()
{
    deleteResourceMap(s_resourceMapBasic);
    deleteResourceMap(s_resourceMapSetup);
    deleteResourceMap(s_resourceMapExtended);
}

/*Add Route for Basic HTTP request*/
void addRouteBasic(const char* method, const char* path, resourceCB onResource, afterResourceCB onAfterResource)
{
    addResourceCBS(s_resourceMapBasic, method, path, onResource, onAfterResource);
}

/*Add Route for Setup HTTP request*/
void addRouteSetup(const char* method, const char* path, resourceCB onResource, afterResourceCB onAfterResource)
{
    addResourceCBS(s_resourceMapSetup, method, path, onResource, onAfterResource);
}

/*Add Route for Extended HTTP request*/
void addRouteExtended(const char* method, const char* path, resourceCB onResource, afterResourceCB onAfterResource)
{
    addResourceCBS(s_resourceMapExtended, method, path, onResource, onAfterResource);
}

/*Start DUT controller Basic*/
void startDutControllerBasic(const char* ip, int port)
{
    startMiniHttpServerBasic(ip, port, onHttpRequestBasic, onAfterHttpRequestBasic);
}

/*Start DUT controller Setup*/
void startDutControllerSetup(const char* ip, int port)
{
    startMiniHttpServerSetup(ip, port, onHttpRequestSetup, onAfterHttpRequestSetup);
}

/*Start DUT controller Extended*/
void startDutControllerExtended(const char* ip, int port)
{
    startMiniHttpServerExtended(ip, port, onHttpRequestExtended, onAfterHttpRequestExtended);
}

/*Stop DUT controllers*/
void stopDutControllers()
{
    stopMiniHttpServerBasic();
    stopMiniHttpServerSetup();
    stopMiniHttpServerExtended();
}

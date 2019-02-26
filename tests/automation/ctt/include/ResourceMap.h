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

#ifndef __RESOURCE_MAP_H__
#define __RESOURCE_MAP_H__

#include <libxml/parser.h>
#ifdef __cplusplus
extern "C"{
#endif

typedef xmlDocPtr (*resourceCB)(xmlDocPtr);
typedef void (*afterResourceCB)(xmlDocPtr);
#define MAX_METHOD 32
#define MAX_PATH 256
typedef struct 
{
    resourceCB onResource;
    afterResourceCB onAfterResource;
} ResourceCBS;

typedef struct 
{
    char method[MAX_METHOD + 1];
    char path[MAX_PATH + 1];
    ResourceCBS resourceCBS;
    struct Resource* next;
}Resource;

typedef struct 
{
    Resource* head;
}ResourceMap;


ResourceMap* createResourceMap();
void addResourceCBS(ResourceMap* self, const char* method, const char* path, resourceCB onResource, afterResourceCB onAfterResource);
ResourceCBS getResourceCBS(ResourceMap* self, const char* method, const char* path);
void deleteResourceMap(ResourceMap* self);
#ifdef __cplusplus
}
#endif
#endif //__RESOURCE_MAP_H__

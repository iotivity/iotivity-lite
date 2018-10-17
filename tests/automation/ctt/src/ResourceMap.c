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

#include <stdio.h>
#include <string.h>
#include <libxml/tree.h>
#include <ResourceMap.h>



/*Create a Resource Map*/
ResourceMap* createResourceMap()
{
    ResourceMap* map = (ResourceMap*)malloc(sizeof(ResourceMap));
    map->head = 0;

    return map;
}

/*Create and add a Resource to the Resource Map*/
void addResourceCBS(ResourceMap* self, const char* method, const char* path, resourceCB onResource, afterResourceCB onAfterResource)
{
    Resource* newElement = (Resource*)malloc(sizeof(Resource));

    strncpy(newElement->method, method, MAX_METHOD);
    strncpy(newElement->path, path, MAX_PATH);
    newElement->path[MAX_PATH] = 0;
    newElement->resourceCBS.onResource = onResource;
    newElement->resourceCBS.onAfterResource = onAfterResource;
    newElement->next = self->head;

    self->head = newElement;
}

/*Get Resource from the Resource Map*/
ResourceCBS getResourceCBS(ResourceMap* self, const char* method, const char* path)
{
    Resource* res = self->head;
    ResourceCBS resourceCBS;

    resourceCBS.onResource = 0;
    resourceCBS.onAfterResource = 0;

    while (res != 0)
    {
        if (strcmp(res->method, method) == 0 && strcmp(res->path, path) == 0)
        {
            resourceCBS = res->resourceCBS;
            break;
        }

        res = res->next;
    };

    return resourceCBS;
}

/*Delete Resource from the Resource Map*/
void deleteResourceMap(ResourceMap* self)
{
    Resource* head = self->head;
    Resource* nextHead = 0;

    while (head != 0)
    {
        nextHead = head->next;
        free(head);
        head = nextHead;
    };
}

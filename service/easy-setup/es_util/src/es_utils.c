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

#include "es_utils.h"
#include "es_logger.h"
#include "string.h"

#define ES_UTILS_TAG "UT"

char* oc_strcpy(char *dest, unsigned int dest_size, char *src, int copy_size) 
{
    int index = 0;

    if (copy_size < 0)
    {
        copy_size = strlen(src);
    }

    if (dest_size < (unsigned int)(copy_size + 1))
    {
        OC_LOGE(ES_UTILS_TAG, "not enough size in destination");
        return NULL ;
    }

    for (index=0; index < copy_size; index++)
    {
        *(dest + index) = *(src + index) ;
    }

    return dest ;
}
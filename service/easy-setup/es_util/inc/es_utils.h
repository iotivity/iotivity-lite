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

#ifndef ES_UTILS_H_
#define ES_UTILS_H_

char* oc_strcpy(char *dest, unsigned int dest_size, char *src, int copy_size) ;

#define OC_STRCPY(d, ds, src) oc_strcpy(d, ds, src, -1)
#define OC_STRNCPY(d, ds, src, n) oc_strcpy(d, ds, src, n)

#endif //ES_UTILS_H_

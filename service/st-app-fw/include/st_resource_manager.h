/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#ifndef ST_RECOURCE_MGR_H
#define ST_RECOURCE_MGR_H

#include "oc_rep.h"
#include <stdbool.h>

typedef struct
{
  const char *uri;
  int uri_len;
  const char *query;
  int query_len;
  oc_rep_t *request_payload;
} st_request_t;

typedef bool (*st_resource_handler)(st_request_t *request);

int st_register_resources(int device);
int st_register_resource_handler(st_resource_handler get_handler,
                                 st_resource_handler set_handler);
int st_notify_back(const char *uri);

#endif /* ST_RECOURCE_MGR_H */
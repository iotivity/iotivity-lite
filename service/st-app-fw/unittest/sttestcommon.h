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

#ifndef ST_TESTCOMMON_H
#define ST_TESTCOMMON_H

#include "st_port.h"

void reset_storage(void);
int test_wait_until(st_mutex_t mutex, st_cond_t cv, int wait_seconds);
void get_wildcard_acl_policy(void);

#endif /* ST_TESTCOMMON_H */
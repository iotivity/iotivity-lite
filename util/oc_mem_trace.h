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

#ifndef OC_MEM_TRACE_H
#define OC_MEM_TRACE_H

#ifdef __cplusplus
extern "C" {
#endif

#define MEM_TRACE_REALLOC (2)
#define MEM_TRACE_ALLOC (1) // it would be combination when BYTE, INT, DOUBLE
#define MEM_TRACE_FREE (0)

void oc_mem_trace_init(void);
void oc_mem_trace_add_pace(const char *func, int size, int type, void *address);
void oc_mem_trace_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_MEM_TRACE_H */

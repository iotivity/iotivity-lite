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

// TODO ::  consider when it isn't OC_DYNAMIC_ALLOCATION
// currently it is only avaliable under OC_DYNAMIC_ALLOCATION
#ifdef OC_MEMORY_TRACE

#include <stdio.h>
#include <stdlib.h>  // TODO: NOT OC_DYNAMIC_ALLOCATION
#include <string.h>  // TODO: NOT OC_DYNAMIC_ALLOCATION

#include "oc_list.h"
#include "oc_mem_trace.h"
#include "port/oc_log.h"

#define FUNC_NAME_LEN 30

typedef struct _mem_info {
  int peak;
  int current;
  OC_LIST_STRUCT(mem_log_list);
} mem_info_s;

typedef struct _mem_logger {
  struct mem_logger_s *next; /* for LIST */
  char func[FUNC_NAME_LEN+1];
  int size;
  int current;
  int peak;
  int type;  // MEM_TRACE_ALLOC, MEM_TRACE_FREE
  void *address;
} mem_logger_s;

static mem_info_s mInfo = {
  0,
};

void oc_mem_trace_init(void)
{
  mInfo.current = 0;
  mInfo.peak = 0;
  OC_LIST_STRUCT_INIT(&mInfo, mem_log_list);
}

void oc_mem_trace_add_pace(const char *func, int size, int type, void *address)
{

  if (type == MEM_TRACE_ALLOC) {
    mInfo.current += size;
    if (mInfo.current > mInfo.peak) {
      mInfo.peak = mInfo.current;
    }
  } else if (type == MEM_TRACE_FREE) {
    mInfo.current -= size;
  } else {
    OC_ERR("mem trace : UNKNOWN TYPE");
    return;
  }

  mem_logger_s *mem_log_item = (mem_logger_s *)malloc(sizeof(mem_logger_s));
  size_t func_name_len = strlen(func);
  if(FUNC_NAME_LEN < func_name_len )
    func_name_len=FUNC_NAME_LEN;
  memcpy(mem_log_item->func, (char *)func, func_name_len);
  mem_log_item->func[func_name_len] = '\0';
  mem_log_item->size = size;
  mem_log_item->current = mInfo.current;
  mem_log_item->peak = mInfo.peak;
  mem_log_item->type = type;
  mem_log_item->address = address;

  oc_list_add((&mInfo)->mem_log_list, mem_log_item);
}

void oc_mem_trace_print_paces(void)
{
  int cnt = 0;
  mem_logger_s *mem_log_item_link = oc_list_head((&mInfo)->mem_log_list);

  PRINT("===================================================================================\n");
  PRINT("  %2s   %-22s   %11s    %5s   %5s    %5s    %5s \n", "No.", "Func", "Address", "Size", "Req", "Cur", "Peak");
  PRINT("-----------------------------------------------------------------------------------\n");

  while (mem_log_item_link) {
    PRINT(" %3d   %-26.25s  %10p   %5d   %5s    %5d    %5d\n", ++cnt, mem_log_item_link->func, mem_log_item_link->address, mem_log_item_link->size, (mem_log_item_link->type == MEM_TRACE_FREE) ? "Free" : "Alloc", mem_log_item_link->current, mem_log_item_link->peak);

    mem_log_item_link = oc_list_item_next(mem_log_item_link);
  }
  PRINT("===================================================================================\n");
}

void oc_mem_trace_shutdown(void)
{
  oc_mem_trace_print_paces();
}
#else   /* OC_MEMORY_TRACE */
//TODO : it would be removed if MEMTRACE=0 excludes compiling this file
void dummy_null_func(void)
{
}
#endif   /* !OC_MEMORY_TRACE */

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

#ifdef OC_MEMORY_TRACE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "oc_list.h"
#include "oc_mem_trace.h"
#include "port/oc_log.h"

#define FUNC_NAME_LEN 30

typedef struct _mem_info
{
  int peak;
  int current;
  OC_LIST_STRUCT(mem_log_list);
} mem_info_s;

typedef struct _mem_logger
{
  struct mem_logger_s *next; /* for LIST */
  char func[FUNC_NAME_LEN + 1];
  size_t size;
  size_t current;
  size_t peak;
  int type; // MEM_TRACE_ALLOC, MEM_TRACE_FREE
  void *address;
} mem_logger_s;

static mem_info_s mInfo = {
  0,
};

#ifndef OC_DYNAMIC_ALLOCATION
#define LOGGER_ITEM_LEN 1000
mem_logger_s logger_item_list[LOGGER_ITEM_LEN];
int list_index = 0;
#endif /* !OC_DYNAMIC_ALLOCATION */

static void oc_mem_trace_free(void);

void
oc_mem_trace_init(void)
{
  mInfo.current = 0;
  mInfo.peak = 0;
  OC_LIST_STRUCT_INIT(&mInfo, mem_log_list);
}

void
oc_mem_trace_add_pace(const char *func, int size, int type, void *address)
{
  if(!mInfo.mem_log_list || !address || !func) {
    OC_ERR("mem trace : invalid param");
    return;
  }

  if (type == MEM_TRACE_ALLOC || type == MEM_TRACE_REALLOC) {
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
#ifdef OC_DYNAMIC_ALLOCATION
  mem_logger_s *mem_log_item = (mem_logger_s *)calloc(1, sizeof(mem_logger_s));
#else
  /* Only LOGGER_ITEM_LEN mem_log_items are available in static allocation
   */
  if (list_index >= LOGGER_ITEM_LEN)
    return;

  mem_logger_s *mem_log_item = &logger_item_list[list_index++];
#endif

  size_t func_name_len = strlen(func);
  if (FUNC_NAME_LEN < func_name_len)
    func_name_len = FUNC_NAME_LEN;
  memcpy(mem_log_item->func, (char *)func, func_name_len);
  mem_log_item->func[func_name_len] = '\0';
  mem_log_item->size = size;
  mem_log_item->current = mInfo.current;
  mem_log_item->peak = mInfo.peak;
  mem_log_item->type = type;
  mem_log_item->address = address;

  oc_list_add((&mInfo)->mem_log_list, mem_log_item);
}

void
oc_mem_trace_print_paces(void)
{
  int cnt = 0;
  mem_logger_s *mem_log_item_link = oc_list_head((&mInfo)->mem_log_list);

  PRINT("==================================================================");
  PRINT("=================\n");
  PRINT("  %2s   %-22s   %11s    %5s   %5s    %5s    %5s \n", "No.", "Func",
        "Address", "Size", "Req", "Cur", "Peak");
  PRINT("------------------------------------------------------------------");
  PRINT("-----------------\n");

  while (mem_log_item_link) {
    PRINT(" %3d   %-26.25s  %10p   %5d", ++cnt, mem_log_item_link->func,
          mem_log_item_link->address, mem_log_item_link->size);

    if (mem_log_item_link->type == MEM_TRACE_FREE)
      PRINT("   %7s", "Free");
    else if (mem_log_item_link->type == MEM_TRACE_ALLOC)
      PRINT("   %7s", "Alloc");
    else if (mem_log_item_link->type == MEM_TRACE_REALLOC)
      PRINT("   %7s", "Realloc");
    else
      PRINT("   %7s", "Unknown");

    PRINT("    %5d    %5d\n", mem_log_item_link->current,
          mem_log_item_link->peak);

    mem_log_item_link = oc_list_item_next(mem_log_item_link);
  }
  PRINT("===================================================================");
  PRINT("================\n");
}

void
oc_mem_trace_shutdown(void)
{
  oc_mem_trace_print_paces();

  if (mInfo.current) {
    PRINT("########################################################\n");
    PRINT("####### Unreleased memory size: [%8d bytes] #######\n",
          mInfo.current);
    PRINT("########################################################\n");
  }

  oc_mem_trace_free();
}

static void
oc_mem_trace_free(void)
{

  mem_logger_s *mem_log_item = oc_list_pop((&mInfo)->mem_log_list);

  while (mem_log_item) {
#ifdef OC_DYNAMIC_ALLOCATION
    free(mem_log_item);
#endif
    mem_log_item = oc_list_pop((&mInfo)->mem_log_list);
  }
}
#else  /* OC_MEMORY_TRACE */
// TODO : it would be removed if MEMTRACE=0 excludes compiling this file
void
dummy_null_mem_trace_func(void)
{
}
#endif /* !OC_MEMORY_TRACE */

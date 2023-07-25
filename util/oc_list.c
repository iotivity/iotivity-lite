/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

#include "oc_list.h"

#ifndef NULL
#define NULL 0
#endif

struct list
{
  struct list *next;
};

void
oc_list_init(oc_list_t list)
{
  *list = NULL;
}

void *
oc_list_head(oc_list_t list)
{
  return *list;
}

void
oc_list_copy(oc_list_t dest, oc_list_t src)
{
  *dest = *src;
}

void *
oc_list_tail(oc_list_t list)
{
  if (*list == NULL) {
    return NULL;
  }

  struct list *l;
  for (l = (struct list *)*list; l->next != NULL; l = l->next)
    ;

  return l;
}

void
oc_list_add(oc_list_t list, void *item)
{
  ((struct list *)item)->next = NULL;
  struct list *l = (struct list *)oc_list_tail(list);

  if (l == NULL) {
    *list = item;
  } else {
    l->next = (struct list *)item;
  }
}

void
oc_list_push(oc_list_t list, void *item)
{
  ((struct list *)item)->next = (struct list *)*list;
  *list = item;
}

void
oc_list_insert(oc_list_t list, void *previtem, void *newitem)
{
  if (previtem == NULL) {
    oc_list_push(list, newitem);
    return;
  }

  ((struct list *)newitem)->next = ((struct list *)previtem)->next;
  ((struct list *)previtem)->next = (struct list *)newitem;
}

void *
oc_list_chop(oc_list_t list)
{
  if (*list == NULL) {
    return NULL;
  }
  if (((struct list *)*list)->next == NULL) {
    struct list *l = (struct list *)*list;
    *list = NULL;
    return l;
  }

  struct list *l;
  for (l = (struct list *)*list; l->next->next != NULL; l = l->next)
    ;

  struct list *r = l->next;
  l->next = NULL;
  return r;
}

void *
oc_list_pop(oc_list_t list)
{
  struct list *l = (struct list *)*list;
  if (*list != NULL) {
    *list = ((struct list *)*list)->next;
    l->next = NULL;
  }

  return l;
}

void
oc_list_remove(oc_list_t list, const void *item)
{
  oc_list_remove2(list, item);
}

void *
oc_list_remove2(oc_list_t list, const void *item)
{
  for (struct list **l = (struct list **)list; *l != NULL; l = &(*l)->next) {
    if (*l == item) {
      struct list *l2 = *l;
      *l = (*l)->next;
      l2->next = NULL;
      return l2;
    }
  }
  return NULL;
}

int
oc_list_length(oc_list_t list)
{
  int n = 0;
  for (struct list *l = (struct list *)*list; l != NULL; l = l->next) {
    ++n;
  }

  return n;
}

bool
oc_list_has_item(oc_list_t list, const void *item)
{
  for (struct list *l = (struct list *)*list; l != NULL; l = l->next) {
    if (l == item) {
      return true;
    }
  }
  return false;
}

void *
oc_list_item_next(void *item)
{
  return item == NULL ? NULL : ((struct list *)item)->next;
}

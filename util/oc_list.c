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

/*---------------------------------------------------------------------------*/
/**
 * Initialize a list.
 *
 * This function initalizes a list. The list will be empty after this
 * function has been called.
 *
 * \param list The list to be initialized.
 */
void
oc_list_init(oc_list_t list)
{
  *list = NULL;
}
/*---------------------------------------------------------------------------*/
/**
 * Get a pointer to the first element of a list.
 *
 * This function returns a pointer to the first element of the
 * list. The element will \b not be removed from the list.
 *
 * \param list The list.
 * \return A pointer to the first element on the list.
 *
 * \sa oc_list_tail()
 */
void *
oc_list_head(oc_list_t list)
{
  return *list;
}
/*---------------------------------------------------------------------------*/
/**
 * Duplicate a list.
 *
 * This function duplicates a list by copying the list reference, but
 * not the elements.
 *
 * \note This function does \b not copy the elements of the list, but
 * merely duplicates the pointer to the first element of the list.
 *
 * \param dest The destination list.
 * \param src The source list.
 */
void
oc_list_copy(oc_list_t dest, oc_list_t src)
{
  *dest = *src;
}
/*---------------------------------------------------------------------------*/
/**
 * Get the tail of a list.
 *
 * This function returns a pointer to the elements following the first
 * element of a list. No elements are removed by this function.
 *
 * \param list The list
 * \return A pointer to the element after the first element on the list.
 *
 * \sa oc_list_head()
 */
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
/*---------------------------------------------------------------------------*/
/**
 * Add an item at the end of a list.
 *
 * This function adds an item to the end of the list.
 *
 * \param list The list.
 * \param item A pointer to the item to be added.
 *
 * \sa oc_list_push()
 *
 */
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
/*---------------------------------------------------------------------------*/
/**
 * Add an item to the start of the list.
 */
void
oc_list_push(oc_list_t list, void *item)
{
  /* Make sure not to add the same element twice */
  oc_list_remove(list, item);

  ((struct list *)item)->next = (struct list *)*list;
  *list = item;
}
/*---------------------------------------------------------------------------*/
/**
 * Remove the last object on the list.
 *
 * This function removes the last object on the list and returns it.
 *
 * \param list The list
 * \return The removed object
 *
 */
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
/*---------------------------------------------------------------------------*/
/**
 * Remove the first object on a list.
 *
 * This function removes the first object on the list and returns a
 * pointer to it.
 *
 * \param list The list.
 * \return Pointer to the removed element of list.
 */
/*---------------------------------------------------------------------------*/
void *
oc_list_pop(oc_list_t list)
{
  struct list *l = (struct list *)*list;
  if (*list != NULL) {
    *list = ((struct list *)*list)->next;
  }

  return l;
}
/*---------------------------------------------------------------------------*/
/**
 * Remove a specific element from a list.
 *
 * This function removes a specified element from the list.
 *
 * \param list The list.
 * \param item The item that is to be removed from the list.
 *
 */
/*---------------------------------------------------------------------------*/
void
oc_list_remove(oc_list_t list, const void *item)
{
  struct list **l;

  for (l = (struct list **)list; *l != NULL; l = &(*l)->next) {
    if (*l == item) {
      *l = (*l)->next;
      return;
    }
  }
}
/*---------------------------------------------------------------------------*/
/**
 * Remove a specific element from a list and return a pointer to the removed
 * item.
 *
 * This function removes a specified element from the list.
 *
 * \param list The list.
 * \param item The item that is to be removed from the list.
 * \return Pointer to the removed element of list.
 *
 */
/*---------------------------------------------------------------------------*/
void *
oc_list_remove2(oc_list_t list, void *item)
{
  struct list **l;

  for (l = (struct list **)list; *l != NULL; l = &(*l)->next) {
    if (*l == item) {
      *l = (*l)->next;
      return item;
    }
  }

  return NULL;
}

/*---------------------------------------------------------------------------*/
/**
 * Get the length of a list.
 *
 * This function counts the number of elements on a specified list.
 *
 * \param list The list.
 * \return The length of the list.
 */
/*---------------------------------------------------------------------------*/
int
oc_list_length(oc_list_t list)
{
  int n = 0;
  for (struct list *l = (struct list *)*list; l != NULL; l = l->next) {
    ++n;
  }

  return n;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief      Insert an item after a specified item on the list
 * \param list The list
 * \param previtem The item after which the new item should be inserted
 * \param newitem  The new item that is to be inserted
 * \author     Adam Dunkels
 *
 *             This function inserts an item right after a specified
 *             item on the list. This function is useful when using
 *             the list module to ordered lists.
 *
 *             If previtem is NULL, the new item is placed at the
 *             start of the list.
 *
 */
void
oc_list_insert(oc_list_t list, void *previtem, void *newitem)
{
  if (previtem == NULL) {
    oc_list_push(list, newitem);
  } else {

    ((struct list *)newitem)->next = ((struct list *)previtem)->next;
    ((struct list *)previtem)->next = (struct list *)newitem;
  }
}
/*---------------------------------------------------------------------------*/
/**
 * \brief      Get the next item following this item
 * \param item A list item
 * \returns    A next item on the list
 *
 *             This function takes a list item and returns the next
 *             item on the list, or NULL if there are no more items on
 *             the list. This function is used when iterating through
 *             lists.
 */
void *
oc_list_item_next(void *item)
{
  return item == NULL ? NULL : ((struct list *)item)->next;
}
/*---------------------------------------------------------------------------*/

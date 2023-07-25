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

/**
 * \defgroup list Linked list library
 *
 * The linked list library provides a set of functions for
 * manipulating linked lists.
 *
 * A linked list is made up of elements where the first element \b
 * must be a pointer. This pointer is used by the linked list library
 * to form lists of the elements.
 *
 * Lists are declared with the LIST() macro. The declaration specifies
 * the name of the list that later is used with all list functions.
 *
 * Lists can be manipulated by inserting or removing elements from
 * either sides of the list (list_push(), list_add(), list_pop(),
 * list_chop()). A specified element can also be removed from inside a
 * list with list_remove(). The head and tail of a list can be
 * extracted using list_head() and list_tail(), respectively.
 *
 * @{
 */

#ifndef OC_LIST_H
#define OC_LIST_H

#include "oc_export.h"
#include "util/oc_compiler.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OC_LIST_CONCAT2(s1, s2) s1##s2
#define OC_LIST_CONCAT(s1, s2) OC_LIST_CONCAT2(s1, s2)

/**
 * Declare a linked list.
 *
 * This macro declares a linked list with the specified \c type. The
 * type \b must be a structure (\c struct) with its first element
 * being a pointer. This pointer is used by the linked list library to
 * form the linked lists.
 *
 * The list variable is declared as static to make it easy to use in a
 * single C module without unnecessarily exporting the name to other
 * modules.
 *
 * \param name The name of the list.
 */
#define OC_LIST(name)                                                          \
  static void *OC_LIST_CONCAT(name, _list) = NULL;                             \
  static oc_list_t name = &OC_LIST_CONCAT(name, _list)

/**
 * Declare a linked list with a local scope.
 */
#define OC_LIST_LOCAL(name)                                                    \
  void *OC_LIST_CONCAT(name, _list) = NULL;                                    \
  oc_list_t name = &OC_LIST_CONCAT(name, _list)

/**
 * Declare a linked list inside a structure declaraction.
 *
 * This macro declares a linked list with the specified \c type. The
 * type \b must be a structure (\c struct) with its first element
 * being a pointer. This pointer is used by the linked list library to
 * form the linked lists.
 *
 * Internally, the list is defined as two items: the list itself and a
 * pointer to the list. The pointer has the name of the parameter to
 * the macro and the name of the list is a concatenation of the name
 * and the suffix "_list". The pointer must point to the list for the
 * list to work. Thus the list must be initialized before using.
 *
 * The list is initialized with the LIST_STRUCT_INIT() macro.
 *
 * \param name The name of the list.
 */
#define OC_LIST_STRUCT(name)                                                   \
  void *OC_LIST_CONCAT(name, _list);                                           \
  oc_list_t name

/**
 * Initialize a linked list that is part of a structure.
 *
 * This macro sets up the internal pointers in a list that has been
 * defined as part of a struct. This macro must be called before using
 * the list.
 *
 * \param struct_ptr A pointer to the struct
 * \param name The name of the list.
 */
#define OC_LIST_STRUCT_INIT(struct_ptr, name)                                  \
  do {                                                                         \
    (struct_ptr)->name = &((struct_ptr)->OC_LIST_CONCAT(name, _list));         \
    (struct_ptr)->OC_LIST_CONCAT(name, _list) = NULL;                          \
    oc_list_init((struct_ptr)->name);                                          \
  } while (0)

/**
 * The linked list type.
 */
typedef void **oc_list_t;

/**
 * Initialize a list.
 *
 * This function initalizes a list. The list will be empty after this function
 * has been called.
 *
 * \param list The list to be initialized.
 *
 * \sa OC_LIST()
 * \sa OC_LIST_LOCAL()
 * \sa OC_LIST_STRUCT()
 */
OC_API
void oc_list_init(oc_list_t list) OC_NONNULL();

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
OC_API
void *oc_list_head(oc_list_t list) OC_NONNULL();

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
OC_API
void *oc_list_tail(oc_list_t list) OC_NONNULL();

/**
 * Remove the first object on a list.
 *
 * This function removes the first object on the list and returns a
 * pointer to it.
 *
 * \param list The list.
 * \return Pointer to the removed element of list.
 */
OC_API
void *oc_list_pop(oc_list_t list) OC_NONNULL();

/**
 * Remove the last object on the list.
 *
 * This function removes the last object on the list and returns it.
 *
 * \param list The list
 * \return The removed object
 */
OC_API
void *oc_list_chop(oc_list_t list) OC_NONNULL();

/**
 * Add an item to the start of the list.
 *
 * \param list The list.
 * \param item A pointer to the item to be added.
 *
 * \sa oc_list_add()
 * \sa oc_list_insert()
 */
OC_API
void oc_list_push(oc_list_t list, void *item) OC_NONNULL();

/**
 * Add an item at the end of a list.
 *
 * This function adds an item to the end of the list.
 *
 * \param list The list.
 * \param item A pointer to the item to be added.
 *
 * \sa oc_list_push()
 * \sa oc_list_insert()
 */
OC_API
void oc_list_add(oc_list_t list, void *item) OC_NONNULL();

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
 * \sa oc_list_add()
 * \sa oc_list_push()
 */
OC_API
void oc_list_insert(oc_list_t list, void *previtem, void *newitem)
  OC_NONNULL(1, 3);

/**
 * Remove a specific element from a list.
 *
 * This function removes a specified element from the list.
 *
 * \param list The list.
 * \param item The item that is to be removed from the list.
 */
OC_API
void oc_list_remove(oc_list_t list, const void *item) OC_NONNULL(1);

/**
 * Remove a specific element from a list and return a pointer to the removed
 * item.
 *
 * This function removes a specified element from the list.
 *
 * \param list The list.
 * \param item The item that is to be removed from the list.
 * \return Pointer to the removed element of list.
 */
OC_API
void *oc_list_remove2(oc_list_t list, const void *item) OC_NONNULL(1);

/**
 * Get the length of a list.
 *
 * This function counts the number of elements on a specified list.
 *
 * \param list The list.
 * \return The length of the list.
 */
OC_API
int oc_list_length(oc_list_t list) OC_NONNULL();

/**
 * Check if a list contains a specific item.
 *
 * \param list The list.
 * \param item The item to check for.
 *
 * \return True if the list contains the item
 * \return False if the list does not contain the item
 */
OC_API
bool oc_list_has_item(oc_list_t list, const void *item) OC_NONNULL();

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
OC_API
void oc_list_copy(oc_list_t dest, oc_list_t src) OC_NONNULL();

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
OC_API
void *oc_list_item_next(void *item);

#ifdef __cplusplus
}
#endif

#endif /* OC_LIST_H */

/** @} */

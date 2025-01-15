/****************************************************************************
 *
 * Copyright (c) 2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "oc_buffer_settings.h"
#include "port/oc_log_internal.h"
#include "util/oc_features.h"

#include <stddef.h>

#ifdef OC_DYNAMIC_ALLOCATION

#include "messaging/coap/conf.h"

#ifdef OC_INOUT_BUFFER_SIZE
static size_t _OC_MTU_SIZE = OC_INOUT_BUFFER_SIZE;
#else  /* OC_INOUT_BUFFER_SIZE */
static size_t _OC_MTU_SIZE = 2048 + COAP_MAX_HEADER_SIZE;
#endif /* !OC_INOUT_BUFFER_SIZE */

static size_t _OC_MAX_APP_DATA_SIZE = 7168;
#if defined(OC_APP_DATA_BUFFER_SIZE) || !defined(OC_REP_ENCODING_REALLOC)
static size_t _OC_MIN_APP_DATA_SIZE = 7168;
#else  /* OC_APP_DATA_BUFFER_SIZE || !OC_REP_ENCODING_REALLOC */
static size_t _OC_MIN_APP_DATA_SIZE = 256;
#endif /* !OC_APP_DATA_BUFFER_SIZE && OC_REP_ENCODING_REALLOC */
static size_t _OC_BLOCK_SIZE = 1024; // FIX

int
oc_set_mtu_size(size_t mtu_size)
{
  (void)mtu_size;
#ifdef OC_INOUT_BUFFER_SIZE
  return -1;
#else /* !OC_INOUT_BUFFER_SIZE */
#ifdef OC_BLOCK_WISE
  if (mtu_size < (COAP_MAX_HEADER_SIZE + 16)) {
    return -1;
  }
#ifdef OC_OSCORE
  _OC_MTU_SIZE = mtu_size + COAP_MAX_HEADER_SIZE;
#else  /* OC_OSCORE */
  _OC_MTU_SIZE = mtu_size;
#endif /* !OC_OSCORE */
  mtu_size -= COAP_MAX_HEADER_SIZE;
  size_t i;
  for (i = 10; i >= 4 && (mtu_size >> i) == 0; i--)
    ;
  _OC_BLOCK_SIZE = ((size_t)1) << i;
#endif /* OC_BLOCK_WISE */
  return 0;
#endif /* OC_INOUT_BUFFER_SIZE */
}

long
oc_get_mtu_size(void)
{
  return (long)_OC_MTU_SIZE;
}

void
oc_set_max_app_data_size(size_t size)
{
#ifdef OC_APP_DATA_BUFFER_SIZE
  (void)size;
#else /* !OC_APP_DATA_BUFFER_SIZE */
  _OC_MAX_APP_DATA_SIZE = size;
#ifndef OC_REP_ENCODING_REALLOC
  _OC_MIN_APP_DATA_SIZE = size;
#endif /* !OC_REP_ENCODING_REALLOC */
#ifndef OC_BLOCK_WISE
  _OC_BLOCK_SIZE = size;
  _OC_MTU_SIZE = size + COAP_MAX_HEADER_SIZE;
#endif /* !OC_BLOCK_WISE */
#endif /* OC_APP_DATA_BUFFER_SIZE */
}

long
oc_get_max_app_data_size(void)
{
  return (long)_OC_MAX_APP_DATA_SIZE;
}

void
oc_set_min_app_data_size(size_t size)
{
#if defined(OC_APP_DATA_BUFFER_SIZE) || !defined(OC_REP_ENCODING_REALLOC)
  (void)size;
#else  /* !OC_APP_DATA_BUFFER_SIZE && !OC_REP_ENCODING_REALLOC */
  _OC_MIN_APP_DATA_SIZE = size;
#endif /* OC_APP_DATA_BUFFER_SIZE || !OC_REP_ENCODING_REALLOC */
}

long
oc_get_min_app_data_size(void)
{
  return (long)_OC_MIN_APP_DATA_SIZE;
}

long
oc_get_block_size(void)
{
  return (long)_OC_BLOCK_SIZE;
}

#else /* !OC_DYNAMIC_ALLOCATION  */

int
oc_set_mtu_size(size_t mtu_size)
{
  (void)mtu_size;
  OC_WRN("Dynamic memory not available");
  return -1;
}

long
oc_get_mtu_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

void
oc_set_max_app_data_size(size_t size)
{
  (void)size;
  OC_WRN("Dynamic memory not available");
}

long
oc_get_max_app_data_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

void
oc_set_min_app_data_size(size_t size)
{
  (void)size;
  OC_WRN("Dynamic memory not available");
}

long
oc_get_min_app_data_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

long
oc_get_block_size(void)
{
  OC_WRN("Dynamic memory not available");
  return -1;
}

#endif /* OC_DYNAMIC_ALLOCATION */

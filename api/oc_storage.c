/****************************************************************************
 *
 * Copyright 2023 Daniel Adam, All Rights Reserved.
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

#include "oc_config.h"

#ifdef OC_STORAGE

#include "api/oc_rep_decode_internal.h"
#include "api/oc_rep_internal.h"
#include "oc_storage_internal.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include "port/oc_storage.h"
#include "util/oc_macros_internal.h"

#include <stdio.h>

#ifdef OC_DYNAMIC_ALLOCATION
#include <stdlib.h>
#endif /* OC_DYNAMIC_ALLOCATION */

#ifdef OC_APP_DATA_STORAGE_BUFFER
static uint8_t g_oc_storage_buf[OC_APP_DATA_BUFFER_SIZE] = { 0 };
#endif /* OC_APP_DATA_STORAGE_BUFFER */

int
oc_storage_gen_svr_tag(const char *name, size_t device_index, char *svr_tag,
                       size_t svr_tag_size)
{
  assert(name != NULL);
  size_t max_buffer_size = svr_tag_size > OC_STORAGE_SVR_TAG_MAX
                             ? OC_STORAGE_SVR_TAG_MAX
                             : svr_tag_size;

  char subscript[32] = { '\0' };
  int ret = snprintf(subscript, sizeof(subscript), "_%zu", device_index);
  if (ret < 0 || (size_t)ret >= sizeof(subscript)) {
    return -1;
  }
  size_t subscript_len = (size_t)ret;

  const size_t required_size =
    subscript_len + 2; // +2 = at least one char from name and null-terminator
  if (max_buffer_size < required_size) {
    return -1;
  }

  const size_t max_name_size = max_buffer_size - subscript_len;
  ret = snprintf(svr_tag, max_name_size, "%s", name);
  if (ret < 0) {
    return -1;
  }
  size_t name_len =
    (size_t)ret >= max_name_size ? max_name_size - 1 : (size_t)ret;
  memcpy(svr_tag + name_len, subscript, subscript_len);
  size_t svr_tag_len = name_len + subscript_len;
  svr_tag[svr_tag_len] = '\0';
  return (int)svr_tag_len;
}

oc_storage_buffer_t
oc_storage_get_buffer(size_t size)
{
  oc_storage_buffer_t buf = { NULL, 0 };
#ifdef OC_APP_DATA_STORAGE_BUFFER
  (void)size;
  buf.buffer = g_oc_storage_buf;
  buf.size = sizeof(g_oc_storage_buf);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  buf.buffer = malloc(size);
  if (buf.buffer == NULL) {
    return buf;
  }
  buf.size = size;
#endif /* OC_APP_DATA_STORAGE_BUFFER */
  return buf;
}

void
oc_storage_free_buffer(oc_storage_buffer_t sb)
{
#ifdef OC_APP_DATA_STORAGE_BUFFER
  (void)sb;
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  free(sb.buffer);
#endif /* OC_APP_DATA_STORAGE_BUFFER */
}

long
oc_storage_data_load(const char *name, size_t device,
                     oc_decode_from_storage_fn_t decode, void *decode_data)
{
  assert(decode != NULL);
  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  if (oc_storage_gen_svr_tag(name, device, svr_tag, sizeof(svr_tag)) < 0) {
    OC_ERR("cannot load from \"%s\" from store: cannot generate svr tag", name);
    return -1;
  }

  oc_storage_buffer_t buf = oc_storage_get_buffer(OC_MAX_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (buf.buffer == NULL) {
    OC_ERR("cannot load from \"%s\" from store: cannot allocate buffer", name);
    return -1;
  }
#endif /* !OC_APP_DATA_STORAGE_BUFFER */

  long ret = oc_storage_read(svr_tag, buf.buffer, buf.size);
  if (ret <= 0) {
#if OC_DBG_IS_ENABLED
    if (ret < 0) {
      OC_DBG("cannot load from \"%s\" from store: read error(%ld)", name, ret);
    } else {
      OC_DBG("cannot load from \"%s\" from store: no data", name);
    }
#endif /* OC_DBG_IS_ENABLED */
    oc_storage_free_buffer(buf);
    return -1;
  }
  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
  oc_rep_t *rep = NULL;
  if (oc_parse_rep(buf.buffer, (int)ret, &rep) != 0) {
    OC_ERR("cannot load from \"%s\" from store: cannot parse representation",
           name);
    goto error;
  }
  if (rep != NULL && decode(rep, device, decode_data) != 0) {
    OC_ERR("cannot load from \"%s\" from store: cannot decode data", name);
    goto error;
  }
  oc_free_rep(rep);
  oc_rep_set_pool(prev_rep_objects);
  oc_storage_free_buffer(buf);
  return ret;

error:
  oc_free_rep(rep);
  oc_rep_set_pool(prev_rep_objects);
  oc_storage_free_buffer(buf);
  return -1;
}

#if OC_DBG_IS_ENABLED

static void
storage_print_data(const uint8_t *buf, size_t size)
{
  // GCOVR_EXCL_START
  if (size == 0) {
    return;
  }
  oc_rep_decoder_t decoder = oc_rep_decoder(OC_REP_CBOR_DECODER);
  OC_MEMB_LOCAL(rep_objects, oc_rep_t, OC_MAX_NUM_REP_OBJECTS);
  struct oc_memb *prev_rep_objects = oc_rep_reset_pool(&rep_objects);
  oc_rep_t *rep = NULL;
  if (CborNoError != decoder.parse(buf, size, &rep)) {
    return;
  }
#ifdef OC_DYNAMIC_ALLOCATION
  size_t json_size = oc_rep_to_json(rep, NULL, 0, true);
  char *json = (char *)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, true);
#else  /* !OC_DYNAMIC_ALLOCATION */
  char json[4096] = { 0 };
  oc_rep_to_json(rep, json, OC_ARRAY_SIZE(json), true);
#endif /* OC_DYNAMIC_ALLOCATION */
  OC_DBG("payload %s", json);
#ifdef OC_DYNAMIC_ALLOCATION
  free(json);
#endif /* OC_DYNAMIC_ALLOCATION */
  oc_free_rep(rep);
  oc_rep_set_pool(prev_rep_objects);
  // GCOVR_EXCL_STOP
}

#endif /* OC_DBG_IS_ENABLED */

long
oc_storage_data_save(const char *name, size_t device,
                     oc_encode_to_storage_fn_t encode, void *encode_data)
{
  assert(encode != NULL);

  oc_storage_buffer_t sb = oc_storage_get_buffer(OC_MIN_APP_DATA_SIZE);
#ifndef OC_APP_DATA_STORAGE_BUFFER
  if (sb.buffer == NULL) {
    OC_ERR("cannot dump \"%s\" to storage: cannot allocate buffer", name);
    return -1;
  }
  oc_rep_new_realloc_v1(&sb.buffer, OC_MIN_APP_DATA_SIZE, OC_MAX_APP_DATA_SIZE);
#else  /* !OC_APP_DATA_STORAGE_BUFFER */
  oc_rep_new_v1(sb.buffer, OC_MIN_APP_DATA_SIZE);
#endif /* OC_APP_DATA_STORAGE_BUFFER */

  if (encode(device, encode_data) != 0 ||
      oc_rep_get_cbor_errno() != CborNoError) {
    OC_ERR("cannot dump \"%s\" to storage: cannot encode data", name);
    goto error;
  }
#ifndef OC_APP_DATA_STORAGE_BUFFER
  sb.buffer = oc_rep_shrink_encoder_buf(sb.buffer);
  sb.size = (size_t)oc_rep_get_encoder_buffer_size();
#endif /* !OC_APP_DATA_STORAGE_BUFFER */
  int size = oc_rep_get_encoded_payload_size();
  if (size < 0) {
    OC_ERR("cannot dump \"%s\" to storage: invalid payload", name);
    goto error;
  }
#if OC_DBG_IS_ENABLED
  OC_DBG("oc_storage: encoded \"%s\" size %d", name, size);
  storage_print_data(sb.buffer, size);
#endif /* OC_DBG_IS_ENABLED */

  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  if (oc_storage_gen_svr_tag(name, device, svr_tag, sizeof(svr_tag)) < 0) {
    OC_ERR("cannot dump \"%s\" to storage: cannot generate svr tag", name);
    goto error;
  }
  long ret = oc_storage_write(svr_tag, sb.buffer, size);
  oc_storage_free_buffer(sb);
  return ret;

error:
  oc_storage_free_buffer(sb);
  return -1;
}

bool
oc_storage_data_clear(const char *name, size_t device)
{
  char svr_tag[OC_STORAGE_SVR_TAG_MAX];
  if (oc_storage_gen_svr_tag(name, device, svr_tag, sizeof(svr_tag)) < 0) {
    OC_ERR("cannot clear \"%s\" from store: cannot generate svr tag", name);
    return false;
  }
  return oc_storage_write(svr_tag, (const uint8_t *)"", 0) == 0;
}

#endif /* OC_STORAGE */

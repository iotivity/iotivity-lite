/*
// Copyright (c) 2020 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifndef OC_OSCORE_CONTEXT_H
#define OC_OSCORE_CONTEXT_H

#include <stddef.h>
#include <inttypes.h>
#include <stdbool.h>
#include "oc_uuid.h"
#include "messaging/coap/oscore_constants.h"
#include "oc_helpers.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct oc_oscore_context_t
{
  struct oc_oscore_context_t *next;
  /* Provisioned parameters */
  void *cred; /* cred entry contains the master secret */
  size_t device;
  uint8_t sendid[OSCORE_CTXID_LEN];
  uint8_t sendid_len;
  uint8_t recvid[OSCORE_CTXID_LEN];
  uint8_t recvid_len;
  uint64_t ssn;
  uint8_t idctx[OSCORE_IDCTX_LEN];
  uint8_t idctx_len;
  oc_string_t desc;
  /* Derived parameters */
  /* 128-bit keys */
  uint8_t sendkey[OSCORE_KEY_LEN];
  uint8_t recvkey[OSCORE_KEY_LEN];
  /* Common IV */
  uint8_t commoniv[OSCORE_COMMON_IV_LEN];
  /* Replay Window */
  uint64_t rwin[OSCORE_REPLAY_WINDOW_SIZE];
  uint8_t rwin_idx;
} oc_oscore_context_t;

int oc_oscore_context_derive_param(const uint8_t *id, uint8_t id_len,
                                   uint8_t *id_ctx, uint8_t id_ctx_len,
                                   const char *type, uint8_t *secret,
                                   uint8_t secret_len, uint8_t *salt,
                                   uint8_t salt_len, uint8_t *param,
                                   uint8_t param_len);

void oc_oscore_free_context(oc_oscore_context_t *ctx);

oc_oscore_context_t *oc_oscore_add_context(size_t device, const char *senderid,
                                           const char *recipientid,
                                           uint64_t ssn, const char *desc,
                                           void *cred, bool from_storagw);

oc_oscore_context_t *oc_oscore_find_context_by_UUID(size_t device,
                                                    oc_uuid_t *uuid);

oc_oscore_context_t *oc_oscore_find_context_by_kid(oc_oscore_context_t *ctx,
                                                   size_t device, uint8_t *kid,
                                                   uint8_t kid_len);

oc_oscore_context_t *oc_oscore_find_context_by_token_mid(
  size_t device, uint8_t *token, uint8_t token_len, uint16_t mid,
  uint8_t **request_piv, uint8_t *request_piv_len, bool tcp);

oc_oscore_context_t *oc_oscore_find_group_context(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_OSCORE_CONTEXT_H */

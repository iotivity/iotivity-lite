/*
// Copyright (c) 2017 Intel Corporation
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

#ifndef OC_DTLS_H
#define OC_DTLS_H

#include "mbedtls/ssl.h"

#include "oc_uuid.h"
#include "port/oc_connectivity.h"
#include "util/oc_etimer.h"
#include "util/oc_list.h"
#include "util/oc_process.h"
#include <stdbool.h>

OC_PROCESS_NAME(oc_dtls_handler);

void oc_sec_dtls_close_connection(oc_endpoint_t *endpoint);
int oc_sec_dtls_update_psk_identity(int device);
bool oc_sec_derive_owner_psk(oc_endpoint_t *endpoint, const uint8_t *oxm,
                             const size_t oxm_len, const uint8_t *server_uuid,
                             const size_t server_uuid_len,
                             const uint8_t *obt_uuid, const size_t obt_uuid_len,
                             uint8_t *key, const size_t key_len);
int oc_sec_dtls_init_context(void);
int oc_sec_dtls_send_message(oc_message_t *message);
oc_uuid_t *oc_sec_dtls_get_peer_uuid(oc_endpoint_t *endpoint);
bool oc_sec_dtls_connected(oc_endpoint_t *endpoint);
void oc_sec_dtls_elevate_anon_ciphersuite(void);
void oc_sec_dtls_demote_anon_ciphersuite(void);

typedef struct
{
  struct oc_etimer fin_timer;
  oc_clock_time_t int_ticks;
} oc_sec_dtls_retr_timer_t;

typedef struct oc_sec_dtls_peer_s
{
  struct oc_sec_dtls_peer_s *next;
  OC_LIST_STRUCT(recv_q);
  OC_LIST_STRUCT(send_q);
  mbedtls_ssl_context ssl_ctx;
  oc_endpoint_t endpoint;
  int role;
  oc_sec_dtls_retr_timer_t timer;
  uint8_t master_secret[48];
  uint8_t client_server_random[64];
  oc_uuid_t uuid;
  oc_clock_time_t timestamp;
} oc_sec_dtls_peer_t;

#endif /* OC_DTLS_H */

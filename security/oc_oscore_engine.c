/****************************************************************************
 *
 * Copyright (c) 2020 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#if defined(OC_SECURITY) && defined(OC_OSCORE)

#include "api/oc_events_internal.h"
#include "api/oc_message_internal.h"
#include "messaging/coap/options_internal.h"
#include "messaging/coap/signal_internal.h"
#include "messaging/coap/engine_internal.h"
#include "messaging/coap/oscore_internal.h"
#include "messaging/coap/transactions_internal.h"
#include "oc_api.h"
#include "oc_client_state.h"
#include "oc_oscore_internal.h"
#include "oc_oscore_context_internal.h"
#include "oc_oscore_crypto_internal.h"
#include "oc_pstat_internal.h"
#include "oc_store.h"
#include "oc_tls_internal.h"
#include "util/oc_process.h"

#include <mbedtls/ccm.h>

#include <inttypes.h>

OC_PROCESS(oc_oscore_handler, "OSCORE Process");

static oc_event_callback_retval_t
dump_cred(void *data)
{
  size_t device = (size_t)data;
  oc_sec_dump_cred(device);
  return OC_EVENT_DONE;
}

static bool
check_if_replayed_request(oc_oscore_context_t *oscore_ctx, uint64_t piv)
{
  if (piv == 0 && oscore_ctx->rwin[0] == 0 &&
      oscore_ctx->rwin[OSCORE_REPLAY_WINDOW_SIZE - 1] == 0) {
    goto fresh_request;
  }
  for (uint8_t i = 0; i < OSCORE_REPLAY_WINDOW_SIZE; i++) {
    if (oscore_ctx->rwin[i] == piv) {
      return true;
    }
  }
fresh_request:
  oscore_ctx->rwin_idx = (oscore_ctx->rwin_idx + 1) % OSCORE_REPLAY_WINDOW_SIZE;
  oscore_ctx->rwin[oscore_ctx->rwin_idx] = piv;
  return false;
}

static bool
oscore_parse_and_process_inner_message(const oc_message_t *message,
                                       const coap_packet_t *oscore_pkt,
                                       bool is_mcast_server,
                                       coap_packet_t *coap_pkt)
{
  OC_DBG("### parse inner message ###");

  /* Parse inner (CoAP) message from the decrypted OSCORE payload */
  coap_status_t st = oscore_parse_inner_message(
    oscore_pkt->payload, oscore_pkt->payload_len, coap_pkt);

  if (st != COAP_NO_ERROR) {
    OC_ERR("***error parsing inner message***");
    oscore_send_error(oscore_pkt, BAD_OPTION_4_02, &message->endpoint);
    return false;
  }

  OC_DBG("### successfully parsed inner message ###");

  if (is_mcast_server && coap_pkt->code != OC_POST) {
    OC_ERR("***non-UPDATE multicast request protected using group OSCORE "
           "context; silently ignore***");
    return false;
  }

  /* Copy type, version, mid, token, observe fields from OSCORE packet to
   * CoAP Packet */
  coap_pkt->transport_type = oscore_pkt->transport_type;
  coap_pkt->version = oscore_pkt->version;
  coap_pkt->type = oscore_pkt->type;
  coap_pkt->mid = oscore_pkt->mid;
  memcpy(coap_pkt->token, oscore_pkt->token, oscore_pkt->token_len);
  coap_pkt->token_len = oscore_pkt->token_len;
  coap_pkt->observe = oscore_pkt->observe;

  return true;
}

static bool
oscore_parse_message(oc_message_t *message)
{
  OC_DBG("#################################");
  message->endpoint.flags |= SECURED;

  coap_packet_t oscore_pkt;
  /* Parse OSCORE message */
  OC_DBG("### parse OSCORE message ###");
  coap_status_t st = oscore_parse_outer_message(message, &oscore_pkt);

  if (st != COAP_NO_ERROR) {
    OC_ERR("***error parsing OSCORE message***");
    oscore_send_error(&oscore_pkt, BAD_OPTION_4_02, &message->endpoint);
    return false;
  }

  OC_DBG("### parsed OSCORE message ###");

  if (oscore_pkt.transport_type == COAP_TRANSPORT_UDP &&
      oscore_pkt.code <= OC_FETCH &&
      oc_coap_check_if_duplicate(&message->endpoint, oscore_pkt.mid)) {
    OC_DBG("dropping duplicate request");
    return false;
  }

  oc_oscore_context_t *oscore_ctx = NULL;
  const uint8_t *request_piv = NULL;
  uint8_t request_piv_len = 0;
  /* If OSCORE packet contains kid... */
  if (oscore_pkt.kid_len > 0) {
    /* Search for OSCORE context by kid */
    OC_DBG("--- got kid from incoming message");
    OC_LOGbytes(oscore_pkt.kid, oscore_pkt.kid_len);
    OC_DBG("### searching for OSCORE context by kid ###");
    oscore_ctx = oc_oscore_find_context_by_kid(
      oscore_ctx, message->endpoint.device, oscore_pkt.kid, oscore_pkt.kid_len);
  } else {
    if (oscore_pkt.code <= OC_FETCH) {
      /* OSCORE message is request and lacks kid, return error */
      OC_ERR("***OSCORE protected request lacks kid param***");
      oscore_send_error(&oscore_pkt, BAD_OPTION_4_02, &message->endpoint);
      return false;
    }

    /* If message is response */
    /* Search for OSCORE context by token */
    OC_DBG("### searching for OSCORE context by token ###");
    oscore_ctx = oc_oscore_find_context_by_token_mid(
      message->endpoint.device, oscore_pkt.token, oscore_pkt.token_len,
      oscore_pkt.mid, &request_piv, &request_piv_len,
      message->endpoint.flags & TCP);
  }

  if (!oscore_ctx) {
    OC_ERR("***could not find matching OSCORE context***");
    oscore_send_error(&oscore_pkt, UNAUTHORIZED_4_01, &message->endpoint);
    return false;
  }

  const oc_sec_cred_t *c = (oc_sec_cred_t *)oscore_ctx->cred;
  if ((message->endpoint.flags & MULTICAST) == 0 &&
      c->credtype != OC_CREDTYPE_OSCORE) {
    OC_ERR("***unicast message protected using group OSCORE context; "
           "silently ignore***");
    return false;
  }

  /* Copy "subjectuuid" of cred with OSCORE context to oc_endpoint_t */
  const oc_sec_cred_t *oscore_cred = (const oc_sec_cred_t *)oscore_ctx->cred;
  memcpy(message->endpoint.di.id, oscore_cred->subjectuuid.id,
         sizeof(oscore_cred->subjectuuid.id));

  /* Use recipient key for decryption */
  const uint8_t *key = oscore_ctx->recvkey;
  uint8_t AAD[OSCORE_AAD_MAX_LEN];
  uint8_t AAD_len = 0;
  uint8_t nonce[OSCORE_AEAD_NONCE_LEN] = { 0 };
  /* If received Partial IV in message */
  if (oscore_pkt.piv_len > 0) {
    /* If message is request */
    if (oscore_pkt.code >= OC_GET && oscore_pkt.code <= OC_FETCH) {
      /* Check if this is a repeat request and discard */
      uint64_t piv = 0;
      oscore_read_piv(oscore_pkt.piv, oscore_pkt.piv_len, &piv);
      if (check_if_replayed_request(oscore_ctx, piv)) {
        oscore_send_error(&oscore_pkt, UNAUTHORIZED_4_01, &message->endpoint);
        return false;
      }

      /* Compose AAD using received piv and context->recvid */
      oc_oscore_compose_AAD(oscore_ctx->recvid, oscore_ctx->recvid_len,
                            oscore_pkt.piv, oscore_pkt.piv_len, AAD, &AAD_len);
      OC_DBG("---composed AAD using received Partial IV and Recipient ID");
      OC_LOGbytes(AAD, AAD_len);
    }

    /* Copy received piv into oc_message_t->endpoint */
    memcpy(message->endpoint.piv, oscore_pkt.piv, oscore_pkt.piv_len);
    message->endpoint.piv_len = oscore_pkt.piv_len;

    OC_DBG("---got Partial IV from incoming message");
    OC_LOGbytes(message->endpoint.piv, message->endpoint.piv_len);

    /* Compute nonce using received piv and context->recvid */
    oc_oscore_AEAD_nonce(oscore_ctx->recvid, oscore_ctx->recvid_len,
                         message->endpoint.piv, message->endpoint.piv_len,
                         oscore_ctx->commoniv, nonce, OSCORE_AEAD_NONCE_LEN);

    OC_DBG("---computed AEAD nonce using received Partial IV and Recipient ID");
    OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);
  }

  /* If message is response */
  if (oscore_pkt.code > OC_FETCH) {
    OC_DBG("---got request_piv from client callback");
    OC_LOGbytes(request_piv, request_piv_len);

    if (message->endpoint.piv_len == 0) {
      /* Copy request_piv from client cb/transaction into
       * oc_message_t->endpoint */
      if (request_piv != NULL) {
        memcpy(message->endpoint.piv, request_piv, request_piv_len);
      }
      message->endpoint.piv_len = request_piv_len;

      /* Compute nonce using request_piv and context->sendid */
      oc_oscore_AEAD_nonce(oscore_ctx->sendid, oscore_ctx->sendid_len,
                           request_piv, request_piv_len, oscore_ctx->commoniv,
                           nonce, OSCORE_AEAD_NONCE_LEN);

      OC_DBG("---use AEAD nonce from request");
      OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);
    }

    /* Compose AAD using request_piv and context->sendid */
    oc_oscore_compose_AAD(oscore_ctx->sendid, oscore_ctx->sendid_len,
                          request_piv, request_piv_len, AAD, &AAD_len);

    OC_DBG("---composed AAD using request_piv and Sender ID");
    OC_LOGbytes(AAD, AAD_len);
  }

  OC_DBG("### decrypting OSCORE payload ###");

  /* Verify and decrypt OSCORE payload */

  int ret =
    oc_oscore_decrypt(oscore_pkt.payload, oscore_pkt.payload_len,
                      OSCORE_AEAD_TAG_LEN, key, OSCORE_KEY_LEN, nonce,
                      OSCORE_AEAD_NONCE_LEN, AAD, AAD_len, oscore_pkt.payload);

  if (ret != 0) {
    OC_ERR("***error decrypting/verifying response : (%d)***", ret);
    oscore_send_error(&oscore_pkt, BAD_REQUEST_4_00, &message->endpoint);
    return false;
  }

  OC_DBG("### successfully decrypted OSCORE payload ###");

  /* Adjust payload length to size after decryption (i.e. exclude the tag)
   */
  oscore_pkt.payload_len -= OSCORE_AEAD_TAG_LEN;

  coap_packet_t coap_pkt;
  if (!oscore_parse_and_process_inner_message(
        message, &oscore_pkt, c->credtype == OC_CREDTYPE_OSCORE_MCAST_SERVER,
        &coap_pkt)) {
    return false;
  }

  OC_DBG("### serializing CoAP message ###");
  /* Serialize fully decrypted CoAP packet to message->data buffer */
  message->length =
    coap_serialize_message(&coap_pkt, message->data, oc_message_buffer_size());

  OC_DBG("### serialized decrypted CoAP message to dispatch to the CoAP "
         "layer ###");
  return true;
}

static int
oc_oscore_recv_message(oc_message_t *message)
{
  /* OSCORE layer receive path pseudocode
   * ------------------------------------
   * If incoming oc_message_t is an OSCORE message:
   *   OSCORE context = nil
   *   Parse OSCORE message
   *   If parse unsuccessful:
   *     Discard message and return error
   *   If packet is a request and is received over UDP:
   *     Check if packet is duplicate by mid; if so, discard
   *   If received kid param:
   *     Search for OSCORE context by kid
   *   Else:
   *     If message is response:
   *       Search for OSCORE context by token
   *     Else:
   *       OSCORE request lacks kid param; Return error
   *   If OSCORE context is nil, return error
   *   If unicast message protected using group OSCORE context, silently ignore
   *   Copy subjectuuid of OSCORE cred entry into oc_message_t->endpoint
   *   Set context->recvkey as the decryption key
   *   If received partial IV:
   *     If message is request:
   *       Check if replayed request and discard
   *       Compose AAD using received piv and context->recvid
   *     Copy received piv into oc_message_t->endpoint
   *     Compute nonce using received piv and context->recvid
   *   If message is response:
   *     if oc_message_t->endpoint.piv is 0:
   *       Copy request_piv from client cb/transaction into
   oc_message_t->endpoint
   *       Compute nonce using request_piv and sendid
   *     Compose AAD using request_piv and sendid
   *   Decrypt OSCORE payload
   *   Parse inner/protected CoAP options/payload
   *   If non-UPDATE mcast message protected using OSCORE group context,
   silently ignore
   *   Copy fields: type, version, mid, token, observe from the OSCORE packet to
   *   CoAP Packet
   *   Serialize full CoAP packet to oc_message
   * Dispatch oc_message_t to the CoAP layer
   */

  if (oscore_is_oscore_message(message) >= 0 &&
      !oscore_parse_message(message)) {
    goto oscore_recv_error;
  }
  OC_DBG("#################################");

  /* Dispatch oc_message_t to the CoAP layer */
  if (oc_process_post(&g_coap_engine,
                      oc_event_to_oc_process_event(INBOUND_RI_EVENT),
                      message) == OC_PROCESS_ERR_FULL) {
    goto oscore_recv_error;
  }
  return 0;

oscore_recv_error:
  oc_message_unref(message);
  return -1;
}

#ifdef OC_CLIENT
static int
oc_oscore_send_multicast_message(oc_message_t *message)
{
  /* OSCORE layer secure multicast pseudocode
   * ----------------------------------------
   * Search for group OSCORE context
   * If found OSCORE context:
   *   Set context->sendkey as the encryption key
   *   Parse CoAP message
   *   If parse unsuccessful, return error
   *   Use context->SSN as partial IV
   *   Use context-sendid as kid
   *   Compute nonce using partial IV and context->sendid
   *   Compute AAD using partial IV and context->sendid
   *   Make room for inner options and payload by moving CoAP payload to offset
   *    2 * COAP_MAX_HEADER_SIZE
   *   Serialize OSCORE plaintext at offset COAP_MAX_HEADER_SIZE
   *   Encrypt OSCORE plaintext at offset COAP_MAX_HEADER_SIZE
   *   Set OSCORE packet payload to location COAP_MAX_HEADER_SIZE
   *   Set OSCORE packet payload length to the plaintext size + tag length (8)
   *   Set OSCORE option in OSCORE packet
   *   Serialize OSCORE message to oc_message_t
   * Dispatch oc_message_t to IP layer
   */
  oc_oscore_context_t *oscore_ctx = oc_oscore_find_group_context();

  if (oscore_ctx) {
    OC_DBG("#################################");
    OC_DBG("found group OSCORE context");

    /* Use sender key for encryption */
    const uint8_t *key = oscore_ctx->sendkey;

    OC_DBG("### parse CoAP message ###");
    /* Parse CoAP message */
    coap_packet_t coap_pkt[1];
    coap_status_t code = 0;
    code =
      coap_udp_parse_message(coap_pkt, message->data, message->length, false);

    if (code != COAP_NO_ERROR) {
      OC_ERR("***error parsing CoAP packet***");
      goto oscore_group_send_error;
    }

    OC_DBG("### parsed CoAP message ###");
    OC_DBG("### protecting multicast request ###");
    /* Use context->SSN as Partial IV */
    uint8_t piv[OSCORE_PIV_LEN];
    uint8_t piv_len = 0;
    oscore_store_piv(oscore_ctx->ssn, piv, &piv_len);
    OC_DBG("---using SSN as Partial IV: %" PRIu64, oscore_ctx->ssn);
    OC_LOGbytes(piv, piv_len);
    /* Increment SSN */
    oscore_ctx->ssn++;

    /* Use context-sendid as kid */
    uint8_t kid[OSCORE_CTXID_LEN];
    uint8_t kid_len = 0;
    memcpy(kid, oscore_ctx->sendid, oscore_ctx->sendid_len);
    kid_len = oscore_ctx->sendid_len;

    /* Compute nonce using partial IV and context->sendid */
    uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
    oc_oscore_AEAD_nonce(oscore_ctx->sendid, oscore_ctx->sendid_len, piv,
                         piv_len, oscore_ctx->commoniv, nonce,
                         OSCORE_AEAD_NONCE_LEN);

    OC_DBG("---computed AEAD nonce using Partial IV (SSN) and Sender ID");
    OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);

    /* Compose AAD using partial IV and context->sendid */
    uint8_t AAD[OSCORE_AAD_MAX_LEN];
    uint8_t AAD_len = 0;
    oc_oscore_compose_AAD(oscore_ctx->sendid, oscore_ctx->sendid_len, piv,
                          piv_len, AAD, &AAD_len);
    OC_DBG("---composed AAD using Partial IV (SSN) and Sender ID");
    OC_LOGbytes(AAD, AAD_len);

    /* Move CoAP payload to offset 2*COAP_MAX_HEADER_SIZE to accommodate for
       Outer+Inner CoAP options in the OSCORE packet.
    */
    if (coap_pkt->payload_len > 0) {
      memmove(message->data + 2UL * COAP_MAX_HEADER_SIZE, coap_pkt->payload,
              coap_pkt->payload_len);

      /* Store the new payload location in the CoAP packet */
      coap_pkt->payload = message->data + 2UL * COAP_MAX_HEADER_SIZE;
    }

    OC_DBG("### serializing OSCORE plaintext ###");
    /* Serialize OSCORE plaintext at offset COAP_MAX_HEADER_SIZE
       (code, inner options, payload)
    */
    uint8_t *buffer = message->data + COAP_MAX_HEADER_SIZE;
    size_t buffer_size = oc_message_buffer_size() - COAP_MAX_HEADER_SIZE;
    size_t plaintext_size =
      oscore_serialize_plaintext(coap_pkt, buffer, buffer_size);

    OC_DBG("### serialized OSCORE plaintext: %zd bytes ###", plaintext_size);

    /* Set the OSCORE packet payload to point to location of the serialized
       inner message.
    */
    coap_pkt->payload = buffer;
    coap_pkt->payload_len = plaintext_size;

    /* Encrypt OSCORE plaintext */
    OC_DBG("### encrypting OSCORE plaintext ###");

    int ret =
      oc_oscore_encrypt(coap_pkt->payload, coap_pkt->payload_len,
                        OSCORE_AEAD_TAG_LEN, key, OSCORE_KEY_LEN, nonce,
                        OSCORE_AEAD_NONCE_LEN, AAD, AAD_len, coap_pkt->payload);

    if (ret != 0) {
      OC_ERR("***error encrypting OSCORE plaintext***");
      goto oscore_group_send_error;
    }

    OC_DBG("### successfully encrypted OSCORE plaintext ###");

    /* Adjust payload length to include the size of the authentication tag */
    coap_pkt->payload_len += OSCORE_AEAD_TAG_LEN;

    /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
    coap_pkt->code = OC_POST;

    /* Set the OSCORE option */
    coap_set_header_oscore(coap_pkt, piv, piv_len, kid, kid_len, NULL, 0);

    /* Serialize OSCORE message to oc_message_t */
    OC_DBG("### serializing OSCORE message ###");
    message->length = oscore_serialize_message(coap_pkt, message->data,
                                               oc_message_buffer_size());
    OC_DBG("### serialized OSCORE message ###");
  } else {
    OC_ERR("*** could not find group OSCORE context ***");
    goto oscore_group_send_error;
  }

  OC_DBG("#################################");
  /* Dispatch oc_message_t to the IP layer */
  OC_DBG("Outbound network event: forwarding to IP Connectivity layer");
  oc_send_discovery_request(message);
  oc_message_unref(message);
  return 0;

oscore_group_send_error:
  OC_ERR("received malformed CoAP packet from stack");
  oc_message_unref(message);
  return -1;
}
#endif /* OC_CLIENT */

static int
oc_oscore_send_message(oc_message_t *msg)
{
  /* OSCORE layer sending path pseudocode
   * ------------------------------------
   * Search for OSCORE context by peer UUID
   * If found OSCORE context:
   *   Set context->sendkey as the encryption key
   *   Clone incoming oc_message_t (*msg) from CoAP layer
   *   Parse CoAP message
   *   If parse unsuccessful, return error
   *   If CoAP message is request:
   *     Search for client cb by request token
   *     If found client cb:
   *       Use context->SSN as partial IV
   *       Use context-sendid as kid
   *       Copy partial IV into client cb
   *       Compute nonce using partial IV and context->sendid
   *       Compute AAD using partial IV and context->sendid
   *       Copy partial IV into incoming oc_message_t (*msg), if valid
   *     Else:
   *       Return error
   *   Else: (CoAP message is response)
   *     Use context->SSN as partial IV
   *     Coompute nonce using partial IV and context->sendid
   *     Compute AAD using request_piv and context->recvid
   *     Copy partial IV into incoming oc_message_t (*msg), if valid
   *    Make room for inner options and payload by moving CoAP payload to offset
   *    2 * COAP_MAX_HEADER_SIZE
   *    Store Observe option; if message is a notification, make Observe option
   *    value empty
   *    Serialize OSCORE plaintext at offset COAP_MAX_HEADER_SIZE
   *    Encrypt OSCORE plaintext at offset COAP_MAX_HEADER_SIZE
   *    Set OSCORE packet payload to location COAP_MAX_HEADER_SIZE
   *    Set OSCORE packet payload length to the plaintext size + tag length (8)
   *    Set OSCORE option in OSCORE packet
   *    Reflect the Observe option (if present in the CoAP packet)
   *    Set the Proxy-uri option to the OCF URI bearing the peer's UUID
   *    Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05)
   *    Serialize OSCORE message to oc_message_t
   * Dispatch oc_message_t to the TLS layer
   */
  oc_message_t *message = msg;
  oc_oscore_context_t *oscore_ctx = oc_oscore_find_context_by_UUID(
    message->endpoint.device, &message->endpoint.di);

  if (oscore_ctx) {
    OC_DBG("#################################");
    OC_DBG("found OSCORE context corresponding to the peer UUID");
    /* Is this is an inadvertent response to a secure multicast message */
    if (msg->endpoint.flags & MULTICAST) {
      OC_DBG("### secure multicast requests do not elicit a response, discard "
             "###");
      oc_message_unref(msg);
      return 0;
    }

    /* Use sender key for encryption */
    const uint8_t *key = oscore_ctx->sendkey;

    /* Clone incoming oc_message_t (*msg) from CoAP layer */
    message = oc_message_allocate_outgoing();
    message->length = msg->length;
    memcpy(message->data, msg->data, msg->length);
    memcpy(&message->endpoint, &msg->endpoint, sizeof(oc_endpoint_t));

    bool msg_valid = false;
    if (msg->ref_count > 1) {
      msg_valid = true;
    }

    oc_message_unref(msg);

    OC_DBG("### parse CoAP message ###");
    /* Parse CoAP message */
    coap_packet_t coap_pkt[1];
    coap_status_t code = 0;
#ifdef OC_TCP
    if (message->endpoint.flags & TCP) {
      code =
        coap_tcp_parse_message(coap_pkt, message->data, message->length, false);
    } else
#endif /* OC_TCP */
    {
      code =
        coap_udp_parse_message(coap_pkt, message->data, message->length, false);
    }

    if (code != COAP_NO_ERROR) {
      OC_ERR("***error parsing CoAP packet***");
      goto oscore_send_error;
    }

    OC_DBG("### parsed CoAP message ###");
    uint8_t piv[OSCORE_PIV_LEN];
    uint8_t piv_len = 0;
    uint8_t kid[OSCORE_CTXID_LEN];
    uint8_t kid_len = 0;
    uint8_t nonce[OSCORE_AEAD_NONCE_LEN];
    uint8_t AAD[OSCORE_AAD_MAX_LEN];
    uint8_t AAD_len = 0;
    /* If CoAP message is request */
    if ((coap_pkt->code >= OC_GET && coap_pkt->code <= OC_DELETE)
#ifdef OC_TCP
        || coap_pkt->code == PING_7_02 || coap_pkt->code == ABORT_7_05 ||
        coap_pkt->code == CSM_7_01
#endif /* OC_TCP */
    ) {
      const oc_sec_pstat_t *pstat = oc_sec_get_pstat(message->endpoint.device);
      if (pstat->s != OC_DOS_RFNOP) {
        OC_ERR("### device not in RFNOP; stop further processing ###");
        goto oscore_send_error;
      }

      OC_DBG("### protecting outgoing request ###");
      /* Request */
      /* Use context->SSN as Partial IV */
      oscore_store_piv(oscore_ctx->ssn, piv, &piv_len);
      OC_DBG("---using SSN as Partial IV: %" PRIu64, oscore_ctx->ssn);
      OC_LOGbytes(piv, piv_len);
      /* Increment SSN */
      oscore_ctx->ssn++;

#ifdef OC_CLIENT
      if (coap_pkt->code >= OC_GET && coap_pkt->code <= OC_DELETE) {
        /* Find client cb for the request */
        oc_client_cb_t *cb =
          oc_ri_find_client_cb_by_token(coap_pkt->token, coap_pkt->token_len);

        if (!cb) {
          OC_ERR("**could not find client callback corresponding to request**");
          goto oscore_send_error;
        }

        /* Copy partial IV into client cb */
        memcpy(cb->piv, piv, piv_len);
        cb->piv_len = piv_len;
      }
#endif /* OC_CLIENT */

      /* Use context-sendid as kid */
      memcpy(kid, oscore_ctx->sendid, oscore_ctx->sendid_len);
      kid_len = oscore_ctx->sendid_len;

      /* Compute nonce using partial IV and context->sendid */
      oc_oscore_AEAD_nonce(oscore_ctx->sendid, oscore_ctx->sendid_len, piv,
                           piv_len, oscore_ctx->commoniv, nonce,
                           OSCORE_AEAD_NONCE_LEN);

      OC_DBG("---computed AEAD nonce using Partial IV (SSN) and Sender ID");
      OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);

      /* Compose AAD using partial IV and context->sendid */
      oc_oscore_compose_AAD(oscore_ctx->sendid, oscore_ctx->sendid_len, piv,
                            piv_len, AAD, &AAD_len);
      OC_DBG("---composed AAD using Partial IV (SSN) and Sender ID");
      OC_LOGbytes(AAD, AAD_len);

      /* Copy partial IV into incoming oc_message_t (*msg), if valid */
      if (msg_valid) {
        memcpy(msg->endpoint.piv, piv, piv_len);
        msg->endpoint.piv_len = piv_len;
      }
    } else {
      /* Request was not protected by OSCORE */
      if (message->endpoint.piv_len == 0) {
        OC_DBG("request was not protected by OSCORE");
        goto oscore_send_dispatch;
      }
      OC_DBG("### protecting outgoing response ###");
      /* Response */
      /* Per OCF specification, all responses must include a new Partial IV */
      /* Use context->SSN as partial IV */
      oscore_store_piv(oscore_ctx->ssn, piv, &piv_len);
      OC_DBG("---using SSN as Partial IV: %" PRIu64, oscore_ctx->ssn);
      OC_LOGbytes(piv, piv_len);

      /* Increment SSN */
      oscore_ctx->ssn++;

      /* Coompute nonce using partial IV and context->sendid */
      oc_oscore_AEAD_nonce(oscore_ctx->sendid, oscore_ctx->sendid_len, piv,
                           piv_len, oscore_ctx->commoniv, nonce,
                           OSCORE_AEAD_NONCE_LEN);

      OC_DBG("---computed AEAD nonce using new Partial IV (SSN) and Sender ID");
      OC_LOGbytes(nonce, OSCORE_AEAD_NONCE_LEN);

      OC_DBG("---request_piv");
      OC_LOGbytes(message->endpoint.piv, message->endpoint.piv_len);

      /* Compose AAD using request_piv and context->recvid */
      oc_oscore_compose_AAD(oscore_ctx->recvid, oscore_ctx->recvid_len,
                            message->endpoint.piv, message->endpoint.piv_len,
                            AAD, &AAD_len);
      OC_DBG("---composed AAD using request_piv and Recipient ID");
      OC_LOGbytes(AAD, AAD_len);

      /* Copy partial IV into incoming oc_message_t (*msg), if valid */
      if (msg_valid) {
        memcpy(msg->endpoint.piv, piv, piv_len);
        msg->endpoint.piv_len = piv_len;
      }
    }

    /* Store current SSN with frequency OSCORE_WRITE_FREQ_K */
    /* Based on recommendations in RFC 8613, Appendix B.1. to prevent SSN reuse
     */
    if (oscore_ctx->ssn % OSCORE_SSN_WRITE_FREQ_K == 0) {
      oc_set_delayed_callback((void *)message->endpoint.device, dump_cred, 0);
    }

    /* Move CoAP payload to offset 2*COAP_MAX_HEADER_SIZE to accommodate for
       Outer+Inner CoAP options in the OSCORE packet.
    */
    if (coap_pkt->payload_len > 0) {
      memmove(message->data + 2UL * COAP_MAX_HEADER_SIZE, coap_pkt->payload,
              coap_pkt->payload_len);

      /* Store the new payload location in the CoAP packet */
      coap_pkt->payload = message->data + 2UL * COAP_MAX_HEADER_SIZE;
    }

    /* Store the observe option. Retain the inner observe option value
     * for observe registrations and cancellations. Use an empty value for
     * notifications.
     */
    int32_t observe_option = coap_pkt->observe;
    if (coap_pkt->observe >= OC_COAP_OPTION_OBSERVE_SEQUENCE_START_VALUE) {
      coap_pkt->observe = 0;
      OC_DBG(
        "---response is a notification; making inner Observe option empty");
    }

    OC_DBG("### serializing OSCORE plaintext ###");
    /* Serialize OSCORE plaintext at offset COAP_MAX_HEADER_SIZE
       (code, inner options, payload)
    */
    uint8_t *buffer = message->data + COAP_MAX_HEADER_SIZE;
    size_t buffer_size = oc_message_buffer_size() - COAP_MAX_HEADER_SIZE;
    size_t plaintext_size =
      oscore_serialize_plaintext(coap_pkt, buffer, buffer_size);

    OC_DBG("### serialized OSCORE plaintext: %zd bytes ###", plaintext_size);

    /* Set the OSCORE packet payload to point to location of the serialized
       inner message.
    */
    coap_pkt->payload = buffer;
    coap_pkt->payload_len = plaintext_size;

    /* Encrypt OSCORE plaintext */
    OC_DBG("### encrypting OSCORE plaintext ###");

    int ret =
      oc_oscore_encrypt(coap_pkt->payload, coap_pkt->payload_len,
                        OSCORE_AEAD_TAG_LEN, key, OSCORE_KEY_LEN, nonce,
                        OSCORE_AEAD_NONCE_LEN, AAD, AAD_len, coap_pkt->payload);

    if (ret != 0) {
      OC_ERR("***error encrypting OSCORE plaintext***");
      goto oscore_send_error;
    }

    OC_DBG("### successfully encrypted OSCORE plaintext ###");

    /* Adjust payload length to include the size of the authentication tag */
    coap_pkt->payload_len += OSCORE_AEAD_TAG_LEN;

    /* Set the Outer code for the OSCORE packet (POST/FETCH:2.04/2.05) */
    coap_pkt->code = oscore_get_outer_code(coap_pkt);

    /* If outer code is 2.05, then set the Max-Age option */
    if (coap_pkt->code == CONTENT_2_05) {
      coap_options_set_max_age(coap_pkt, 0);
    }

    /* Set the OSCORE option */
    coap_set_header_oscore(coap_pkt, piv, piv_len, kid, kid_len, NULL, 0);

    /* Reflect the Observe option (if present in the CoAP packet) */
    coap_pkt->observe = observe_option;

    /* Set the Proxy-uri option to the OCF URI bearing the peer's UUID */
    char uuid[OC_UUID_LEN];
    oc_uuid_to_str(&message->endpoint.di, uuid, OC_UUID_LEN);
    oc_string_t proxy_uri;
    oc_concat_strings(&proxy_uri, "ocf://", uuid);
    coap_options_set_proxy_uri(coap_pkt, oc_string(proxy_uri),
                               oc_string_len(proxy_uri));

    /* Serialize OSCORE message to oc_message_t */
    OC_DBG("### serializing OSCORE message ###");
    message->length = oscore_serialize_message(coap_pkt, message->data,
                                               oc_message_buffer_size());
    OC_DBG("### serialized OSCORE message ###");
    oc_free_string(&proxy_uri);
  }
oscore_send_dispatch:
  OC_DBG("#################################");
  /* Dispatch oc_message_t to the TLS layer */
  OC_DBG("Outbound network event: forwarding to TLS");
  OC_DBG("Posting RI_TO_TLS_EVENT");
  oc_process_post(&oc_tls_handler,
                  oc_event_to_oc_process_event(RI_TO_TLS_EVENT), message);
  return 0;

oscore_send_error:
  OC_ERR("received malformed CoAP packet from stack");
  oc_message_unref(message);
  return -1;
}

OC_PROCESS_THREAD(oc_oscore_handler, ev, data)
{
  OC_PROCESS_BEGIN();
  while (oc_process_is_running(&oc_oscore_handler)) {
    OC_PROCESS_YIELD();

    if (ev == oc_event_to_oc_process_event(INBOUND_OSCORE_EVENT)) {
      OC_DBG("Inbound OSCORE event: encrypted request");
      oc_oscore_recv_message(data);
    } else if (ev == oc_event_to_oc_process_event(OUTBOUND_OSCORE_EVENT)) {
      OC_DBG("Outbound OSCORE event: protecting message");
      oc_oscore_send_message(data);
    }
#ifdef OC_CLIENT
    else if (ev == oc_event_to_oc_process_event(OUTBOUND_GROUP_OSCORE_EVENT)) {
      OC_DBG("Outbound OSCORE event: protecting multicast message");
      oc_oscore_send_multicast_message(data);
    }
#endif /* OC_CLIENT */
  }

  OC_PROCESS_END();
}
#else  /* OC_SECURITY && OC_OSCORE */
typedef int dummy_declaration;
#endif /* !OC_SECURITY && !OC_OSCORE */

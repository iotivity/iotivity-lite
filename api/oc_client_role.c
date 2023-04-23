/****************************************************************************
 *
 * Copyright (c) 2016 Intel Corporation
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

#include "oc_api.h"

#if defined(OC_CLIENT) && defined(OC_SECURITY) && defined(OC_PKI)

#include "oc_role.h"
#include "port/oc_log_internal.h"
#include "security/oc_roles_internal.h"

oc_role_t *
oc_get_all_roles(void)
{
  return oc_sec_get_role_creds();
}

static void
serialize_role_credential(CborEncoder *roles_array, const oc_sec_cred_t *cr)
{
  oc_rep_begin_object(roles_array, role);
  /* credtype */
  oc_rep_set_int(role, credtype, cr->credtype);
  /* roleid */
  if (oc_string_len(cr->role.role) > 0) {
    oc_rep_set_object(role, roleid);
    oc_rep_set_text_string(roleid, role, oc_string(cr->role.role));
    if (oc_string_len(cr->role.authority) > 0) {
      oc_rep_set_text_string(roleid, authority, oc_string(cr->role.authority));
    }
    oc_rep_close_object(role, roleid);
  }
  /* credusage */
  oc_rep_set_text_string(role, credusage, OC_CREDUSAGE_ROLE_CERT_STR);
  /* publicdata */
  if (oc_string_len(cr->publicdata.data) > 0) {
    oc_rep_set_object(role, publicdata);
    oc_rep_set_text_string(publicdata, data, oc_string(cr->publicdata.data));
    oc_rep_set_text_string(publicdata, encoding, OC_ENCODING_PEM_STR);
    oc_rep_close_object(role, publicdata);
  }
  oc_rep_end_object(roles_array, role);
}

bool
oc_assert_role(const char *role, const char *authority,
               const oc_endpoint_t *endpoint, oc_response_handler_t handler,
               void *user_data)
{
  if (oc_tls_uses_psk_cred(oc_tls_get_peer(endpoint))) {
    return false;
  }
  const oc_sec_cred_t *cr =
    oc_sec_find_role_cred(/*start*/ NULL, role, authority,
                          /*tag*/ NULL); // ignore tag, we want to serialize
                                         // only the [role,authority] pairs
  if (cr == NULL) {
    OC_ERR("no role was found");
    return false;
  }
  oc_tls_select_cert_ciphersuite();
  if (!oc_init_post("/oic/sec/roles", endpoint, NULL, handler, HIGH_QOS,
                    user_data)) {
    OC_ERR("cannot init POST");
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, roles);
  serialize_role_credential(&roles_array, cr);
  oc_rep_close_array(root, roles);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("cannot send POST");
    return false;
  }
  return true;
}

void
oc_assert_all_roles(const oc_endpoint_t *endpoint,
                    oc_response_handler_t handler, void *user_data)
{
  oc_tls_peer_t *peer = oc_tls_get_peer(endpoint);
  if (oc_tls_uses_psk_cred(peer)) {
    return;
  }
  oc_tls_select_cert_ciphersuite();
  oc_role_t *roles = oc_get_all_roles();
  if (roles == NULL) {
    return;
  }
  if (!oc_init_post("/oic/sec/roles", endpoint, NULL, handler, HIGH_QOS,
                    user_data)) {
    OC_ERR("cannot init POST");
  }
  oc_rep_start_root_object();
  oc_rep_set_array(root, roles);

  while (roles) {
    const oc_sec_cred_t *cr = oc_sec_find_role_cred(
      /*start*/ NULL, oc_string(roles->role), oc_string(roles->authority),
      /*tag*/ NULL); // ignore tag, we want to serialize only the
                     // [role,authority] pairs
    if (cr != NULL) {
      serialize_role_credential(&roles_array, cr);
    }

    roles = roles->next;
  }

  oc_rep_close_array(root, roles);
  oc_rep_end_root_object();
  if (!oc_do_post()) {
    OC_ERR("cannot send POST");
    return;
  }
}

#endif /* OC_CLIENT && OC_SECURITY && OC_PKI */

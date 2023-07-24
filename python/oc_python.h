/****************************************************************************
 *
 * Copyright (c) 2017-2019 Intel Corporation
 * Copyright (c) 2021 Cascoda Ltd.
 * Copyright (c) 2021 Cable Televesion Laboratories Ltd.
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

#ifndef OC_PYTHON_H
#define OC_PYTHON_H

#include "oc_api.h"
#include "oc_export.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * callback prototypes to inform python layer that the onboarded/unonboarded
 * list has changed
 */
typedef void (*changedCB)(const char *uuid, const char *state,
                          const char *event);
typedef void (*diplomatCB)(const char *anchor, const char *uri,
                           const char *state, const char *event,
                           const char *target, const char *target_cred);
typedef void (*resourceCB)(const char *anchor, const char *uri,
                           const char *types, const char *interfaces);
typedef void (*clientCB)(const char *uuid, const char *state,
                         const char *event);

/* Structure in app to track currently discovered owned/unowned devices */
typedef struct device_handle_t
{
  struct device_handle_t *next;
  oc_uuid_t uuid;
  char device_name[64];
} device_handle_t;

/**
 * function to install callbacks, called from python
 */
OC_API
void install_changedCB(changedCB changedCB);

/**
 * function to install diplomat callbacks, called from python
 */
OC_API
void install_diplomatCB(diplomatCB diplomatCB);

/**
 * function to install resource callbacks, called from python
 */
OC_API
void install_resourceCB(resourceCB resourceCB);

/**
 * function to install client callbacks, called from python
 */
OC_API
void install_clientCB(clientCB clientCB);

/**
 * function to call the callback to python.
 */
OC_API
void inform_python(const char *uuid, const char *state, const char *event);

OC_API
void inform_resource_python(const char *anchor, const char *uri,
                            const char *types, const char *interfaces);

/**
 * function to print the returned cbor as JSON
 */
OC_API
void print_rep(const oc_rep_t *rep, bool pretty_print);

OC_API
char *get_response_payload(void);

/**
 * function to save the returned cbor as JSON
 */
OC_API
void save_rep(const oc_rep_t *rep, bool pretty_print);

/**
 * function to call the callback for diplomats to python.
 */
OC_API
void inform_diplomat_python(const char *anchor, const char *uri,
                            const char *state, const char *event,
                            const char *target, const char *target_cred);

/**
 * function to call the callback for clients to python.
 */
OC_API
void inform_client_python(const char *uuid, const char *state,
                          const char *event);

/**
 * function to convert the uuid to the device handle
 */
OC_API
device_handle_t *py_getdevice_from_uuid(const char *uuid, int owned);

/**
 * function to quit the event loop
 */
OC_API
void python_exit(int signal);

/* App utility functions */

OC_API
void empty_device_list(oc_list_t list);

/* End of app utility functions */

/* App invocations of oc_obt APIs */

/**
 * CB function on getting the device data.
 * generic callback for owned/unowned devices
 */
OC_API
bool get_cb_result(void);

OC_API
void discover_owned_devices(int scope);

OC_API
void discover_unowned_devices(int scope);

OC_API
void py_discover_unowned_devices(int scope);

OC_API
void py_otm_rdp(const char *uuid, const char *pin);

OC_API
void py_request_random_pin(const char *uuid);

#ifdef OC_PKI
OC_API
void otm_cert_cb(const oc_uuid_t *uuid, int status, void *data);
#endif /* OC_PKI */

// function to list the unowned devices in iotivity (printed in C)
OC_API
void py_list_unowned_devices(void);

// function to list the owned devices in iotivity (printed in C)
OC_API
void py_list_owned_devices(void);

OC_API
void py_otm_just_works(const char *uuid);

OC_API
void py_retrieve_acl2(const char *uuid);

OC_API
void display_cred_rsrc(const oc_sec_creds_t *creds);

OC_API
void retrieve_cred_rsrc_cb(oc_sec_creds_t *creds, void *data);

OC_API
void retrieve_own_creds(void);

OC_API
void delete_ace_by_aceid_cb(int status, void *data);

OC_API
void delete_cred_by_credid_cb(int status, void *data);

/**
 * function to retrieve the # owned devices
 */
OC_API
int py_get_nr_owned_devices(void);

/**
 * function to retrieve the uuid of the owned/unowned device
 *
 * @return " empty " if device with given index does not exist
 * @return uuid of the device
 *
 * @warning not thread-safe, returns pointer to a static buffer
 */
OC_API
const char *get_uuid(int owned, int index);

/**
 * function to retrieve the device name of the owned/unowned device
 */
OC_API
const char *get_device_name(int owned, int index);

/**
 * function to retrieve the device name belonging to the uuid
 */
OC_API
const char *get_device_name_from_uuid(const char *uuid);

/**
 * function to retrieve the number of unowned device
 */
OC_API
int py_get_nr_unowned_devices(void);

/**
 * function to reset the owned device
 */
OC_API
void py_reset_device(const char *uuid);

#ifdef OC_PKI
OC_API
void py_provision_id_cert(const char *uuid);

OC_API
void py_provision_role_cert(const char *uuid, const char *role,
                            const char *auth);

OC_API
void provision_role_wildcard_ace_cb(const oc_uuid_t *uuid, int status,
                                    void *data);
#endif /* OC_PKI */

#ifdef OC_OSCORE
OC_API
void provision_group_context_cb(const oc_uuid_t *uuid, int status, void *data);

OC_API
void provision_oscore_contexts_cb(int status, void *data);
#endif /* OC_OSCORE */

OC_API
void py_provision_pairwise_credentials(const char *uuid1, const char *uuid2);

OC_API
void provision_authcrypt_wildcard_ace_cb(const oc_uuid_t *uuid, int status,
                                         void *data);

OC_API
void py_provision_ace_cloud_access(const char *uuid);

OC_API
void py_provision_ace_to_obt(const char *uuid, const char *res_uri);

OC_API
void py_provision_ace_device_resources(const char *device_uuid,
                                       const char *subject_uuid);

OC_API
void py_provision_ace2(const char *target, const char *subject,
                       const char *href, char *crudn);

#if defined(OC_SECURITY) && defined(OC_PKI)
OC_API
int read_pem(const char *file_path, char *buffer, size_t *buffer_len);
#endif /* OC_SECURITY && OC_PKI */

#ifdef OC_PKI
OC_API
void install_trust_anchor(void);
#endif /* OC_PKI */

OC_API
void set_sd_info(void);

#ifdef OC_CLOUD
OC_API
void py_provision_cloud_config_info(const char *uuid,
                                    const char *cloud_access_token,
                                    const char *cloud_apn,
                                    const char *cloud_cis,
                                    const char *cloud_id);

OC_API
void trustanchorcb(int status, void *data);

OC_API
void py_provision_cloud_trust_anchor(const char *uuid, const char *cloud_id,
                                     const char *cloud_trust_anchor);

OC_API
void py_retrieve_d2dserverlist(const char *uuid);

OC_API
void py_post_d2dserverlist(const char *cloud_proxy_uuid, const char *query);
#endif /* OC_CLOUD */

OC_API
void py_general_get(const char *uuid, const char *url);

OC_API
void py_general_post(const char *uuid, const char *query, const char *url,
                     char **payload_properties, char **payload_values,
                     char **payload_types, int array_size);

OC_API
void py_general_delete(const char *uuid, const char *query, const char *url);

OC_API
void factory_presets_cb(size_t device, void *data);

OC_API
void py_discover_resources(const char *uuid);

OC_API
void display_device_uuid(void);

OC_API
char *py_get_obt_uuid(void);

OC_API
void test_print(void);

#ifdef OC_SO
OC_API
void discover_diplomat_for_observe(void);

OC_API
void py_diplomat_set_observe(const char *state);

OC_API
void py_diplomat_stop_observe(const char *uuid);

OC_API
void py_discover_diplomat_for_observe(void);
#endif /* OC_SO */

#ifdef OC_CLIENT
OC_API
void discover_doxm(void);

OC_API
void discover_resource(const char *rt, const char *uuid);

OC_API
void change_light(int value);
#endif /* OC_CLIENT */

OC_API
int python_main(void);

#ifdef __cplusplus
}
#endif

#endif /* OC_PYTHON_H */

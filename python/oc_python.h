/*
// Copyright (c) 2017-2019 Intel Corporation
//           (c) 2021 Cascoda Ltd.
//           (c) 2021 Cable Televesion Laboratories Ltd.

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

#ifndef OC_PYTHON_H
#define OC_PYTHON_H

#include "oc_api.h"
#include "oc_export.h"

#include <stddef.h>

/**
 * callback prototypes to inform python layer that the onboarded/unonboarded
 * list has changed
 */
typedef void (*changedCB)(char *uuid, char *state, char *event);
typedef void (*diplomatCB)(char *anchor, char *uri, char *state, char *event,
                           char *target, char *target_cred);
typedef void (*resourceCB)(char *anchor, char *uri, char *types,
                           char *interfaces);
typedef void (*clientCB)(char *uuid, char *state, char *event);

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
void print_rep(oc_rep_t *rep, bool pretty_print);

OC_API
char *get_response_payload();

/**
 * function to save the returned cbor as JSON
 */
OC_API
void save_rep(oc_rep_t *rep, bool pretty_print);

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
device_handle_t *py_getdevice_from_uuid(char *uuid, int owned);

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
bool get_cb_result();

OC_API
void discover_owned_devices(int scope);

OC_API
void discover_unowned_devices(int scope);

OC_API
void py_discover_unowned_devices(int scope);

OC_API
void py_otm_rdp(char *uuid, char *pin);

OC_API
void py_request_random_pin(char *uuid);

#ifdef OC_PKI
OC_API
void otm_cert_cb(oc_uuid_t *uuid, int status, void *data);
#endif /* OC_PKI */

// function to list the unowned devices in iotivity (printed in C)
OC_API
void py_list_unowned_devices(void);

// function to list the owned devices in iotivity (printed in C)
OC_API
void py_list_owned_devices(void);

OC_API
void py_otm_just_works(char *uuid);

OC_API
void py_retrieve_acl2(char *uuid);

OC_API
void display_cred_rsrc(oc_sec_creds_t *creds);

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
 */
OC_API
char *get_uuid(int owned, int index);

/**
 * function to retrieve the device name of the owned/unowned device
 */
OC_API
char *get_device_name(int owned, int index);

/**
 * function to retrieve the device name belonging to the uuid
 */
OC_API
char *get_device_name_from_uuid(char *uuid);

/**
 * function to retrieve the number of unowned device
 */
OC_API
int py_get_nr_unowned_devices(void);

/**
 * function to reset the owned device
 */
OC_API
void py_reset_device(char *uuid);

#ifdef OC_PKI
OC_API
void py_provision_id_cert(char *uuid);

OC_API
void py_provision_role_cert(char *uuid, char *role, char *auth);

OC_API
void provision_role_wildcard_ace_cb(oc_uuid_t *uuid, int status, void *data);
#endif /* OC_PKI */

#ifdef OC_OSCORE
OC_API
void provision_group_context_cb(oc_uuid_t *uuid, int status, void *data);

OC_API
void provision_oscore_contexts_cb(int status, void *data);
#endif /* OC_OSCORE */

OC_API
void py_provision_pairwise_credentials(char *uuid1, char *uuid2);

OC_API
void provision_authcrypt_wildcard_ace_cb(oc_uuid_t *uuid, int status,
                                         void *data);

OC_API
void py_provision_ace_cloud_access(char *uuid);

OC_API
void py_provision_ace_d2dserverlist(char *uuid);

OC_API
void py_provision_ace_device_resources(char *device_uuid, char *subject_uuid);

OC_API
void py_provision_ace2(char *target, char *subject, char *href, char *crudn);

#if defined(OC_SECURITY) && defined(OC_PKI)
OC_API
int read_pem(const char *file_path, char *buffer, size_t *buffer_len);
#endif /* OC_SECURITY && OC_PKI */

#ifdef OC_PKI
OC_API
void install_trust_anchor(void);
#endif /* OC_PKI */

OC_API
void set_sd_info();

#ifdef OC_CLOUD
OC_API
void py_provision_cloud_config_info(char *uuid, char *cloud_access_token,
                                    char *cloud_apn, char *cloud_cis,
                                    char *cloud_id);

OC_API
void trustanchorcb(int status, void *data);

OC_API
void py_provision_cloud_trust_anchor(char *uuid, char *cloud_id,
                                     char *cloud_trust_anchor);

OC_API
void py_retrieve_d2dserverlist(char *uuid);

OC_API
void py_post_d2dserverlist(char *cloud_proxy_uuid, char *query);
#endif /* OC_CLOUD */

OC_API
void py_general_get(char *uuid, char *url);

OC_API
void py_general_post(char *uuid, char *query, char *url,
                     char **payload_properties, char **payload_values,
                     char **payload_types, int array_size);

OC_API
void factory_presets_cb(size_t device, void *data);

OC_API
void py_discover_resources(char *uuid);

OC_API
void py_post(char *uri, int value);

OC_API
void display_device_uuid();

OC_API
char *py_get_obt_uuid();

OC_API
void test_print(void);

#ifdef OC_SO
OC_API
void discover_diplomat_for_observe(void);

OC_API
void py_diplomat_set_observe(char *state);

OC_API
void py_diplomat_stop_observe(char *uuid);

OC_API
void py_discover_diplomat_for_observe(void);
#endif /* OC_SO */

#ifdef OC_CLIENT
OC_API
void discover_doxm(void);

OC_API
void discover_resource(char *rt, char *uuid);

OC_API
void change_light(int value);
#endif /* OC_CLIENT */

OC_API
int python_main(void);

#endif /* OC_PYTHON_H */

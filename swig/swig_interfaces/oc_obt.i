/* File oc_storage.i */
%module OCObt
%include "typemaps.i"

%pragma(java) jniclasscode=%{
  static {
    try {
        System.loadLibrary("iotivity-lite-jni");
    } catch (UnsatisfiedLinkError e) {
      System.err.println("Native code library failed to load. \n" + e);
      System.exit(1);
    }
  }
%}

%{
#include "oc_obt.h"

%}

%rename(init) oc_obt_init;
%rename(discoverUnownedDevices) oc_obt_discover_unowned_devices;
%rename(discoverOwnedDevices) oc_obt_discover_owned_devices;
%rename(performJustWorksOtm) oc_obt_perform_just_works_otm;
%rename(deviceHardReset) oc_obt_device_hard_reset;
%rename(provisionPairwiseCredentials) oc_obt_provision_pairwise_credentials;
%rename(newAceForSubject) oc_obt_new_ace_for_subject;
%rename(newAceForConnection) oc_obt_new_ace_for_connection;
%rename(aceNewResource) oc_obt_ace_new_resource;
%rename(aceResourceSetHref) oc_obt_ace_resource_set_href;
%rename(aceResoruceSetNumRt) oc_obt_ace_resource_set_num_rt;
%rename(aceResoruceBindRt) oc_obt_ace_resource_bind_rt;
%rename(aceResourceBindIf) oc_obt_ace_resource_bind_if;
%rename(aceResourceSetWc) oc_obt_ace_resource_set_wc;
%rename(aceAddPermission) oc_obt_ace_add_permission;
%rename(provisionAce) oc_obt_provision_ace;

/*
int oc_obt_discover_unowned_devices(oc_obt_discovery_cb_t cb, void *data);
int oc_obt_discover_owned_devices(oc_obt_discovery_cb_t cb, void *data);
int oc_obt_perform_just_works_otm(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb, void *data);
int oc_obt_device_hard_reset(oc_uuid_t *uuid, oc_obt_device_status_cb_t cb, void *data);
int oc_obt_provision_pairwise_credentials(oc_uuid_t *uuid1, oc_uuid_t *uuid2, oc_obt_status_cb_t cb, void *data);
oc_sec_ace_t *oc_obt_new_ace_for_subject(oc_uuid_t *uuid);
oc_sec_ace_t *oc_obt_new_ace_for_connection(oc_ace_connection_type_t conn);
oc_ace_res_t *oc_obt_ace_new_resource(oc_sec_ace_t *ace);
void oc_obt_ace_resource_set_href(oc_ace_res_t *resource, const char *href);
void oc_obt_ace_resource_set_num_rt(oc_ace_res_t *resource, int num_resources);
void oc_obt_ace_resource_bind_rt(oc_ace_res_t *resource, const char *rt);
void oc_obt_ace_resource_bind_if(oc_ace_res_t *resource, oc_interface_mask_t interface);
void oc_obt_ace_resource_set_wc(oc_ace_res_t *resource, oc_ace_wildcard_t wc);
void oc_obt_ace_add_permission(oc_sec_ace_t *ace, oc_ace_permissions_t permission);
int oc_obt_provision_ace(oc_uuid_t *subject, oc_sec_ace_t *ace, oc_obt_device_status_cb_t cb, void *data);
void oc_obt_free_ace(oc_sec_ace_t *ace);
*/
%include "oc_obt.h";
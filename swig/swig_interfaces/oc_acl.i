/* File oc_acl.i */
%module OCAcl

%{
#include "oc_acl.h"
%}

%rename(OCAceWildcard) oc_ace_wildcard_t;
%ignore oc_ace_subject_type_t;
%rename(OCAceConnectionType) oc_ace_connection_type_t;
%rename(OCAceResource) oc_ace_res_s;
%ignore oc_ace_subject_t;
%rename(OCSecurityAce) oc_sec_ace_s;
%ignore oc_sec_acl_t;
%ignore oc_sec_acl_init;
%ignore oc_sec_acl_free;
%ignore oc_sec_get_acl;
%ignore oc_sec_acl_default;
%ignore oc_sec_encode_acl;
%ignore oc_sec_decode_acl;
%ignore oc_sec_acl_init;
%ignore post_acl;
%ignore get_acl;
%ignore delete_acl;
%ignore oc_sec_check_acl;
%ignore oc_sec_set_post_otm_acl;

// TODO solve why the -I is nto working for oc_acl.h here
%include "../../security/oc_acl.h"

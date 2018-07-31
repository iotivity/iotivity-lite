/* File oc_rep.i */
%module OCRequestPayload
%{
#include "../../include/oc_rep.h"

void rep_start_root_object() {
    oc_rep_start_root_object();
}

void rep_end_root_object() {
    oc_rep_end_root_object();
}

int java_get_rep_error() {
    return g_err;
}

void java_rep_set_double(const char* key, double value) {
    g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
    g_err |= cbor_encode_double(&root_map, value); 
}

void java_rep_set_int(const char* key, int value) {
    g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
    g_err |= cbor_encode_int(&root_map, value);
}

void java_rep_set_uint(const char* key, int value) {
    g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
    g_err |= cbor_encode_uint(&root_map, value);
}

void java_rep_set_uint(const char* key, int value) {
    g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
    g_err |= cbor_encode_uint(&root_map, value);
}

void java_rep_set_boolean(const char* key, bool value) {
    g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
    g_err |= cbor_encode_boolean(&root_map, value);
}

void java_rep_set_text_string(const char* key, const char* value) {
    g_err |= cbor_encode_text_string(&root_map, key, strlen(key));
      g_err |= cbor_encode_text_string(&root_map, value, strlen(value));
}
%}

%include "../../include/oc_rep.h"

void rep_start_root_object();
void rep_end_root_object();

%rename (get_rep_error) java_get_rep_error;
int java_get_rep_error();

%rename (rep_set_int) java_rep_set_int;
void java_rep_set_int(const char* key, int value);

%rename (rep_set_boolean) java_rep_set_boolean;
void java_rep_set_boolean(const char* key, bool value)

%rename (rep_set_text_string) java_rep_set_text_string;
void java_rep_set_text_string(const char* key, const char* value)
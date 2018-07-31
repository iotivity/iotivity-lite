/* File oc_base64.i */
%module base64
%{
#include "../../include/oc_base64.h"
%}

%rename(encode) oc_base64_encode;
%apply (char *STRING, size_t LENGTH) { (const uint8_t *input, int input_len) }
/* %apply INPUT(char*STRING, size_t LENGTH) {const uint8_t *input, int input_len} */
/* %apply OUTPUT(char*STRING, size_t LENGTH) {const uint8_t *input, int input_len} */
/* %apply BOTH(char*STRING, size_t LENGTH) {const uint8_t *input, int input_len} */
%apply (char *STRING, size_t LENGTH) {(uint8_t *output_buffer, int output_buffer_len)}
int oc_base64_encode(const uint8_t *input, int input_len, uint8_t *output_buffer, int output_buffer_len);

%rename(decode) oc_base64_decode;
%apply (char * STRING, size_t LENGTH) {(uint8_t *str, int len)}
int oc_base64_decode(uint8_t *str, int len);
/*
// Copyright (c) 2018 Intel Corporation
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

#include "oc_log_android.h"

#define ADDR_SIZE 64
#define TAG_SIZE 256

int get_log_level(const char *level) {
    int log_level = 0;
    if (strcmp(level, "DEBUG") == 0) {
        log_level = ANDROID_LOG_DEBUG;
    } else if (strcmp(level, "WARNING") == 0) {
        log_level = ANDROID_LOG_WARN;
    } else if (strcmp(level, "ERROR") == 0) {
        log_level = ANDROID_LOG_ERROR;
    } else {
        log_level = ANDROID_LOG_INFO;
    }
    return log_level;
}

void get_tag(char *tag, const char *file, const char *func, int line) {
    snprintf(tag, TAG_SIZE, "%s <%s:%d>", file, func, line);
}

void get_ipaddr(char *buffer, oc_endpoint_t endpoint) {
    if (endpoint.flags & IPV4) {
        snprintf(buffer, ADDR_SIZE, "[%d.%d.%d.%d]:%d",
            endpoint.addr.ipv4.address[0], endpoint.addr.ipv4.address[1],
            endpoint.addr.ipv4.address[2], endpoint.addr.ipv4.address[3],
            endpoint.addr.ipv4.port);
    } else {
        snprintf(buffer, ADDR_SIZE,
            "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%d",
            endpoint.addr.ipv6.address[0], endpoint.addr.ipv6.address[1],
            endpoint.addr.ipv6.address[2], endpoint.addr.ipv6.address[3],
            endpoint.addr.ipv6.address[4], endpoint.addr.ipv6.address[5],
            endpoint.addr.ipv6.address[6], endpoint.addr.ipv6.address[7],
            endpoint.addr.ipv6.address[8], endpoint.addr.ipv6.address[9],
            endpoint.addr.ipv6.address[10],endpoint.addr.ipv6.address[11],
            endpoint.addr.ipv6.address[12],endpoint.addr.ipv6.address[13],
            endpoint.addr.ipv6.address[14],endpoint.addr.ipv6.address[15],
            endpoint.addr.ipv6.port);
    }
}

void android_log(const char *level, const char *file, const char *func, int line, ...) {
    char tag[TAG_SIZE];
    get_tag(tag, file, func, line);
    va_list args;
    va_start(args, line);
    char *format = va_arg(args, char *);
    __android_log_vprint(get_log_level(level), tag, format, args);
    va_end(args);
}

void android_log_ipaddr(const char *level, const char *file, const char *func, int line, oc_endpoint_t endpoint) {
    char tag[TAG_SIZE];
    get_tag(tag, file, func, line);
    char addr[ADDR_SIZE];
    get_ipaddr(addr, endpoint);
    __android_log_write(get_log_level(level), tag, addr);
}

void android_log_bytes(const char *level, const char *file, const char *func, int line, uint8_t *bytes, size_t length) {
    char tag[TAG_SIZE];
    get_tag(tag, file, func, line);
    char buffer[length*3 + 1];
    uint16_t i;
    for (i = 0; i < length; ++i) {
      sprintf(buffer+(i*3), " %02X", bytes[i]);
    }
    buffer[length*3] = '\0';
    __android_log_write(get_log_level(level), tag, buffer);
}

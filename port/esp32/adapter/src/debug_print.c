/*
   This code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <stdio.h>
#include <stdint.h>
#include "debug_print.h"
#include "port/oc_connectivity.h"

void print_macro_info()
{
    printf("\n****************************************\n");

#ifdef OC_DEBUG
    printf("OC_DEBUG defined!\n");
#else
    printf("OC_DEBUG not defined!\n");
#endif

#ifdef APP_DEBUG
    printf("APP_DEBUG defined!\n");
#else
    printf("APP_DEBUG not defined!\n");
#endif

#ifdef OC_CLIENT
    printf("OC_CLIENT defined!\n");
#else
    printf("OC_CLIENT not defined!\n");
#endif

#ifdef OC_SERVER
    printf("OC_SERVER defined!\n");
#else
    printf("OC_SERVER not defined!\n");
#endif

#ifdef OC_IPV4
    printf("OC_IPV4 defined!\n");
#else
    printf("OC_IPV4 not defined!\n");
#endif

#ifdef ENABLE_LIGHT
    printf("ENABLE_LIGHT defined!\n");
#else
    printf("ENABLE_LIGHT not defined!\n");
#endif

#ifdef OC_SECURITY
    printf("OC_SECURITY defined!\n");
#else
    printf("OC_SECURITY not defined!\n");
#endif

#ifdef OC_DYNAMIC_ALLOCATION
    printf("OC_DYNAMIC_ALLOCATION defined!\n");
#else
    printf("OC_DYNAMIC_ALLOCATION not defined!\n");
#endif

#ifdef OC_BLOCK_WISE
    printf("OC_BLOCK_WISE defined!\n");
#else
    printf("OC_BLOCK_WISE not defined!\n");
#endif

    printf("\n****************************************\n");
}

void print_message_info(oc_message_t *message)
{
#ifdef OC_DEBUG
    printf("\n****************************************\n");

#ifdef OC_IPV4
    printf("ipv4 message info:\n------------------\n");
    printf("message length:%d ref_count:%d\n", message->length, message->ref_count);
    printf("endpoint flags:%d port:%d\naddr:", message->endpoint.flags, message->endpoint.addr.ipv4.port);
    for (int i = 0; i < 4; ++i) {
        printf("%d ", message->endpoint.addr.ipv4.address[i]);
    }
#else
    printf("ipv6 message info:\n------------------\n");
    printf("message length:%d ref_count:%d\n", message->length, message->ref_count);
    printf("endpoint flags:%d port:%d scope:%d\naddr:", message->endpoint.flags, message->endpoint.addr.ipv6.port, message->endpoint.addr.ipv6.scope);
    for (int i = 0; i < 16; ++i) {
        printf("%d ", message->endpoint.addr.ipv6.address[i]);
    }
#endif

    printf("\nmessage content:\n");
    for (int i = 0; i < message->length; ++i) {
        printf("%x ", message->data[i]);
    }

    printf("\n****************************************\n");
#endif
}

/**
 * @brief  print the data detail information
 *
 * print input data, print from data[0] to data[len-1], addtionally add notes string
 *
 * @param[in]  data: input data pointer to print
 * @param[in]  len: data length
 * @param[in]  note: notes for read easily
 * @param[in]  mode: 0x00, 0x01, 0x10, 0x11 to decide the BINARY_SHOW && BYTES_SHOW
 *
 * @return noreturn
 *
 */
void print_debug(const char* data, const unsigned int len, const char* note, int mode)
{
#define BINARY_SHOW 0x10
#define BYTES_SHOW  0x01
    printf("\n********** %s [len:%u] start addr:%p **********\n", note, len, data);
    int i = 0;
    for (i = 0; i < len; ++i) {
        if (BINARY_SHOW & mode) {
            printf("%02x ",data[i]);
        } else {
            if(data[i] < 32 || data[i] > 126) { // control || invisible charset
                if(i > 0 && (data[i-1] >= 33 && data[i-1] <= 126) )
                        printf(" ");
                printf("%02x ",data[i]);
             } else {
                printf("%c", data[i]);
             }
        }

        if ((BYTES_SHOW & mode) && ((i + 1) % 32 == 0)) {
                printf("    | %d Bytes\n",i + 1);
        }
    }   // end for

    printf("\n---------- %s End ----------\n", note);
}

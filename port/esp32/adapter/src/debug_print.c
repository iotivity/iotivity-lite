/*
   This code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include "debug_print.h"
#include "port/oc_connectivity.h"
#include "port/oc_log_internal.h"
#include <stdint.h>
#include <stdio.h>

void
print_macro_info()
{
  printf("\n****************************************\n");

  printf("OC_LOG_MAXIMUM_LEVEL=%d\n", OC_LOG_MAXIMUM_LEVEL);

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

#ifdef OC_CLOUD
  printf("OC_CLOUD defined!\n");
#else
  printf("OC_CLOUD not defined!\n");
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

#ifdef OC_PKI
  printf("OC_PKI defined!\n");
#else
  printf("OC_PKI not defined!\n");
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

#ifdef OC_SOFTWARE_UPDATE
  printf("OC_SOFTWARE_UPDATE defined!\n");
#else
  printf("OC_SOFTWARE_UPDATE not defined!\n");
#endif

#ifdef PLGD_DEV_HAWKBIT
  printf("PLGD_DEV_HAWKBIT defined!\n");
#else
  printf("PLGD_DEV_HAWKBIT not defined!\n");
#endif

  printf("\n****************************************\n");
}

void
print_message_info(const oc_message_t *message)
{
#ifdef APP_DEBUG
  printf("\n****************************************\n");

#ifdef OC_IPV4
  printf("ipv4 message info:\n------------------\n");
  printf("message length:%d ref_count:%d\n", message->length,
         message->ref_count);
  printf("endpoint flags:%d port:%d\naddr:", message->endpoint.flags,
         message->endpoint.addr.ipv4.port);
  for (int i = 0; i < 4; ++i) {
    printf("%d ", message->endpoint.addr.ipv4.address[i]);
  }
#else
  printf("ipv6 message info:\n------------------\n");
  printf("message length:%d ref_count:%d\n", message->length,
         message->ref_count);
  printf("endpoint flags:%d port:%d scope:%d\naddr:", message->endpoint.flags,
         message->endpoint.addr.ipv6.port, message->endpoint.addr.ipv6.scope);
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

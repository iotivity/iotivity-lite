/*
// Copyright 2018 Oleksandr Grytsov
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

#include <openthread/platform/uart.h>

#ifdef OC_RETARGET

#define TX_BUFFER_SIZE 1024

static uint16_t tx_head = 0;
static uint16_t tx_tail = 0;
static uint16_t tx_size = 0;
static char tx_buffer[TX_BUFFER_SIZE];

static void
send(void)
{
  if (tx_tail > tx_head) {
    tx_size = TX_BUFFER_SIZE - tx_tail;
  } else {
    tx_size = tx_head - tx_tail;
  }

  if (tx_size) {
    otPlatUartSend((uint8_t *)&tx_buffer[tx_tail], tx_size);
  }
}

static bool
put_char(char c)
{
  uint16_t next_head = tx_head + 1;

  if (next_head == TX_BUFFER_SIZE) {
    next_head = 0;
  }

  if (next_head == tx_tail) {
    return false;
  }

  tx_buffer[tx_head] = c;
  tx_head = next_head;

  return true;
}

int
_write(int file, const char *ptr, int len)
{
  (void)file;

  int i;

  for(i = 0; i < len; i++) {

    if (*ptr == '\n') {
      if (!put_char('\r')) {
        break;
      }
    }

    if (!put_char(*ptr)) {
      break;
    }

    ptr++;
  }

  if (tx_size == 0) {
    send();
  }

  return i;
}

#endif

void
otPlatUartSendDone(void)
{
#ifdef OC_RETARGET
  tx_tail += tx_size;

  if (tx_tail == TX_BUFFER_SIZE) {
    tx_tail = 0;
  }

  tx_size = 0;

  send();
#endif
}

void
otPlatUartReceived(const uint8_t *buf, uint16_t len)
{
  (void)buf;
  (void)len;
}

/*
 // Copyright (c) 2016 Intel Corporation
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

#include <stdio.h>
#include <signal.h>
#include "port/oc_clock.h"
#include "oc_main.h"

int quit = 0;

void handle_signal(int signal)
{
    quit = 1;
}

int main()
{
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  sigaction(SIGINT, &sa, NULL);
  
  oc_main_init();
  while(quit != 1) {
    oc_main_poll();
  }
  oc_main_shutdown();
  return 0;
}

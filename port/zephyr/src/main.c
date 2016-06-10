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

#include <zephyr.h>
#include <sections.h>
#include "oc_main.h"
#include "port/oc_clock.h"

#define STACKSIZE 1024
static char __noinit __stack event_loop[STACKSIZE];

void main_loop() {
  oc_main_init();
  while (1) {
    oc_main_poll();
    fiber_sleep(10);
  }
  oc_main_shutdown();
}

void main(void) {
  task_fiber_start(&event_loop[0], STACKSIZE,
		   (nano_fiber_entry_t)main_loop, 0, 0, 7, 0);
}


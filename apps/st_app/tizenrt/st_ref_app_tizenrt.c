/****************************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "../st_manager.h"
#include "../st_port.h"

// TODO: resource handling callbacks.

int
stapp_main(void)
{
  if (st_manager_initialize() != 0) {
    st_print_log("[ST_APP] st_manager_initialize failed.\n");
    return -1;
  }

  // TODO: callback registration.

  if (st_manager_start() != 0) {
    st_print_log("[ST_APP] st_manager_start failed.\n");
  }

  st_manager_stop();
  st_manager_deinitialize();
  return 0;
}

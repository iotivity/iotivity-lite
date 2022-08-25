/****************************************************************************
 *
 * Copyright (c) 2022 Jozef Kralik, All Rights Reserved.
 * Copyright (c) 2022 Daniel Adam, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"),
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "unity.h"

void
app_main(void)
{
  /* These are the different ways of running registered tests.
   * In practice, only one of them is usually needed.
   *
   * UNITY_BEGIN() and UNITY_END() calls tell Unity to print a summary
   * (number of tests executed/failed/ignored) of tests executed between these
   * calls.
   */
  UNITY_BEGIN();
  unity_run_all_tests();
  UNITY_END();

  /* This function will not return, and will be busy waiting for UART input.
   * Make sure that task watchdog is disabled if you use this function.
   */
  unity_run_menu();
}

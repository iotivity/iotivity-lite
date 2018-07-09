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

#include "oc_assert.h"
#include "st_manager.h"
#include "st_resource_manager.h"

static const char *switch_rsc_uri = "/capability/switch/main/0";
static const char *switchlevel_rsc_uri = "/capability/switchLevel/main/0";
static const char *color_temp_rsc_uri = "/capability/colorTemperature/main/0";

static const char *power_prop_key = "power";
static const char *dimming_prop_key = "dimmingSetting";
static const char *ct_prop_key = "ct";

static char power[10] = "on";

static int dimmingSetting = 50;
static int dimming_range[2] = { 0, 100 };
static int dimming_step = 5;

static int ct = 50;
static int ct_range[2] = { 0, 100 };

static void
switch_resource_construct(void)
{
  oc_abort(__func__);
}

static void
switchlevel_resource_construct(void)
{
  oc_abort(__func__);
}

static void
color_temp_resource_construct(void)
{
  oc_abort(__func__);
}

static bool
get_resource_handler(st_request_t *request)
{
  oc_abort(__func__);
}
static void
switch_resource_change(oc_rep_t *rep)
{
  oc_abort(__func__);
}

static void
switchlevel_resource_change(oc_rep_t *rep)
{
  oc_abort(__func__);
}

static void
color_temp_resource_change(oc_rep_t *rep)
{
  oc_abort(__func__);
}

static bool
set_resource_handler(st_request_t *request)
{
  oc_abort(__func__);
  return true;
}

int
main(void)
{
  oc_abort(__func__);
  return 0;
}

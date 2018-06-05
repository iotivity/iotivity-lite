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

#include "oc_otm_state.h"
#include "oc_pstat.h"

static oc_sec_otm_err_cb_t _cb;

void oc_sec_otm_set_err_cb(oc_sec_otm_err_cb_t cb)
{
  _cb = cb;
}

void oc_sec_otm_err(int device, oc_sec_otm_err_code_t code)
{
  if (_cb) {
    oc_sec_pstat_t *pstat = oc_sec_get_pstat(device);
    if (pstat->s == OC_DOS_RFOTM) {
      _cb(code);
    }
  }
}

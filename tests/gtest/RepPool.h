/****************************************************************************
 *
 * Copyright 2022 Daniel Adam, All Rights Reserved.
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

#pragma once

#include "oc_config.h"
#include "oc_rep.h"
#include "util/oc_memb.h"

#include <memory>
#include <stdint.h>
#include <string>
#include <string.h>
#include <vector>
namespace oc {

using oc_rep_unique_ptr = std::unique_ptr<oc_rep_t, void (*)(oc_rep_t *)>;

class RepPool {
public:
  RepPool(size_t size = 1024);
  ~RepPool();

  void Clear();

  oc_memb *GetRepObjectsPool() { return &rep_objects_; }

  /* convert global CborEncoder to oc_rep_t */
  oc_rep_unique_ptr ParsePayload();

  static std::vector<char> GetJson(const oc_rep_t *rep,
                                   bool pretty_print = false);

  static void CheckJson(const oc_rep_t *rep, const std::string &expected,
                        bool pretty_print = false);

private:
  size_t size_;
#ifdef OC_DYNAMIC_ALLOCATION
  uint8_t *buffer_{ nullptr };
  oc_memb rep_objects_{ sizeof(oc_rep_t), 0, nullptr, nullptr, nullptr };
#else  /* !OC_DYNAMIC_ALLOCATION */
  char rep_objects_alloc_[OC_MAX_NUM_REP_OBJECTS];
  oc_rep_t rep_objects_pool_[OC_MAX_NUM_REP_OBJECTS];
  oc_memb rep_objects_{ sizeof(oc_rep_t), OC_MAX_NUM_REP_OBJECTS,
                        rep_objects_alloc_, (void *)rep_objects_pool_,
                        nullptr };
  std::vector<uint8_t> buffer_{};
#endif /* OC_DYNAMIC_ALLOCATION */
};

} // namespace oc

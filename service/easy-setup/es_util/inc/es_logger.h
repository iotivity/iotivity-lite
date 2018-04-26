/* ****************************************************************
 *
 * Copyright 2018 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/

#ifndef ES_LOGGER_H
#define ES_LOGGER_H

#include "oc_log.h"

#define OC_LOGN(level, ...)                                                     \
  do {                                                                         \
    printf("%s: %s <%s:%d>: ", level, __FILE__, __func__, __LINE__);            \
    printf(__VA_ARGS__);  \
    printf("\n");\
  } while (0)
  
#define OC_LOGI(...) OC_LOGN("INFO", __VA_ARGS__)
#define OC_LOGD(...) OC_LOGN("DEBUG", __VA_ARGS__)
#define OC_LOGW(...) OC_LOGN("WARNING", __VA_ARGS__)
#define OC_LOGE(...) OC_LOGN("ERROR", __VA_ARGS__)
#define OC_LOGP(...) OC_LOGN("PRIVATE", __VA_ARGS__)


#endif //ES_LOGGER_H
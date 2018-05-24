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

#ifndef ES_UTILS_H
#define ES_UTILS_H

#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define es_rep_set_boolean(object, key, value) oc_rep_set_boolean(object, key, value)

#define es_rep_set_int(object, key, value) oc_rep_set_int(object, key, value)

#define es_rep_set_text_string(object, key, value)           \
  do {                                                    \
    if (value) oc_rep_set_text_string(object, key, value); \
  } while(0);

#define es_free_string(str) if(oc_string_len(str) > 0) oc_free_string(&str);

static void
es_new_string(oc_string_t *desString, char *srcString){
  if (!desString || (!srcString || strlen(srcString) == 0)) {
    return;
  }

  if(oc_string_len(*desString) == 0){
    oc_new_string(desString, srcString, strlen(srcString));
  }else if(oc_string_len(*desString)== strlen(srcString)){
    strncpy(oc_string(*desString), srcString, strlen(srcString));
  }else{
    oc_free_string(desString);
    oc_new_string(desString, srcString,strlen(srcString));
  }
}

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // ES_UTILS_H

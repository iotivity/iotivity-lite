/******************************************************************
 *
 * Copyright 2016 Granite River Labs All Rights Reserved.
 *
 *
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

#ifndef __MINI_HTTP_SERVER__
#define __MINI_HTTP_SERVER__

#ifdef __cplusplus
extern "C"{
#endif

typedef char* (*httpRequestCB)(const char* method, const char* url, const char* body);
typedef void (*afterHttpRequestCB)(char* rspBody);
void startMiniHttpServerBasic(const char* addr, int port, httpRequestCB onHttpRequest, afterHttpRequestCB onAfterHttpRequest);
void startMiniHttpServerSetup(const char* addr, int port, httpRequestCB onHttpRequest, afterHttpRequestCB onAfterHttpRequest);
void startMiniHttpServerExtended(const char* addr, int port, httpRequestCB onHttpRequest, afterHttpRequestCB onAfterHttpRequest);
void stopMiniHttpServerBasic();
void stopMiniHttpServerSetup();
void stopMiniHttpServerExtended();

#ifdef __cplusplus
}
#endif

#endif //__MINI_HTTP_SERVER__
